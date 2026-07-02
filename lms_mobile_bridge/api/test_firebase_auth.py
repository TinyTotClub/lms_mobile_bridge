"""Tests for the Firebase login bridge.

Tokens are minted in-test with a locally generated RSA key; the Google cert
fetch is monkeypatched to serve the matching self-signed x509 certificate, so
google-auth performs REAL signature/aud/exp verification against our key.
"""

from __future__ import annotations

import datetime
import json
import time
from unittest.mock import patch

import frappe
import jwt as pyjwt
from frappe.tests import IntegrationTestCase

from lms_mobile_bridge.api import firebase_auth
from lms_mobile_bridge.helpers import firebase_token as ft_module
from lms_mobile_bridge.helpers.firebase_token import verify_firebase_id_token
from lms_mobile_bridge.helpers.user_provisioning import get_or_create_user
from lms_mobile_bridge.helpers.user_provisioning import sync_roles

PROJECT_ID = "bridge-test-project"
ISSUER = f"https://securetoken.google.com/{PROJECT_ID}"
KID = "test-key-1"


def _generate_key_and_cert():
	from cryptography import x509
	from cryptography.hazmat.primitives import hashes, serialization
	from cryptography.hazmat.primitives.asymmetric import rsa
	from cryptography.x509.oid import NameOID

	key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bridge-test")])
	cert = (
		x509.CertificateBuilder()
		.subject_name(subject)
		.issuer_name(issuer)
		.public_key(key.public_key())
		.serial_number(x509.random_serial_number())
		.not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
		.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
		.sign(key, hashes.SHA256())
	)
	key_pem = key.private_bytes(
		serialization.Encoding.PEM,
		serialization.PrivateFormat.TraditionalOpenSSL,
		serialization.NoEncryption(),
	)
	cert_pem = cert.public_bytes(serialization.Encoding.PEM)
	return key_pem, cert_pem


class _StubResponse:
	def __init__(self, data: bytes):
		self.status = 200
		self.headers = {"content-type": "application/json"}
		self.data = data


class _StubGoogleRequest:
	"""Duck-types google.auth.transport.Request: serves our test cert."""

	def __init__(self, certs: dict[str, str]):
		self._payload = json.dumps(certs).encode()

	def __call__(self, url, method="GET", **kwargs):
		return _StubResponse(self._payload)


KEY_PEM, CERT_PEM = _generate_key_and_cert()
STUB_REQUEST = _StubGoogleRequest({KID: CERT_PEM.decode()})


def mint_token(**overrides) -> str:
	now = int(time.time())
	claims = {
		"iss": ISSUER,
		"aud": PROJECT_ID,
		"sub": "firebase-uid-001",
		"email": "bridge.user@example.com",
		"email_verified": True,
		"name": "Bridge User",
		"iat": now - 10,
		"auth_time": now - 10,
		"exp": now + 3600,
		"firebase": {"sign_in_provider": "password"},
	}
	claims.update(overrides)
	claims = {k: v for k, v in claims.items() if v is not None}
	return pyjwt.encode(claims, KEY_PEM, algorithm="RS256", headers={"kid": KID})


class FirebaseBridgeTestCase(IntegrationTestCase):
	TEST_ROLES = ("Bridge Test Role A", "Bridge Test Role B", "Bridge Test Manual Role")

	def setUp(self):
		super().setUp()
		for role_name in self.TEST_ROLES:
			if not frappe.db.exists("Role", role_name):
				frappe.get_doc({"doctype": "Role", "role_name": role_name, "desk_access": 0}).insert(
					ignore_permissions=True
				)
		settings = frappe.get_doc("Firebase Auth Settings")
		settings.enabled = 1
		settings.firebase_project_id = PROJECT_ID
		settings.require_verified_email = 1
		settings.access_token_ttl_seconds = 0
		settings.role_mappings = []
		settings.append("role_mappings", {"app_role": "teacher", "frappe_role": "Bridge Test Role A"})
		settings.append("role_mappings", {"app_role": "businessOwner", "frappe_role": "Bridge Test Role A"})
		settings.append(
			"role_mappings", {"app_role": "businessOwner", "frappe_role": "Bridge Test Role B"}
		)
		settings.save(ignore_permissions=True)

		self._request_patch = patch.object(ft_module, "_get_google_request", return_value=STUB_REQUEST)
		self._request_patch.start()
		self.addCleanup(self._request_patch.stop)

	def tearDown(self):
		for email in ("bridge.user@example.com", "existing.user@example.com"):
			if frappe.db.exists("User", email):
				frappe.delete_doc("User", email, force=True, ignore_permissions=True)
		super().tearDown()


class TestTokenVerification(FirebaseBridgeTestCase):
	def test_valid_token_returns_claims(self):
		claims = verify_firebase_id_token(mint_token())
		self.assertEqual(claims["sub"], "firebase-uid-001")
		self.assertEqual(claims["email"], "bridge.user@example.com")

	def test_wrong_audience_rejected(self):
		with self.assertRaises(frappe.AuthenticationError):
			verify_firebase_id_token(mint_token(aud="some-other-project"))

	def test_wrong_issuer_rejected(self):
		with self.assertRaises(frappe.AuthenticationError):
			verify_firebase_id_token(mint_token(iss="https://securetoken.google.com/other"))

	def test_expired_token_rejected(self):
		now = int(time.time())
		with self.assertRaises(frappe.AuthenticationError):
			verify_firebase_id_token(mint_token(iat=now - 7200, exp=now - 3600))

	def test_missing_email_rejected(self):
		with self.assertRaises(frappe.AuthenticationError):
			verify_firebase_id_token(mint_token(email=None))

	def test_oversized_uid_rejected(self):
		with self.assertRaises(frappe.AuthenticationError):
			verify_firebase_id_token(mint_token(sub="x" * 129))

	def test_hs256_token_rejected(self):
		token = pyjwt.encode(
			{"iss": ISSUER, "aud": PROJECT_ID, "sub": "u", "email": "a@b.c"},
			"shared-secret",
			algorithm="HS256",
			headers={"kid": KID},
		)
		with self.assertRaises(frappe.AuthenticationError):
			verify_firebase_id_token(token)

	def test_garbage_token_rejected(self):
		with self.assertRaises(frappe.AuthenticationError):
			verify_firebase_id_token("not-a-jwt")


class TestUserProvisioning(FirebaseBridgeTestCase):
	def test_new_user_created_with_uid(self):
		claims = verify_firebase_id_token(mint_token())
		user = get_or_create_user(claims)
		self.assertEqual(user.email, "bridge.user@example.com")
		self.assertEqual(user.firebase_uid, "firebase-uid-001")
		self.assertEqual(user.user_type, "Website User")

	def test_new_user_with_unverified_email_rejected(self):
		claims = verify_firebase_id_token(mint_token(email_verified=False))
		with self.assertRaises(frappe.AuthenticationError):
			get_or_create_user(claims)

	def test_existing_user_linked_by_verified_email(self):
		frappe.get_doc(
			{
				"doctype": "User",
				"email": "existing.user@example.com",
				"first_name": "Existing",
				"user_type": "Website User",
				"send_welcome_email": 0,
			}
		).insert(ignore_permissions=True)

		claims = verify_firebase_id_token(
			mint_token(sub="firebase-uid-link", email="existing.user@example.com")
		)
		user = get_or_create_user(claims)
		self.assertEqual(user.name, "existing.user@example.com")
		self.assertEqual(
			frappe.db.get_value("User", user.name, "firebase_uid"), "firebase-uid-link"
		)

	def test_existing_user_link_requires_verified_email(self):
		frappe.get_doc(
			{
				"doctype": "User",
				"email": "existing.user@example.com",
				"first_name": "Existing",
				"user_type": "Website User",
				"send_welcome_email": 0,
			}
		).insert(ignore_permissions=True)

		claims = verify_firebase_id_token(
			mint_token(sub="uid-x", email="existing.user@example.com", email_verified=False)
		)
		with self.assertRaises(frappe.AuthenticationError):
			get_or_create_user(claims)

	def test_uid_conflict_rejected(self):
		claims = verify_firebase_id_token(mint_token(sub="uid-first"))
		get_or_create_user(claims)

		# A different Firebase account claiming the same email must fail
		claims2 = verify_firebase_id_token(mint_token(sub="uid-second"))
		with self.assertRaises(frappe.AuthenticationError):
			get_or_create_user(claims2)

	def test_email_change_keeps_uid_match(self):
		claims = verify_firebase_id_token(mint_token())
		created = get_or_create_user(claims)

		changed = verify_firebase_id_token(mint_token(email="renamed@example.com"))
		matched = get_or_create_user(changed)
		self.assertEqual(matched.name, created.name)


class TestRoleSync(FirebaseBridgeTestCase):
	def _user_for(self, **token_overrides):
		claims = verify_firebase_id_token(mint_token(**token_overrides))
		user = get_or_create_user(claims)
		sync_roles(user, claims)
		return frappe.get_doc("User", user.name)

	def test_mapped_role_added(self):
		user = self._user_for(app_role="teacher")
		self.assertIn("Bridge Test Role A", frappe.get_roles(user.name))

	def test_multi_role_mapping(self):
		user = self._user_for(app_role="businessOwner")
		roles = frappe.get_roles(user.name)
		self.assertIn("Bridge Test Role A", roles)
		self.assertIn("Bridge Test Role B", roles)

	def test_managed_role_removed_on_downgrade(self):
		user = self._user_for(app_role="businessOwner")
		self.assertIn("Bridge Test Role B", frappe.get_roles(user.name))

		user = self._user_for(app_role="teacher")
		roles = frappe.get_roles(user.name)
		self.assertIn("Bridge Test Role A", roles)
		self.assertNotIn("Bridge Test Role B", roles)

	def test_manual_roles_preserved(self):
		user = self._user_for(app_role="teacher")
		user.add_roles("Bridge Test Manual Role")  # not in the mapping table

		user = self._user_for()  # no app_role claim
		roles = frappe.get_roles(user.name)
		self.assertNotIn("Bridge Test Role A", roles)
		self.assertIn("Bridge Test Manual Role", roles)

	def test_protected_roles_always_present(self):
		user = self._user_for()
		roles = frappe.get_roles(user.name)
		if frappe.db.exists("Role", "Mobile User"):
			self.assertIn("Mobile User", roles)
		if frappe.db.exists("Role", "LMS Student"):
			self.assertIn("LMS Student", roles)


class TestLoginEndpoint(FirebaseBridgeTestCase):
	def _call(self, token: str):
		frappe.local.response = frappe._dict({"docs": []})
		firebase_auth.login_with_firebase(token)
		return frappe.local.response

	def test_login_response_shape(self):
		response = self._call(mint_token())
		for key in (
			"user",
			"full_name",
			"language",
			"access_token",
			"refresh_token",
			"offline_enabled",
			"mobile_form_names",
			"roles",
			"permissions",
		):
			self.assertIn(key, response, f"missing key: {key}")
		self.assertEqual(response["user"], "bridge.user@example.com")
		self.assertTrue(response["access_token"].startswith("gAAAA"))

	def test_disabled_user_cannot_login(self):
		self._call(mint_token())
		frappe.db.set_value("User", "bridge.user@example.com", "enabled", 0)

		with self.assertRaises(frappe.AuthenticationError):
			self._call(mint_token())

	def test_disabled_settings_blocks_login(self):
		settings = frappe.get_doc("Firebase Auth Settings")
		settings.enabled = 0
		settings.save(ignore_permissions=True)

		with self.assertRaises(frappe.AuthenticationError):
			self._call(mint_token())

	def test_login_failure_message_is_opaque(self):
		try:
			self._call(mint_token(aud="wrong-project"))
			self.fail("expected AuthenticationError")
		except frappe.AuthenticationError as e:
			self.assertIn("Unable to login", str(e))
