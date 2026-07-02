"""Firebase ID token verification.

Verifies RS256 ID tokens issued by Firebase Authentication against Google's
public x509 certificates. No service-account credential is required for
verification — only the Firebase project id.
"""

import frappe
from frappe import _

FIREBASE_ISSUER_PREFIX = "https://securetoken.google.com/"
MAX_UID_LENGTH = 128
CLOCK_SKEW_SECONDS = 10

# Module-level cached HTTP session: cachecontrol honours the Cache-Control
# max-age (~1h) Google sends with its certs, so workers refetch them rarely.
_google_request = None


def get_settings():
	return frappe.get_cached_doc("Firebase Auth Settings")


def get_project_id() -> str:
	settings = get_settings()
	project_id = (settings.firebase_project_id or "").strip() or frappe.conf.get("firebase_project_id")
	if not project_id:
		frappe.log_error(title="Firebase Bridge Misconfigured", message="firebase_project_id is not set")
		raise frappe.AuthenticationError
	return project_id


def _get_google_request():
	global _google_request
	if _google_request is None:
		import cachecontrol
		import google.auth.transport.requests
		import requests

		session = cachecontrol.CacheControl(requests.session())
		_google_request = google.auth.transport.requests.Request(session=session)
	return _google_request


def verify_firebase_id_token(id_token: str) -> dict:
	"""Verify the token and return its claims, or raise AuthenticationError.

	Checks: RS256 signature against Google's certs, audience (project id),
	issuer, expiry, uid shape, and email presence. `email_verified` is
	returned in the claims for the provisioning layer to enforce.
	"""
	if not id_token or not isinstance(id_token, str) or id_token.count(".") != 2:
		raise frappe.AuthenticationError

	project_id = get_project_id()

	if _emulator_mode_enabled():
		claims = _decode_emulator_token(id_token)
	else:
		claims = _verify_production_token(id_token, project_id)

	if claims.get("iss") != f"{FIREBASE_ISSUER_PREFIX}{project_id}":
		raise frappe.AuthenticationError
	if claims.get("aud") != project_id:
		raise frappe.AuthenticationError

	uid = claims.get("sub")
	if not uid or not isinstance(uid, str) or len(uid) > MAX_UID_LENGTH:
		raise frappe.AuthenticationError

	email = claims.get("email")
	if not email or not isinstance(email, str):
		# Providers without an email (e.g. anonymous auth) cannot map to a
		# Frappe user; Apple's private relay still supplies an email.
		raise frappe.AuthenticationError

	return claims


def _verify_production_token(id_token: str, project_id: str) -> dict:
	import google.auth.exceptions
	import google.oauth2.id_token
	import jwt as pyjwt

	try:
		header = pyjwt.get_unverified_header(id_token)
	except Exception:
		raise frappe.AuthenticationError

	if header.get("alg") != "RS256":
		raise frappe.AuthenticationError

	try:
		return google.oauth2.id_token.verify_firebase_token(
			id_token,
			_get_google_request(),
			audience=project_id,
			clock_skew_in_seconds=CLOCK_SKEW_SECONDS,
		)
	except google.auth.exceptions.GoogleAuthError:
		raise frappe.AuthenticationError
	except ValueError:
		# verify_firebase_token raises ValueError for bad signature/expiry/aud
		raise frappe.AuthenticationError


def _emulator_mode_enabled() -> bool:
	"""Firebase Auth emulator tokens are unsigned (alg=none) — only ever
	accept them on developer-mode sites that explicitly opt in."""
	return bool(frappe.conf.get("developer_mode")) and bool(
		frappe.conf.get("firebase_auth_emulator_host")
	)


def _decode_emulator_token(id_token: str) -> dict:
	import jwt as pyjwt

	try:
		return pyjwt.decode(
			id_token,
			options={"verify_signature": False, "verify_exp": True, "verify_aud": False},
			leeway=CLOCK_SKEW_SECONDS,
		)
	except Exception:
		raise frappe.AuthenticationError
