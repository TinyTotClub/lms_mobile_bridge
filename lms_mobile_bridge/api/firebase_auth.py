"""Firebase login endpoint for the frappe_mobile_sdk.

Exchanges a verified Firebase ID token for mobile_control's standard
access/refresh token pair. The response is shape-identical to
`mobile_auth.login`, so the mobile SDK's session restore, 401 auto-refresh,
and permission wiring work unchanged.
"""

import frappe
from frappe import _
from frappe.rate_limiter import rate_limit

from mobile_control.api.helpers.mobile_config import get_mobile_configuration_payload
from mobile_control.api.helpers.refresh_token import create_refresh_token
from mobile_control.api.helpers.response_builder import build_auth_response
from mobile_control.api.helpers.response_builder import get_request_metadata
from mobile_control.api.helpers.user_auth import ensure_api_credentials
from mobile_control.api.helpers.user_auth import generate_auth_token
from mobile_control.api.helpers.user_auth import validate_mobile_user_role_for_user

from lms_mobile_bridge.helpers.firebase_token import get_settings
from lms_mobile_bridge.helpers.firebase_token import verify_firebase_id_token
from lms_mobile_bridge.helpers.user_provisioning import get_or_create_user
from lms_mobile_bridge.helpers.user_provisioning import sync_roles


# nosemgrep frappe-semgrep-rules.rules.security.guest-whitelisted-method
@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=20, seconds=15 * 60)
def login_with_firebase(id_token: str, device_id: str | None = None) -> None:
	"""Verify a Firebase ID token and issue mobile_control tokens.

	Mirrors mobile_auth.login's flow with the Firebase token as the proof of
	identity. Failures are reported with one opaque message so account state
	(exists / disabled / unverified) cannot be enumerated.
	"""
	try:
		settings = get_settings()
		if not settings.enabled:
			raise frappe.AuthenticationError

		claims = verify_firebase_id_token(id_token)
		user = get_or_create_user(claims)

		if not user.enabled:
			raise frappe.AuthenticationError

		sync_roles(user, claims)
		validate_mobile_user_role_for_user(user)

		ensure_api_credentials(user)
		token_ttl = int(settings.access_token_ttl_seconds or 0)
		if token_ttl > 0:
			access_token = generate_auth_token(user, expires_in=token_ttl)
		else:
			access_token = generate_auth_token(user)

		request_device_id, user_agent = get_request_metadata()
		refresh_token = create_refresh_token(
			user, device_id=device_id or request_device_id, user_agent=user_agent
		)

		payload = get_mobile_configuration_payload()
		mobile_config = payload.get("configuration", [])
		offline_enabled = bool(payload.get("offline_enabled", False))

		frappe.local.response.update(
			build_auth_response(
				user,
				access_token,
				refresh_token=refresh_token,
				mobile_config=mobile_config,
				offline_enabled=offline_enabled,
			)
		)

	except (frappe.AuthenticationError, frappe.PermissionError):
		# Provisioning may have written (new user / linked uid / role changes)
		# before a later step failed — don't leave partial state behind.
		frappe.db.rollback()
		frappe.throw(_("Unable to login"), frappe.AuthenticationError)
	except Exception:
		frappe.db.rollback()
		# Never include the id_token (a live bearer credential) in the log
		frappe.log_error(title="Firebase Login Error")
		frappe.throw(_("Unable to login"), frappe.AuthenticationError)
