"""Map verified Firebase identities to Frappe users and sync their roles."""

import frappe
from frappe import _

from lms_mobile_bridge.helpers.firebase_token import get_settings

# Roles every bridged user needs; never removed by mapping reconciliation.
# Mobile User gates mobile_control logins; LMS Student is the LMS baseline
# (also auto-added by LMS's own User.before_insert hook on creation).
PROTECTED_ROLES = ("Mobile User", "LMS Student")


def get_or_create_user(claims: dict):
	"""Resolve the Frappe User for a verified set of Firebase claims.

	Identity model: `firebase_uid` (JWT sub) is canonical. Email is only used
	to link a pre-existing Frappe user once — and only when Firebase says the
	email is verified, so an attacker cannot claim someone's account by
	registering their email with an unverified provider.
	"""
	uid = claims["sub"]
	email = claims["email"].strip().lower()
	settings = get_settings()

	# 1) Returning user — matched by uid
	user_name = frappe.db.get_value("User", {"firebase_uid": uid})
	if user_name:
		user = frappe.get_doc("User", user_name)
		if email != user.email.lower():
			# Email changed in Firebase. The uid stays canonical; renaming the
			# User docname is an admin action (see README runbook).
			user.add_comment(
				"Comment",
				text=f"Firebase email changed: {frappe.bold(user.email)} → {frappe.bold(email)}",
			)
		return user

	# 2) Existing Frappe user with this email — link once, verified email only
	user_name = frappe.db.get_value("User", {"email": email})
	if user_name:
		if not claims.get("email_verified"):
			raise frappe.AuthenticationError
		existing_uid = frappe.db.get_value("User", user_name, "firebase_uid")
		if existing_uid and existing_uid != uid:
			# A different Firebase account already owns this Frappe user
			raise frappe.AuthenticationError
		frappe.db.set_value("User", user_name, "firebase_uid", uid, update_modified=False)
		return frappe.get_doc("User", user_name)

	# 3) New user
	if settings.require_verified_email and not claims.get("email_verified"):
		raise frappe.AuthenticationError

	first_name = (claims.get("name") or "").strip() or email.split("@", 1)[0]
	user = frappe.get_doc(
		{
			"doctype": "User",
			"email": email,
			"first_name": first_name,
			"user_type": "Website User",
			"firebase_uid": uid,
			"send_welcome_email": 0,
			"enabled": 1,
		}
	)
	user.flags.ignore_permissions = True
	user.flags.no_welcome_mail = True
	user.insert()
	return user


def sync_roles(user, claims: dict) -> None:
	"""Reconcile the user's roles against the configured app_role mapping.

	Only roles that appear in the mapping table are managed (added/removed);
	roles granted manually in the desk are never touched. The app_role claim
	is trusted because it arrives inside a signature-verified token and is set
	server-side by the Firebase project's custom-claims pipeline.
	"""
	settings = get_settings()

	mappings = {}
	managed_roles = set()
	for row in settings.role_mappings or []:
		if not row.frappe_role:
			continue
		mappings.setdefault((row.app_role or "").strip(), set()).add(row.frappe_role)
		managed_roles.add(row.frappe_role)

	app_role = (claims.get("app_role") or "").strip()
	desired = set(mappings.get(app_role, set()))

	current = set(frappe.get_roles(user.name))

	to_add = [role for role in PROTECTED_ROLES if role not in current]
	to_add += sorted(desired - current)
	# Tolerate roles that don't exist on this site (e.g. LMS Student before
	# the lms app is installed) instead of failing every login.
	to_add = [role for role in to_add if frappe.db.exists("Role", role)]
	to_remove = sorted((current & managed_roles) - desired - set(PROTECTED_ROLES))

	if to_add:
		user.add_roles(*to_add)
	if to_remove:
		user.remove_roles(*to_remove)
