"""Development-site seeding for the LMS mobile stack.

Invoked by the docker init script:
    bench --site <site> execute lms_mobile_bridge.dev_seed.seed_dev_site

Idempotent — safe to run on every container start. Reads its inputs from
site_config (set from environment by the init script); never hardcode
project-specific values here, this file ships in a public-safe app.
"""

import frappe

# DocTypes surfaced to the mobile SDK's metadata-driven admin screens
MOBILE_DOCTYPES = [
	"LMS Course",
	"LMS Batch",
	"LMS Enrollment",
	"LMS Batch Enrollment",
	"LMS Quiz",
	"LMS Quiz Submission",
	"LMS Certificate",
	"Course Lesson",
	"LMS Assignment Submission",
]

# Default Firebase app_role claim → LMS role mapping (LMS Student is implicit)
DEFAULT_ROLE_MAPPINGS = [
	("businessOwner", "Moderator"),
	("adminTeacher", "Course Creator"),
	("adminTeacher", "Moderator"),
	("teacher", "Course Creator"),
	("asstTeacher", "Course Creator"),
]


def seed_dev_site():
	seed_mobile_configuration()
	seed_firebase_auth_settings()
	frappe.db.commit()
	print("lms_mobile_bridge: dev site seeded")


def seed_mobile_configuration():
	config = frappe.get_doc("Mobile Configuration")
	config.enabled = 1
	config.offline_enabled = 0
	if not config.package_name:
		config.package_name = frappe.conf.get("mobile_package_name") or "com.example.lmsapp"

	existing = {row.mobile_workspace_item for row in (config.table_lwis or [])}
	for idx, doctype in enumerate(MOBILE_DOCTYPES):
		if doctype in existing or not frappe.db.exists("DocType", doctype):
			continue
		config.append("table_lwis", {"mobile_workspace_item": doctype, "order": idx})

	config.save(ignore_permissions=True)


def seed_firebase_auth_settings():
	settings = frappe.get_doc("Firebase Auth Settings")

	project_id = frappe.conf.get("firebase_project_id")
	if project_id:
		settings.enabled = 1
		settings.firebase_project_id = project_id
	else:
		print("lms_mobile_bridge: firebase_project_id not set — bridge left disabled")

	existing = {(row.app_role, row.frappe_role) for row in (settings.role_mappings or [])}
	for app_role, frappe_role in DEFAULT_ROLE_MAPPINGS:
		if (app_role, frappe_role) in existing or not frappe.db.exists("Role", frappe_role):
			continue
		settings.append("role_mappings", {"app_role": app_role, "frappe_role": frappe_role})

	settings.save(ignore_permissions=True)
