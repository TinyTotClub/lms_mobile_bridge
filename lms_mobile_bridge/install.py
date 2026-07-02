from frappe.custom.doctype.custom_field.custom_field import create_custom_fields


def after_install():
	create_firebase_uid_field()


def create_firebase_uid_field():
	"""Custom field linking a Frappe User to their Firebase account.

	The uid (JWT `sub` claim) is the canonical identity: emails can change in
	Firebase, uids cannot. Unique so two Firebase accounts can never claim the
	same Frappe user.
	"""
	create_custom_fields(
		{
			"User": [
				{
					"fieldname": "firebase_uid",
					"label": "Firebase UID",
					"fieldtype": "Data",
					"unique": 1,
					"read_only": 1,
					"no_copy": 1,
					"hidden": 1,
					"insert_after": "username",
					"description": "Firebase Authentication user id (sub claim); set by lms_mobile_bridge",
				}
			]
		},
		ignore_validate=True,
	)
