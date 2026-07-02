app_name = "lms_mobile_bridge"
app_title = "LMS Mobile Bridge"
app_publisher = "TinyTotClub"
app_description = "Firebase Auth bridge for Frappe LMS mobile apps (mobile_control companion)"
app_email = "dev@tinytotclub.com"
app_license = "MIT"

# The bridge rides on mobile_control's token machinery; both must be installed.
required_apps = ["mobile_control"]

after_install = "lms_mobile_bridge.install.after_install"

# Routes /api/method/mobile_auth.login_with_firebase (and the /api/v2 variant)
# to this app. Frappe merges this map across all installed apps, so
# mobile_control's own entries are untouched.
override_whitelisted_methods = {
	"mobile_auth.login_with_firebase": "lms_mobile_bridge.api.firebase_auth.login_with_firebase",
}
