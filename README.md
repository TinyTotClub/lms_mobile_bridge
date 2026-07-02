# LMS Mobile Bridge

Firebase Auth bridge for Frappe LMS mobile apps. Lets a Flutter app that
authenticates users with **Firebase Authentication** exchange the Firebase ID
token for [mobile_control](https://github.com/TinyTotClub/frappe-mobile-control)'s
standard access/refresh token pair — no second login, no passwords on the
Frappe side.

```
Flutter app ── Firebase ID token ──▶ mobile_auth.login_with_firebase
                                          │  verify RS256 signature against
                                          │  Google's public certs (aud/iss/exp)
                                          ▼
                                    find-or-create Frappe User (firebase_uid)
                                          │  sync roles from app_role claim
                                          ▼
                                    mobile_control token pair (same response
                                    shape as mobile_auth.login)
```

The response is shape-identical to `mobile_auth.login`, so the
`frappe_mobile_sdk`'s `loginWithFirebase()` (session restore, 401
auto-refresh, permissions) works unchanged.

## Installation

Requires the `mobile_control` app on the same site.

```bash
cd $PATH_TO_YOUR_BENCH
bench get-app https://github.com/TinyTotClub/frappe-mobile-control
bench get-app https://github.com/TinyTotClub/lms_mobile_bridge
bench --site <site> install-app mobile_control lms_mobile_bridge
bench --site <site> migrate
```

## Configuration

Open **Firebase Auth Settings** (single doctype) in the desk:

| Field | Meaning |
|---|---|
| Enabled | Master switch for the endpoint |
| Firebase Project ID | The `aud`/`iss` of accepted ID tokens (e.g. `my-project-id`). Fallback: `firebase_project_id` in `site_config.json` |
| Require Verified Email | Reject sign-ins from unverified Firebase emails (default on). Email-based linking of existing users always requires a verified email |
| Access Token TTL | 0 = mobile_control default (24h) |
| Role Mappings | `app_role` Firebase custom claim → Frappe Role. Only mapped roles are managed (added/removed) at login; desk-granted roles are never touched |

Every bridged user always gets **Mobile User** (mobile_control's login gate)
and **LMS Student** (when the lms app is installed).

Suggested LMS mapping:

| app_role claim | Frappe roles |
|---|---|
| businessOwner | Moderator |
| adminTeacher | Course Creator, Moderator |
| teacher / asstTeacher | Course Creator |
| parent | (LMS Student only) |

### site_config.json keys (no secrets required)

```jsonc
{
  "firebase_project_id": "my-project-id",   // fallback for the settings field
  // dev only:
  "developer_mode": 1,
  "firebase_auth_emulator_host": "127.0.0.1:9099"  // accept unsigned emulator tokens
}
```

No Firebase service account is needed — verification uses Google's public
x509 certificates. **Never commit real keys or service accounts to this
repository.**

## API

`POST /api/v2/method/mobile_auth.login_with_firebase` (also `/api/method/...`)

```json
{ "id_token": "<firebase-id-token>", "device_id": "optional-device-id" }
```

Success → the `mobile_auth.login` response shape (`access_token`,
`refresh_token`, `user`, `roles`, `permissions`, `mobile_form_names`,
`offline_enabled`, ...). Any failure → HTTP 401 with the opaque message
`Unable to login` (no account-state enumeration). Rate limit: 20 requests
per 15 minutes per IP.

## Identity model

- `User.firebase_uid` (custom field, unique) is the canonical link; the JWT
  `sub` claim.
- Email matching is only used ONCE to link a pre-existing Frappe user, and
  only when Firebase reports the email as verified.
- A second Firebase account can never claim an already-linked user.

### Email-change runbook

When a user changes their email in Firebase, logins keep working via
`firebase_uid` and a comment is logged on the User. To align the Frappe
docname/email, run during a maintenance window:

```python
# bench --site <site> console
frappe.rename_doc("User", "old@example.com", "new@example.com")
```

## Tests

```bash
bench --site <site> run-tests --app lms_mobile_bridge
```

Tokens are minted in-test with a local RSA key and the Google cert fetch is
stubbed to serve the matching self-signed certificate — signature, audience,
issuer, and expiry verification run for real.
