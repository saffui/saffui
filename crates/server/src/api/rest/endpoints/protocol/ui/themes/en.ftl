# Saffui — hosted UI strings (en)
# Fluent. Keys are shared with fr.ftl.

## Common
action-signin = Sign in
action-continue = Continue
action-cancel = Cancel
action-back-signin = Back to sign-in
action-retry = Try again
action-copy = Copy
common-or = or
common-request-id = Request reference

## 1 — Sign-in
login-title = Sign in
login-subtitle = Sign in to continue.
login-username = Username
login-password = Password
login-forgot = Forgot your password?
login-magic-link = Get a link by email
login-federated = Continue with { $provider }
login-error-rejected = Incorrect username or password. Check your details and try again.
login-error-locked = Incorrect username or password. Check your details and try again.

## 2 — TOTP second factor
totp-title = Verification code
totp-subtitle = Enter the 6-digit code from your app.
totp-code = Code
totp-error = Code rejected. Codes change every 30 seconds — enter the next one.
totp-use-passkey = Use a security key instead

## 3 — TOTP enrolment
enroll-title = Add a code app
enroll-step-1 = 1. Scan this code with your app.
enroll-step-2 = 2. Enter the code it shows.
enroll-secret-label = Or type this key by hand
enroll-code = Code from the app
enroll-submit = Turn on

## 4 — Security key / passkey
passkey-title = Security key
passkey-waiting = Touch your key, or use this device.
passkey-error = The key did not respond. Try again, or use a code.
passkey-use-totp = Use a code instead
passkey-add-title = Add a key to this account
passkey-add-body = Your browser will ask you to confirm.
passkey-add-action = Add a key
passkey-name-title = Key added
passkey-name-label = Key name
passkey-name-hint = So you can recognise it later.
passkey-name-save = Save

## 5 — Magic link
magic-sent-title = Check your inbox
magic-sent-body = A link is on its way to { $email }. It works for 10 minutes.
magic-resend = Send another link
magic-resend-wait = Resend in { $seconds }s
magic-ok-title = You are signed in
magic-ok-body = Taking you to { $app }…
magic-expired-title = This link has expired
magic-expired-body = Ask for a new one from the sign-in page.
magic-expired-action = Ask for a new link

## 6 — Consent
consent-title = { $app } is asking for:
consent-scope-profile = Your name and picture
consent-scope-email = Your email address
consent-scope-offline = Access while you are away
consent-account = Signed in as { $account }
consent-switch = Switch account
consent-accept = Allow
consent-decline = Deny

## 7 — Sign-out
logout-title = Sign out?
logout-body = { $app } is asking to close your session.
logout-yes = Sign out
logout-no = Stay signed in
logout-done-title = You are signed out
logout-done-body = You can close this page.
logout-done-return = Return to { $app }
logout-kept-title = You are still signed in
logout-kept-body = No session was closed.

## 8 — Error
error-title = This request did not go through
error-body = Go back to the application and start signing in again. If it happens again, contact its support team.

## 9 — Device
device-title = Connect a device
device-subtitle = Enter the code shown on your device.
device-code = Code
device-confirm-title = Connecting { $device }?
device-confirm-body = Only allow this if you just started signing in on that device.
device-confirm-yes = Allow
device-confirm-no = Deny
device-done-title = All set
device-done-body = Go back to your device — it carries on from there.

## 10 — CIBA
ciba-title = Waiting requests
ciba-empty = Nothing waiting.
ciba-approve = Approve
ciba-decline = Deny
ciba-expires = Expires in { $seconds }s

## Page glue — strings the sign-in page itself carries
totp-one-time = One-time code
enroll-add = Add this account to your authenticator app, then enter the code it shows.
enroll-open = Open in your authenticator app
consent-asking = is asking for access to your account.
flash-refused = Sign-in refused.
flash-no-such-login = This sign-in has expired or was never started. Go back to the application and try again.
flash-key-needs-script = A security key needs scripts enabled on this page.
flash-wrong-browser = Open that link in the browser where you started signing in. It is still good.
flash-consent = This application is asking for access to your account, and answering that needs scripts enabled on this page.
flash-locked-out = Too many failed attempts. Sign-in is paused for a while; try again later, or ask an administrator to lift it.
flash-went-wrong = Something went wrong. Try again.
flash-no-key-here = This browser cannot use a security key here.
flash-key-silent = The key did not answer.
org-choose-title = Choose an organization to continue.
flash-choice-needs-script = Choosing an organization needs scripts enabled on this page.
