app-title = { $realm } account
loading = Loading…
nav-label = Your account
nav-profile = Profile
nav-security = Security
nav-sessions = Sign-ins
nav-applications = Applications
tongue-label = Language
tongue-help = The language of this page, and of the sign-in pages it sends you to.
tongue-en = English
tongue-fr = Français
account-sign-out = Sign out
account-sign-out-help = End your sign-in to { $realm } on this browser.

profile-title = Profile
profile-lead = What { $realm } holds about you.
profile-unreadable = Your profile could not be read. Reload the page to try again.
profile-identity = Identity
profile-name = Name
profile-username = Username
profile-username-help = The name you sign in with. It cannot be changed here.
profile-contact = Contact
profile-email = Email
profile-phone = Phone
profile-none = None given
profile-email-verified = Verified
profile-email-unverified = Not verified
profile-email-verified-help = { $realm } has checked that this address is yours.
profile-email-unverified-help = { $realm } has not checked this address yet, so no security notice is sent to it.
profile-phone-verified = Verified
profile-phone-unverified = Not verified
profile-phone-verified-help = { $realm } has checked that this number is yours.
profile-phone-unverified-help = { $realm } has not checked this number yet.
profile-more = More about you
profile-nickname = Nickname
profile-middle-name = Middle name
profile-birthdate = Date of birth
profile-gender = Gender
profile-locale = Language
profile-zoneinfo = Time zone
profile-website = Website
profile-page = Profile page
profile-address = Address
profile-managed = { $realm } keeps these details. To change one, ask your administrator.
profile-updated = Last changed on { $when }.

return-busy = Signing you in…
signed-out-title = You are signed out
signed-out-lead = Your sign-in to { $realm } has ended on this browser.
signed-out-again = Sign in again
trouble-title = Your account page could not open
trouble-lead = { $realm } did not let this page use your sign-in. Try again, and if it keeps happening, tell your administrator.
trouble-again = Try again
nowhere-title = No account page here
nowhere-lead = This address names no realm. An account page lives at /realms/, then the realm's name, then /account/.

sessions-title = Sign-ins
sessions-lead = Where your account is signed in, and what applications got from each sign-in. End any you do not recognise.
sessions-unreadable = Your sign-ins could not be read. Reload the page to try again.
sessions-end-others = Sign out everywhere else
sessions-end-others-help = Ends every sign-in but this browser's, with the offline access that relies on them.
sessions-no-others = This browser is your only sign-in.
sessions-device = { $browser } on { $system }
sessions-device-unknown = Unknown device
sessions-this-browser = This browser
sessions-this-browser-help = The sign-in this page is using right now.
sessions-closed = Signed out
sessions-closed-help = This sign-in has ended, but an application still holds offline access from it.
sessions-started = Signed in on { $when }
sessions-from = From { $address }
sessions-through = Through { $provider }
sessions-ends = Ends on { $when }
sessions-applications = Applications
sessions-no-applications = No application holds access through this sign-in.
sessions-offline = Offline access
sessions-offline-help = { $application } can keep reaching your account while you are away, until its access is taken back.
sessions-take-back = Take back access
sessions-take-back-help = Take back what { $application } got through this sign-in.
sessions-end = End this sign-in
sessions-end-current = Sign out of this browser
sessions-ended = The sign-in ended.
sessions-ended-others = { $count ->
    [0] No other sign-in was open.
    [one] One other sign-in ended.
   *[other] { $count } other sign-ins ended.
}
sessions-taken-back = { $application } no longer holds access through that sign-in.
sessions-gone = That had already ended. The list is up to date.
sessions-failed = The change did not go through. Reload the page to see where things stand.

confirm-keep = Cancel
confirm-end-title = End this sign-in?
confirm-end-body = { $device } is signed out, and loses the offline access that relies on this sign-in. Applications that asked to hear of it are told.
confirm-end = End sign-in
confirm-end-current-title = Sign out of this browser?
confirm-end-current-body = Your sign-in here ends, with the offline access that relies on it. Applications that asked to hear of it are told.
confirm-end-current = Sign out
confirm-end-others-title = Sign out everywhere else?
confirm-end-others-body = Every other sign-in ends, with the offline access that relies on it. This browser stays signed in.
confirm-end-others = Sign out everywhere else
confirm-take-back-title = Take back { $application }'s access?
confirm-take-back-body = { $application } loses what it got through this sign-in, offline access included. A token it already holds keeps working until it runs out, usually within minutes. This page stays signed in.
confirm-take-back = Take back access

security-title = Security
security-lead = How you sign in to { $realm }: your password, and the other ways you have added.
security-unreadable = Your ways to sign in could not be read. Reload the page to try again.
security-step-up = Sign in again
security-step-up-lead = To change your password or remove a way to sign in, sign in again first. It keeps anyone who finds this browser open from locking you out.
security-step-up-not-enough = Your new sign-in was not strong enough for this. Sign in again with the strongest way you have, such as your authenticator app or your security key.
security-step-up-help = You go through the sign-in page and come back here. Anything typed on this page is lost.
security-step-up-needed = This change needs a more recent sign-in. Sign in again, then try once more.
security-step-up-refused = The new sign-in did not finish. Nothing was changed.
security-enrol-refused = { $realm } does not offer that way to sign in here.
security-password = Password
security-password-current = Current password
security-password-new = New password
security-password-new-help = { $realm } may ask for a length, digits, capitals or punctuation, and may refuse a password used before.
security-password-again = New password, again
security-password-change = Change password
security-password-change-help = Changing your password ends your other sign-ins, so a device that knew the old one has to sign in again.
security-password-none = No password is kept here for your account.
security-password-missing = Type your current password and a new one.
security-password-repeat-differs = The new password and its repeat differ.
security-password-wrong = The current password is not right. Too many wrong tries can lock the account for a while.
security-password-locked = Too many wrong tries: your account is locked for a while. Try again later.
security-password-not-here = Your password is kept by another service, so it cannot be changed here.
security-password-changed = Password changed. { $count ->
    [0] No other sign-in was open.
    [one] One other sign-in ended.
   *[other] { $count } other sign-ins ended.
}
security-rule-too-short = The new password is too short.
security-rule-too-long = The new password is too long.
security-rule-digits = The new password needs more digits.
security-rule-capitals = The new password needs more capital letters.
security-rule-small-letters = The new password needs more small letters.
security-rule-punctuation = The new password needs more punctuation.
security-rule-about-you = The new password is too close to things about you.
security-rule-refused = This password is not allowed. Choose another.
security-rule-shape = The new password does not have the form required.
security-rule-used-before = You used this password before. Choose one you have not used.
security-apps = Authenticator apps
security-apps-none = No authenticator app is set up.
security-apps-add = Add an authenticator app
security-apps-add-help = You sign in again, then scan a code with the app on your phone.
security-app-unnamed = Authenticator app
security-keys = Security keys and passkeys
security-keys-none = No security key or passkey is set up.
security-keys-add = Add a security key or passkey
security-keys-add-help = You sign in again, then your browser asks for the key, or for your device's fingerprint, face or PIN.
security-codes = Recovery codes
security-codes-left = { $count ->
    [0] You have no recovery codes.
    [one] One recovery code left.
   *[other] { $count } recovery codes left.
}
security-codes-new = Get new codes
security-codes-new-help = You sign in again, and a new set of codes is shown once. Codes you had before stop working.
security-codes-remove = Remove codes
security-added = Added on { $when }
security-used = Last used on { $when }
security-remove = Remove
security-removed = Removed.
security-gone = That was already removed. The list is up to date.
security-failed = The change did not go through. Reload the page to see where things stand.
security-kept-last-second-factor = This is your last second step for signing in: add another before removing it.
security-kept-only-way-in = This key is the only way you sign in: add another way before removing it.
confirm-remove = Remove
confirm-remove-app-title = Remove { $name }?
confirm-remove-app-body = You will no longer sign in with this authenticator app. Remove its entry from the app too.
confirm-remove-key-title = Remove { $name }?
confirm-remove-key-body = You will no longer sign in with this key or passkey.
confirm-remove-codes-title = Remove your recovery codes?
confirm-remove-codes-body = { $count ->
    [one] Your last code stops working.
   *[other] Your { $count } codes stop working.
} You can get a new set at any time.

applications-title = Applications
applications-lead = The applications that hold something of yours: what you agreed they may have, and the access they hold from your sign-ins.
applications-unreadable = Your applications could not be read. Reload the page to try again.
applications-none = No application holds anything of yours.
applications-visit = Open
applications-visit-help = Open { $application } in a new tab.
applications-consent = What you agreed to
applications-agreed = Agreed on { $when }
applications-withdraw-consent = Withdraw consent
applications-withdraw-consent-help = The application keeps what it already holds, and asks for your agreement again the next time it signs you in.
applications-withdraw-consent-help-unasked = The application keeps what it already holds, and it does not ask for agreement before signing you in: only the record of your agreement goes.
applications-access = Access
applications-access-logins = { $count ->
    [one] Holds access through one of your sign-ins.
   *[other] Holds access through { $count } of your sign-ins.
}
applications-access-until = Until { $when }
applications-take-back-access = Take back access
applications-take-back-access-help = Ends what the application got from all your sign-ins, offline access included. Your sign-ins stay.
applications-scope-openid = Who you are
applications-scope-profile = Your name and profile
applications-scope-email = Your email address
applications-scope-phone = Your phone number
applications-scope-address = Your postal address
applications-scope-offline-access = Access while you are away
applications-consent-withdrawn = Your consent to { $application } is withdrawn.
applications-access-taken-back = { $count ->
    [one] { $application } no longer holds access through one of your sign-ins.
   *[other] { $application } no longer holds access through { $count } of your sign-ins.
}
applications-gone = That was already done. The list is up to date.
applications-failed = The change did not go through. Reload the page to see where things stand.
confirm-withdraw-consent = Withdraw consent
confirm-withdraw-consent-title = Withdraw your consent to { $application }?
confirm-withdraw-consent-body = { $application } keeps what it already holds. The next time it signs you in, it asks for your agreement again.
confirm-withdraw-consent-body-unasked = { $application } keeps what it already holds, and it does not ask for agreement before signing you in, so its next sign-in goes ahead. Only the record of your agreement goes.
confirm-take-back-access = Take back access
confirm-take-back-access-title = Take back { $application }'s access?
confirm-take-back-access-body = { $application } loses what it got from all your sign-ins, offline access included, and is told if it asked to be. A token it already holds keeps working until it runs out, usually within minutes. Your consent stays until you withdraw it.
