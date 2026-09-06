# Saffui — hosted UI strings (fr)
# Fluent. Les clés sont partagées avec en.ftl.

## Commun
action-signin = Se connecter
action-continue = Continuer
action-cancel = Annuler
action-back-signin = Retour à la connexion
action-retry = Réessayer
action-copy = Copier
common-or = ou
common-request-id = Référence de la demande

## 1 — Connexion
login-title = Se connecter
login-subtitle = Connectez-vous pour continuer.
login-username = Identifiant
login-password = Mot de passe
login-forgot = Mot de passe oublié ?
login-magic-link = Recevoir un lien par e-mail
login-federated = Continuer avec { $provider }
login-error-rejected = Identifiant ou mot de passe incorrect. Vérifiez vos informations et réessayez.
login-error-locked = Identifiant ou mot de passe incorrect. Vérifiez vos informations et réessayez.

## 2 — Deuxième facteur TOTP
totp-title = Code de vérification
totp-subtitle = Saisissez le code à 6 chiffres affiché par votre application.
totp-code = Code
totp-error = Code refusé. Le code change toutes les 30 secondes : saisissez le suivant.
totp-use-passkey = Utiliser une clé de sécurité à la place

## 3 — Enrôlement TOTP
enroll-title = Ajouter une application de codes
enroll-step-1 = 1. Scannez ce code avec votre application.
enroll-step-2 = 2. Saisissez le code affiché.
enroll-secret-label = Ou saisissez cette clé à la main
enroll-code = Code affiché par l'application
enroll-submit = Activer

## 4 — Clé de sécurité / passkey
passkey-title = Clé de sécurité
passkey-waiting = Touchez votre clé, ou utilisez cet appareil.
passkey-error = La clé n'a pas répondu. Réessayez, ou utilisez un code.
passkey-use-totp = Utiliser un code à la place
passkey-add-title = Ajouter une clé à ce compte
passkey-add-body = Votre navigateur va vous demander confirmation.
passkey-add-action = Ajouter une clé
passkey-name-title = Clé ajoutée
passkey-name-label = Nom de la clé
passkey-name-hint = Pour la reconnaître plus tard.
passkey-name-save = Enregistrer

## 5 — Lien magique
magic-sent-title = Vérifiez votre boîte mail
magic-sent-body = Un lien vient de partir vers { $email }. Il est valable 10 minutes.
magic-resend = Renvoyer le lien
magic-resend-wait = Renvoyer dans { $seconds } s
magic-ok-title = Connexion confirmée
magic-ok-body = Redirection vers { $app }…
magic-expired-title = Ce lien a expiré
magic-expired-body = Demandez-en un nouveau depuis la page de connexion.
magic-expired-action = Demander un nouveau lien

## 6 — Consentement
consent-title = { $app } demande :
consent-scope-profile = Votre nom et votre photo
consent-scope-email = Votre adresse e-mail
consent-scope-offline = Un accès quand vous n'êtes pas connecté
consent-account = Connecté en tant que { $account }
consent-switch = Changer de compte
consent-accept = Autoriser
consent-decline = Refuser

## 7 — Déconnexion
logout-title = Se déconnecter ?
logout-body = { $app } demande à fermer votre session.
logout-yes = Se déconnecter
logout-no = Rester connecté
logout-done-title = Vous êtes déconnecté
logout-done-body = Vous pouvez fermer cette page.
logout-done-return = Retourner à { $app }
logout-kept-title = Vous restez connecté
logout-kept-body = Aucune session n'a été fermée.

## 8 — Erreur
error-title = Cette demande n'a pas abouti
error-body = Retournez à l'application et relancez la connexion. Si cela se reproduit, contactez son support.

## 9 — Appareil
device-title = Connecter un appareil
device-subtitle = Saisissez le code affiché sur votre appareil.
device-code = Code
device-confirm-title = Vous connectez { $device } ?
device-confirm-body = N'autorisez que si vous venez de lancer la connexion sur cet appareil.
device-confirm-yes = Autoriser
device-confirm-no = Refuser
device-done-title = C'est fait
device-done-body = Retournez sur votre appareil, la connexion continue là-bas.

## 10 — CIBA
ciba-title = Demandes en attente
ciba-empty = Aucune demande.
ciba-approve = Approuver
ciba-decline = Refuser
ciba-expires = Expire dans { $seconds } s

## Colle de page — les chaînes portées par la page de connexion elle-même
totp-one-time = Code à usage unique
enroll-add = Ajoutez ce compte à votre application de codes, puis saisissez le code affiché.
enroll-open = Ouvrir dans votre application
consent-asking = demande l'accès à votre compte.
flash-refused = Connexion refusée.
flash-no-such-login = Cette connexion a expiré ou n'a jamais commencé. Retournez à l'application et réessayez.
flash-key-needs-script = Une clé de sécurité nécessite les scripts sur cette page.
flash-wrong-browser = Ouvrez ce lien dans le navigateur où vous avez commencé la connexion. Il est toujours valable.
flash-consent = Cette application demande l'accès à votre compte, et répondre nécessite les scripts sur cette page.
flash-locked-out = Trop de tentatives échouées. La connexion est suspendue un moment ; réessayez plus tard, ou demandez à un administrateur de la débloquer.
flash-went-wrong = Une erreur est survenue. Réessayez.
flash-no-key-here = Ce navigateur ne peut pas utiliser de clé de sécurité ici.
flash-key-silent = La clé n'a pas répondu.
org-choose-title = Choisissez une organisation pour continuer.
flash-choice-needs-script = Choisir une organisation nécessite les scripts sur cette page.
flash-no-such-code = Ce code n'est pas valable. Vérifiez-le sur votre appareil et réessayez.
flash-device-expired = Cette connexion a expiré. Recommencez sur votre appareil.
flash-doorbell-signed-out = Connectez-vous d'abord dans ce navigateur, puis revenez sur cette page.

## Les portes optionnelles de la page de connexion.
login-remember = Rester connecté sur ce navigateur
recover-lede = Nommez votre compte et un lien de réinitialisation part vers son adresse.
recover-send = Envoyer le lien
recover-sent = Si ce compte existe, le courriel est en route.
recover-back = Retour à la connexion

## La moitié inscription de la page de connexion.
signup-invite = Première visite ?
signup-link = Créer un compte
signup-title = Créez votre compte
signup-email = Adresse e-mail
signup-given = Prénom
signup-family = Nom
signup-again = Mot de passe, encore
signup-send = Créer le compte
signup-done = Votre compte est prêt. Connectez-vous avec.
signup-verify = Consultez votre messagerie pour continuer : une vérification est en route.
signup-mismatch = Les deux mots de passe ne sont pas identiques.
login-passkey = Se connecter avec une passkey

## Codes de récupération : le chemin de retour quand le second facteur a disparu.
recovery-use = Utiliser un code de récupération
recovery-code = Code de récupération
recovery-keep = Gardez-les en lieu sûr. Chacun ouvre une session une fois, et c'est la seule fois qu'ils s'affichent.
recovery-confirm = Retapez-en un pour confirmer que vous les avez gardés

## Le remplacement que le realm exige.
renew-lede = Ce realm vous demande un nouveau mot de passe avant de continuer.
renew-password = Nouveau mot de passe
renew-again = Nouveau mot de passe, encore
