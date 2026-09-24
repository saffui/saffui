app-title = Compte { $realm }
loading = Chargement…
nav-label = Votre compte
nav-profile = Profil
nav-security = Sécurité
nav-sessions = Connexions
nav-applications = Applications
tongue-label = Langue
tongue-help = La langue de cette page, et des pages de connexion vers lesquelles elle vous envoie.
tongue-en = English
tongue-fr = Français
account-sign-out = Se déconnecter
account-sign-out-help = Mettre fin à votre connexion à { $realm } sur ce navigateur.

profile-title = Profil
profile-lead = Ce que { $realm } conserve à votre sujet.
profile-unreadable = Votre profil n'a pas pu être lu. Rechargez la page pour réessayer.
profile-identity = Identité
profile-name = Nom
profile-username = Identifiant
profile-username-help = Le nom avec lequel vous vous connectez. Il ne se change pas ici.
profile-contact = Coordonnées
profile-email = Adresse e-mail
profile-phone = Téléphone
profile-none = Non renseigné
profile-email-verified = Vérifiée
profile-email-unverified = Non vérifiée
profile-email-verified-help = { $realm } a vérifié que cette adresse est bien la vôtre.
profile-email-unverified-help = Cette adresse n'a pas encore été vérifiée par { $realm } : aucun avis de sécurité n'y est donc envoyé.
profile-phone-verified = Vérifié
profile-phone-unverified = Non vérifié
profile-phone-verified-help = { $realm } a vérifié que ce numéro est bien le vôtre.
profile-phone-unverified-help = Ce numéro n'a pas encore été vérifié par { $realm }.
profile-more = Autres informations
profile-nickname = Surnom
profile-middle-name = Deuxième prénom
profile-birthdate = Date de naissance
profile-gender = Genre
profile-locale = Langue
profile-zoneinfo = Fuseau horaire
profile-website = Site web
profile-page = Page de profil
profile-address = Adresse postale
profile-managed = Ces informations sont conservées par { $realm }. Pour en modifier une, adressez-vous à votre administrateur.
profile-updated = Dernière modification le { $when }.

return-busy = Connexion en cours…
signed-out-title = Déconnexion effectuée
signed-out-lead = Votre connexion à { $realm } est terminée sur ce navigateur.
signed-out-again = Se reconnecter
trouble-title = Votre page de compte n'a pas pu s'ouvrir
trouble-lead = { $realm } n'a pas accepté que cette page utilise votre connexion. Réessayez, et si cela se reproduit, prévenez votre administrateur.
trouble-again = Réessayer
nowhere-title = Aucune page de compte ici
nowhere-lead = Cette adresse ne nomme aucun realm. Une page de compte se trouve à /realms/, suivi du nom du realm, puis de /account/.

sessions-title = Connexions
sessions-lead = Les endroits où votre compte est connecté, et ce que les applications ont obtenu de chaque connexion. Mettez fin à celles que vous ne reconnaissez pas.
sessions-unreadable = Vos connexions n'ont pas pu être lues. Rechargez la page pour réessayer.
sessions-end-others = Déconnecter partout ailleurs
sessions-end-others-help = Met fin à toutes les connexions sauf celle de ce navigateur, avec les accès hors ligne qui en dépendent.
sessions-no-others = Ce navigateur est votre seule connexion.
sessions-device = { $browser } sur { $system }
sessions-device-unknown = Appareil inconnu
sessions-this-browser = Ce navigateur
sessions-this-browser-help = La connexion qu'utilise cette page en ce moment.
sessions-closed = Terminée
sessions-closed-help = Cette connexion est terminée, mais une application garde un accès hors ligne obtenu grâce à elle.
sessions-started = Connexion le { $when }
sessions-from = Depuis { $address }
sessions-through = Via { $provider }
sessions-ends = Prend fin le { $when }
sessions-applications = Applications
sessions-no-applications = Aucune application ne détient d'accès par cette connexion.
sessions-offline = Accès hors ligne
sessions-offline-help = { $application } peut accéder à votre compte en votre absence, jusqu'à ce que cet accès lui soit retiré.
sessions-take-back = Retirer l'accès
sessions-take-back-help = Retirer ce que { $application } a obtenu par cette connexion.
sessions-end = Mettre fin à cette connexion
sessions-end-current = Se déconnecter de ce navigateur
sessions-ended = La connexion a pris fin.
sessions-ended-others = { $count ->
    [0] Aucune autre connexion n'était ouverte.
    [one] Une autre connexion a pris fin.
   *[other] { $count } autres connexions ont pris fin.
}
sessions-taken-back = { $application } ne détient plus d'accès par cette connexion.
sessions-gone = C'était déjà terminé. La liste est à jour.
sessions-failed = La modification n'a pas abouti. Rechargez la page pour voir où en sont les choses.

confirm-keep = Annuler
confirm-end-title = Mettre fin à cette connexion ?
confirm-end-body = { $device } est déconnecté et perd les accès hors ligne qui dépendent de cette connexion. Les applications qui ont demandé à en être informées le sont.
confirm-end = Mettre fin
confirm-end-current-title = Se déconnecter de ce navigateur ?
confirm-end-current-body = Votre connexion ici prend fin, avec les accès hors ligne qui en dépendent. Les applications qui ont demandé à en être informées le sont.
confirm-end-current = Se déconnecter
confirm-end-others-title = Déconnecter partout ailleurs ?
confirm-end-others-body = Toutes les autres connexions prennent fin, avec les accès hors ligne qui en dépendent. Ce navigateur reste connecté.
confirm-end-others = Déconnecter partout ailleurs
confirm-take-back-title = Retirer l'accès de { $application } ?
confirm-take-back-body = { $application } perd ce qu'elle a obtenu par cette connexion, accès hors ligne compris. Un jeton qu'elle détient déjà fonctionne jusqu'à son expiration, en général quelques minutes. Cette page reste connectée.
confirm-take-back = Retirer l'accès

security-title = Sécurité
security-lead = Comment vous vous connectez à { $realm } : votre mot de passe, et les autres moyens que vous avez ajoutés.
security-unreadable = Vos moyens de connexion n'ont pas pu être lus. Rechargez la page pour réessayer.
security-step-up = Se reconnecter
security-step-up-lead = Pour changer votre mot de passe ou retirer un moyen de connexion, reconnectez-vous d'abord. Cela empêche quiconque trouve ce navigateur ouvert de vous fermer l'accès à votre compte.
security-step-up-not-enough = Votre nouvelle connexion ne suffit pas pour cela. Reconnectez-vous avec votre moyen le plus fort, comme votre application d'authentification ou votre clé de sécurité.
security-step-up-help = Vous passez par la page de connexion puis revenez ici. Ce qui a été saisi sur cette page est perdu.
security-step-up-needed = Cette modification demande une connexion plus récente. Reconnectez-vous, puis réessayez.
security-step-up-refused = La nouvelle connexion n'a pas abouti. Rien n'a été modifié.
security-enrol-refused = { $realm } ne propose pas ce moyen de connexion ici.
security-password = Mot de passe
security-password-current = Mot de passe actuel
security-password-new = Nouveau mot de passe
security-password-new-help = { $realm } peut exiger une longueur, des chiffres, des majuscules ou de la ponctuation, et refuser un mot de passe déjà utilisé.
security-password-again = Nouveau mot de passe, à nouveau
security-password-change = Changer le mot de passe
security-password-change-help = Changer votre mot de passe met fin à vos autres connexions : un appareil qui connaissait l'ancien devra se reconnecter.
security-password-none = Aucun mot de passe n'est conservé ici pour votre compte.
security-password-missing = Saisissez votre mot de passe actuel et un nouveau.
security-password-repeat-differs = Le nouveau mot de passe et sa répétition diffèrent.
security-password-wrong = Le mot de passe actuel n'est pas le bon. Trop d'essais erronés peuvent verrouiller le compte un moment.
security-password-locked = Trop d'essais erronés : votre compte est verrouillé pour un moment. Réessayez plus tard.
security-password-throttled = Trop de tentatives échouées depuis votre réseau. Patientez un moment, puis réessayez.
security-password-not-here = Votre mot de passe est géré par un autre service : il ne se change pas ici.
security-password-changed = Mot de passe changé. { $count ->
    [0] Aucune autre connexion n'était ouverte.
    [one] Une autre connexion a pris fin.
   *[other] { $count } autres connexions ont pris fin.
}
security-rule-too-short = Le nouveau mot de passe est trop court.
security-rule-too-long = Le nouveau mot de passe est trop long.
security-rule-digits = Le nouveau mot de passe demande plus de chiffres.
security-rule-capitals = Le nouveau mot de passe demande plus de majuscules.
security-rule-small-letters = Le nouveau mot de passe demande plus de minuscules.
security-rule-punctuation = Le nouveau mot de passe demande plus de ponctuation.
security-rule-about-you = Le nouveau mot de passe ressemble trop à des informations vous concernant.
security-rule-refused = Ce mot de passe n'est pas autorisé. Choisissez-en un autre.
security-rule-shape = Le nouveau mot de passe n'a pas la forme demandée.
security-rule-used-before = Vous avez déjà utilisé ce mot de passe. Choisissez-en un nouveau.
security-apps = Applications d'authentification
security-apps-none = Aucune application d'authentification n'est configurée.
security-apps-add = Ajouter une application d'authentification
security-apps-add-help = Vous vous reconnectez, puis scannez un code avec l'application de votre téléphone.
security-app-unnamed = Application d'authentification
security-keys = Clés de sécurité et passkeys
security-keys-none = Aucune clé de sécurité ni passkey n'est configurée.
security-keys-add = Ajouter une clé de sécurité ou une passkey
security-keys-add-help = Vous vous reconnectez, puis votre navigateur demande la clé, ou l'empreinte, le visage ou le code de votre appareil.
security-codes = Codes de secours
security-codes-left = { $count ->
    [0] Vous n'avez aucun code de secours.
    [one] Il vous reste un code de secours.
   *[other] Il vous reste { $count } codes de secours.
}
security-codes-new = Obtenir de nouveaux codes
security-codes-new-help = Vous vous reconnectez, et un nouveau jeu de codes s'affiche une seule fois. Les codes précédents cessent de fonctionner.
security-codes-remove = Retirer les codes
security-added = Ajout le { $when }
security-used = Dernière utilisation le { $when }
security-remove = Retirer
security-removed = C'est retiré.
security-gone = C'était déjà retiré. La liste est à jour.
security-failed = La modification n'a pas abouti. Rechargez la page pour voir où en sont les choses.
security-kept-last-second-factor = C'est votre dernière seconde étape de connexion : ajoutez-en une autre avant de la retirer.
security-kept-only-way-in = Cette clé est votre seul moyen de connexion : ajoutez-en un autre avant de la retirer.
confirm-remove = Retirer
confirm-remove-app-title = Retirer { $name } ?
confirm-remove-app-body = Vous ne pourrez plus vous connecter avec cette application d'authentification. Supprimez aussi son entrée dans l'application.
confirm-remove-key-title = Retirer { $name } ?
confirm-remove-key-body = Vous ne pourrez plus vous connecter avec cette clé ou cette passkey.
confirm-remove-codes-title = Retirer vos codes de secours ?
confirm-remove-codes-body = { $count ->
    [one] Votre dernier code cesse de fonctionner.
   *[other] Vos { $count } codes cessent de fonctionner.
} Vous pouvez en obtenir un nouveau jeu à tout moment.

applications-title = Applications
applications-lead = Les applications qui détiennent quelque chose de vous : ce que vous avez accepté qu'elles aient, et les accès qu'elles tiennent de vos connexions.
applications-unreadable = Vos applications n'ont pas pu être lues. Rechargez la page pour réessayer.
applications-none = Aucune application ne détient quoi que ce soit de vous.
applications-visit = Ouvrir
applications-visit-help = Ouvrir { $application } dans un nouvel onglet.
applications-consent = Ce que vous avez accepté
applications-agreed = Accepté le { $when }
applications-withdraw-consent = Retirer le consentement
applications-withdraw-consent-help = L'application garde ce qu'elle détient déjà, et vous redemande votre accord à sa prochaine connexion.
applications-withdraw-consent-help-unasked = L'application garde ce qu'elle détient déjà, et ne demande pas d'accord avant de vous connecter : seule la trace de votre accord disparaît.
applications-access = Accès
applications-access-logins = { $count ->
    [one] Détient un accès par une de vos connexions.
   *[other] Détient un accès par { $count } de vos connexions.
}
applications-access-until = Jusqu'au { $when }
applications-take-back-access = Retirer l'accès
applications-take-back-access-help = Met fin à ce que l'application a obtenu de toutes vos connexions, accès hors ligne compris. Vos connexions restent ouvertes.
applications-scope-openid = Qui vous êtes
applications-scope-profile = Votre nom et votre profil
applications-scope-email = Votre adresse e-mail
applications-scope-phone = Votre numéro de téléphone
applications-scope-address = Votre adresse postale
applications-scope-offline-access = Un accès en votre absence
applications-consent-withdrawn = Votre consentement à { $application } est retiré.
applications-access-taken-back = { $count ->
    [one] { $application } ne détient plus d'accès par une de vos connexions.
   *[other] { $application } ne détient plus d'accès par { $count } de vos connexions.
}
applications-gone = C'était déjà fait. La liste est à jour.
applications-failed = La modification n'a pas abouti. Rechargez la page pour voir où en sont les choses.
confirm-withdraw-consent = Retirer le consentement
confirm-withdraw-consent-title = Retirer votre consentement à { $application } ?
confirm-withdraw-consent-body = { $application } garde ce qu'elle détient déjà. À sa prochaine connexion, elle vous redemande votre accord.
confirm-withdraw-consent-body-unasked = { $application } garde ce qu'elle détient déjà, et ne demande pas d'accord avant de vous connecter : sa prochaine connexion se fera sans vous le demander. Seule la trace de votre accord disparaît.
confirm-take-back-access = Retirer l'accès
confirm-take-back-access-title = Retirer l'accès de { $application } ?
confirm-take-back-access-body = { $application } perd ce qu'elle a obtenu de toutes vos connexions, accès hors ligne compris, et en est informée si elle l'a demandé. Un jeton qu'elle détient déjà fonctionne jusqu'à son expiration, en général quelques minutes. Votre consentement reste jusqu'à ce que vous le retiriez.
