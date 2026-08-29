/// Declare the catalogue.
///
/// One table, four projections. Written this way because the alternative is
/// four lists that agree until one of them does not: a code added to the enum
/// and forgotten in `ALL` is a code nothing tests, which is how the reference
/// implementation ended up with an entry its own test never reached.
macro_rules! catalogue {
    ($($variant:ident = $code:literal, $status:literal, $slug:literal, $message:literal;)+) => {
        /// A catalogued failure.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[repr(u32)]
        pub enum ErrorCode {
            $($variant = $code,)+
        }

        impl ErrorCode {
            /// Every code, complete by construction.
            pub const ALL: &'static [ErrorCode] = &[$(ErrorCode::$variant,)+];

            /// The HTTP status this maps to. A transport concern, kept apart
            /// from the number, which is the contract.
            pub const fn status(self) -> u16 {
                match self { $(Self::$variant => $status,)+ }
            }

            /// The greppable slug, and the key an i18n catalogue would use.
            pub const fn slug(self) -> &'static str {
                match self { $(Self::$variant => $slug,)+ }
            }

            /// The built-in English message.
            pub const fn message(self) -> &'static str {
                match self { $(Self::$variant => $message,)+ }
            }
        }
    };
}

impl ErrorCode {
    /// The stable number.
    pub const fn code(self) -> u32 {
        self as u32
    }
}

catalogue! {
    ValidationError = 4000, 422, "validation_error", "the request payload is invalid";
    Unauthorized = 91, 401, "unauthorized", "authentication required";
    AccessDenied = 90, 403, "access_denied", "access denied";
    BadRequest = 4001, 400, "bad_request", "the request is invalid";
    TooManyRequests = 4029, 429, "too_many_requests", "too many requests; retry later";
    InternalError = 5000, 500, "internal_error", "an internal error occurred";
    NotImplemented = 5010, 501, "not_implemented", "this feature is not implemented";
    RealmNotFound = 100, 404, "realm.not_found", "unknown realm";
    MailSettingsNotFound = 102, 404, "realm.mail.not_found", "this realm has no mail settings";
    RealmAlreadyExists = 101, 409, "realm.already_exists", "a realm with this identifier already exists";
    KeyNotFound = 110, 404, "realm.key.not_found", "this realm holds no such key";
    KeyStillActive = 111, 409, "realm.key.still_active", "this key is still in service; rotate its algorithm first";
    UserNotFound = 200, 404, "user.not_found", "user not found";
    UserAlreadyExists = 201, 409, "user.already_exists", "a user with this identifier already exists in the realm";
    ClientNotFound = 300, 404, "client.not_found", "client not found";
    ClientAlreadyExists = 301, 409, "client.already_exists", "a client with this identifier already exists";
    ClientScopeNotFound = 310, 404, "client.scope.not_found", "client scope not found";
    ClientScopeAlreadyExists = 311, 409, "client.scope.already_exists", "a client scope with this name already exists";
    ProtocolMapperNotFound = 320, 404, "protocol_mapper.not_found", "protocol mapper not found";
    ProtocolMapperAlreadyExists = 321, 409, "protocol_mapper.already_exists", "a protocol mapper with this name already exists";
    NoActiveFlow = 411, 503, "auth.no_active_flow", "no active login flow for this realm";
    SessionExpired = 410, 400, "auth.session_expired", "the login session has expired; start again";
    SessionNotFound = 412, 404, "auth.session.not_found", "session not found";
    GrantNotFound = 413, 404, "auth.grant.not_found", "this client holds nothing from that session";
    AuthFlowNotFound = 420, 404, "auth.flow.not_found", "authentication flow not found";
    AuthFlowAlreadyExists = 421, 409, "auth.flow.already_exists", "an authentication flow with this alias already exists";
    AuthExecutionNotFound = 430, 404, "auth.execution.not_found", "authentication execution not found";
    AuthExecutionAlreadyExists = 431, 409, "auth.execution.already_exists", "an authentication execution with this identity already exists";
    AuthConfigNotFound = 440, 404, "auth.config.not_found", "authenticator config not found";
    AuthConfigAlreadyExists = 441, 409, "auth.config.already_exists", "an authenticator config with this alias already exists";
    RequiredActionNotFound = 450, 404, "auth.required_action.not_found", "required action not found";
    RequiredActionAlreadyExists = 451, 409, "auth.required_action.already_exists", "a required action with this alias already exists";
    OrganizationNotFound = 700, 404, "organization.not_found", "organization not found";
    OrganizationAlreadyExists = 701, 409, "organization.already_exists", "an organization with this name already exists";
    CredentialNotFound = 800, 404, "credential.not_found", "credential not found";
    RoleNotFound = 900, 404, "role.not_found", "role not found";
    RoleAlreadyExists = 901, 409, "role.already_exists", "a role with this name already exists";
    GroupNotFound = 910, 404, "group.not_found", "group not found";
    GroupAlreadyExists = 911, 409, "group.already_exists", "a group with this name already exists";
    StillGranted = 912, 409, "directory.still_granted", "still granted, so not deleted";
    IdentityProviderNotFound = 920, 404, "identity_provider.not_found", "identity provider not found";
    IdentityProviderAlreadyExists = 921, 409, "identity_provider.already_exists", "an identity provider with this alias already exists";
    IdpMapperNotFound = 922, 404, "identity_provider.mapper.not_found", "identity provider mapper not found";
    RebacSchemaNotFound = 970, 404, "rebac.schema.not_found", "the realm has no relationship schema";
    RebacEdgeNotFound = 971, 404, "rebac.edge.not_found", "no such relationship stands";
    ResourceServerNotFound = 930, 404, "resource_server.not_found", "resource server not found";
    ResourceServerAlreadyExists = 931, 409, "resource_server.already_exists", "a resource server with this identifier already exists";
    ResourceNotFound = 940, 404, "resource.not_found", "resource not found";
    ResourceAlreadyExists = 941, 409, "resource.already_exists", "a resource with this name already exists";
    ScopeNotFound = 950, 404, "scope.not_found", "authorization scope not found";
    ScopeAlreadyExists = 951, 409, "scope.already_exists", "an authorization scope with this name already exists";
    PolicyNotFound = 960, 404, "policy.not_found", "authorization policy not found";
    PolicyAlreadyExists = 961, 409, "policy.already_exists", "an authorization policy with this name already exists";
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;

    /// No two failures share a number.
    ///
    /// The one property that must never break: a client tells failures apart by
    /// this number, so two sharing it are one failure as far as any caller can
    /// see. Nothing in the reference implementation checked it.
    #[test]
    fn every_code_is_its_own_number() {
        let mut seen = HashSet::new();

        for code in ErrorCode::ALL {
            assert!(
                seen.insert(code.code()),
                "{:?} reuses number {}",
                code,
                code.code()
            );
        }

        assert_eq!(seen.len(), ErrorCode::ALL.len());
    }

    /// Nor a slug, which is the other identity a caller may match on.
    #[test]
    fn every_code_is_its_own_slug() {
        let mut seen = HashSet::new();

        for code in ErrorCode::ALL {
            assert!(
                seen.insert(code.slug()),
                "{:?} reuses slug {}",
                code,
                code.slug()
            );
        }
    }

    /// The number is the discriminant, so `code()` cannot drift from the table.
    #[test]
    fn the_number_is_the_discriminant() {
        assert_eq!(ErrorCode::RealmNotFound.code(), 100);
        assert_eq!(ErrorCode::InternalError.code(), 5000);
        assert_eq!(ErrorCode::TooManyRequests.code(), 4029);
    }

    /// Every entry is answerable: a real failure status, a slug, a message.
    ///
    /// Bounded above as well as below — the reference asked only for `>= 400`,
    /// which a status of 999 satisfies.
    #[test]
    fn every_code_answers_for_itself() {
        for code in ErrorCode::ALL {
            assert!(
                (400..=599).contains(&code.status()),
                "{code:?} has status {}",
                code.status()
            );
            assert!(!code.slug().is_empty(), "{code:?}");
            assert!(!code.message().is_empty(), "{code:?}");
        }
    }

    /// The catalogue is the size it is, so a code cannot be removed unnoticed.
    ///
    /// Adding one is meant to change this number; removing one is meant to be
    /// hard, because a number that stops existing is a contract broken for
    /// whoever still sends it.
    #[test]
    fn the_catalogue_has_not_shrunk() {
        assert_eq!(ErrorCode::ALL.len(), 53);
    }

    /// A message never restates the slug, and never carries a value.
    ///
    /// These reach a client. A message that echoed an identifier would put
    /// caller-supplied text into a response nobody sanitised.
    #[test]
    fn a_message_is_prose_and_not_a_key() {
        for code in ErrorCode::ALL {
            assert!(
                !code.message().contains('_') || code.message().contains(' '),
                "{code:?} reads like a key: {}",
                code.message()
            );
            assert!(!code.message().contains('{'), "{code:?} has a placeholder");
        }
    }
}
