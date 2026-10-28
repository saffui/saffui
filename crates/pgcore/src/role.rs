//! What the connected role is allowed to do. Row security is the second wall
//! between tenants: a node must not serve under a role that walks through it.

use tokio_postgres::GenericClient;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleFacts {
    pub name: String,
    pub superuser: bool,
    pub bypasses_row_security: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the role {name} bypasses row security: a node does not serve under it")]
pub struct PrivilegedRole {
    pub name: String,
}

/// Reads the facts of the role this session runs as.
///
/// # Errors
///
/// Returns the driver's error when the catalog cannot be read.
pub async fn read_role_facts(
    client: &impl GenericClient,
) -> Result<RoleFacts, tokio_postgres::Error> {
    let row = client
        .query_one(
            "SELECT rolname::text, rolsuper, rolbypassrls FROM pg_catalog.pg_roles \
        WHERE rolname = current_user",
            &[],
        )
        .await?;
    Ok(RoleFacts {
        name: row.get(0),
        superuser: row.get(1),
        bypasses_row_security: row.get(2),
    })
}

/// Refuses a role under which row security does not apply.
///
/// # Errors
///
/// Returns the name of the role when it is a superuser or bypasses row security.
pub fn refuse_privileged_role(facts: &RoleFacts) -> Result<(), PrivilegedRole> {
    if facts.superuser || facts.bypasses_row_security {
        return Err(PrivilegedRole {
            name: facts.name.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{PrivilegedRole, RoleFacts, refuse_privileged_role};

    fn role(superuser: bool, bypasses_row_security: bool) -> RoleFacts {
        RoleFacts {
            name: "some_role".to_owned(),
            superuser,
            bypasses_row_security,
        }
    }

    #[test]
    fn an_ordinary_role_may_serve() {
        assert_eq!(refuse_privileged_role(&role(false, false)), Ok(()));
    }

    #[test]
    fn a_superuser_and_a_role_bypasses_row_security_are_both_refused() {
        let refused = Err(PrivilegedRole {
            name: "some_role".to_owned(),
        });
        assert_eq!(refuse_privileged_role(&role(true, false)), refused);
        assert_eq!(refuse_privileged_role(&role(false, true)), refused);
    }
}
