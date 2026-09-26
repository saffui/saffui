use crate::tenancy::UnitOfWork;
use models::messaging::Channel;

use crate::error::{StoreError, StoreResult};

/// The way this person asked their codes to come, if they asked it for the
/// number they hold now.
pub async fn chosen_for(
    transaction: &UnitOfWork,
    user_id: &str,
    recipient: &str,
) -> StoreResult<Option<Channel>> {
    let Some(row) = transaction
        .query_opt(
            "SELECT channel FROM code_channels WHERE user_id = $1 AND recipient = $2",
            &[&user_id, &recipient],
        )
        .await
        .map_err(|_| StoreError::Backend)?
    else {
        return Ok(None);
    };
    row.get::<_, String>("channel")
        .parse()
        .map(Some)
        .map_err(|_| StoreError::Backend)
}

/// Remember the way this person asked their codes to come, for this number,
/// in place of whatever they asked before.
pub async fn choose(
    transaction: &UnitOfWork,
    user_id: &str,
    recipient: &str,
    channel: Channel,
    now: chrono::DateTime<chrono::Utc>,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO code_channels \
                 (tenant, realm_id, user_id, recipient, channel, chosen_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4 \
             ON CONFLICT (tenant, realm_id, user_id) DO UPDATE \
             SET recipient = EXCLUDED.recipient, \
                 channel = EXCLUDED.channel, \
                 chosen_at = EXCLUDED.chosen_at",
            &[&user_id, &recipient, &channel.as_str(), &now],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}
