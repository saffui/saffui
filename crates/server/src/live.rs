use std::time::Duration;

use deadpool_postgres::tokio_postgres::{AsyncMessage, NoTls};

/// One committed happening, as the notify spoke it: the summary and never
/// the payload, which stays in the store for whoever is entitled to ask.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Told {
    pub tenant: String,
    pub realm: String,
    pub event_id: i64,
    pub kind: String,
    pub user_id: String,
    pub occurred_at: String,
}

/// Hold LISTEN open on its own connection and hand every committed emission
/// to in-process subscribers. A lagging watcher may miss broadcast frames;
/// the admin stream repairs that gap from the outbox on reconnect.
pub fn listen(
    config: deadpool_postgres::tokio_postgres::Config,
) -> tokio::sync::broadcast::Sender<Told> {
    let (feed, _) = tokio::sync::broadcast::channel(256);
    let out = feed.clone();
    tokio::spawn(async move {
        loop {
            if let Err(why) = pump(&config, &out).await {
                tracing::warn!(%why, "the live feed lost its ear; listening again shortly");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
    feed
}

async fn pump(
    config: &deadpool_postgres::tokio_postgres::Config,
    out: &tokio::sync::broadcast::Sender<Told>,
) -> Result<(), deadpool_postgres::tokio_postgres::Error> {
    let (client, mut held) = config.connect(NoTls).await?;
    let feed = out.clone();
    let speaking = tokio::spawn(async move {
        loop {
            match std::future::poll_fn(|cx| held.poll_message(cx)).await {
                Some(Ok(AsyncMessage::Notification(spoken))) => {
                    if spoken.channel() == store::providers::outbox::CHANNEL
                        && let Ok(told) = serde_json::from_str::<Told>(spoken.payload())
                    {
                        // Nobody watching is not an error: the feed simply
                        // has no subscribers right now.
                        drop(feed.send(told));
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => return,
            }
        }
    });
    client
        .batch_execute(&format!("LISTEN {}", store::providers::outbox::CHANNEL))
        .await?;
    // The client half must outlive the pump: dropping it hangs up the very
    // connection the messages arrive on.
    drop(speaking.await);
    drop(client);
    Ok(())
}
