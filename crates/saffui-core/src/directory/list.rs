use super::Person;
use crate::app::App;
use crate::clients::store::ListWindow;
use crate::error::Failure;
use crate::tenancy::RealmScope;

/// Lists the people of a realm, and counts them when asked. The page and its
/// count are read in one snapshot: a person created between the two would
/// otherwise give a total that does not match the page.
///
/// # Errors
///
/// Returns the storage failure.
pub async fn list_persons(
    app: &App,
    scope: RealmScope,
    window: ListWindow,
    counted: bool,
) -> Result<(Vec<Person>, Option<u64>), Failure> {
    let mut work = app.storage.begin_snapshot(scope).await?;
    let persons = work.list_persons(window).await?;
    let total = if counted {
        Some(work.count_persons().await?)
    } else {
        None
    };
    Ok((persons, total))
}
