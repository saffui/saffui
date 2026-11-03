//! The second step of signing in: a code of the person's authenticator
//! application.

use std::net::IpAddr;

use serde_json::json;
use uuid::Uuid;

use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::directory::Person;
use crate::error::{ErrorCode, Failure};
use crate::login::device::{DeviceMark, find_known_browser, prove_device_marks};
use crate::login::store::TotpUse;
use crate::login::throttle::Brake;
use crate::ports::crypto::{SealPlace, WrappedDataKey};
use crate::ports::storage::UnitOfWork;
use crate::tenancy::RealmScope;

/// What the secret of an authenticator is sealed for.
pub(crate) const TOTP_SECRET_PURPOSE: &str = "totp-secret";

/// How many codes in a row a person may get wrong, from whatever addresses:
/// past it, their codes are suspended until an administrator resumes them or
/// a key of theirs proves itself. Ten guesses at the three codes each one is
/// compared to leave about three chances in a hundred thousand. The person
/// bounds the codes here, and the name by its lock; the address bounds the
/// hashes, and a code hashes nothing.
pub(crate) const MAX_CODE_FAILURES: u32 = 10;

/// Where the secret of an authenticator is sealed: under the data key of the
/// realm, for the row of its person.
pub(crate) async fn read_secret_place(
    work: &mut dyn UnitOfWork,
    person: Uuid,
) -> Result<(WrappedDataKey, SealPlace), Failure> {
    let scope = work.scope();
    let data_key = work.read_data_key().await?.ok_or_else(|| {
        Failure::with_detail(ErrorCode::CryptoUnavailable, "the realm has no data key")
    })?;
    let place = SealPlace {
        tenant: scope.tenant().as_uuid(),
        realm: scope.realm().as_uuid(),
        purpose: TOTP_SECRET_PURPOSE,
        row: person,
    };
    Ok((data_key, place))
}

/// Tells whether `code` is a code of the sealed secret of `person` that was
/// never accepted, and accepts it for `used_for`, as long as that secret is
/// still the one kept. Nothing is counted here.
pub(crate) async fn accept_code(
    app: &App,
    work: &mut dyn UnitOfWork,
    person: Uuid,
    sealed_secret: &[u8],
    code: &str,
    used_for: TotpUse,
) -> Result<bool, Failure> {
    let unavailable = |detail: &str| Failure::with_detail(ErrorCode::CryptoUnavailable, detail);
    let (data_key, place) = read_secret_place(work, person).await?;
    let secret = app
        .sealer
        .open(&data_key, &place, sealed_secret)
        .map_err(|_| unavailable("an authenticator secret does not open where it is stored"))?;
    let now = app.now();
    let Ok(seconds) = u64::try_from(now.unix_timestamp()) else {
        return Ok(false);
    };
    let step = app
        .one_time_codes
        .find_totp_step(&secret, code.trim(), seconds)
        .map_err(|_| unavailable("a one-time code cannot be computed"))?;
    let Some(step) = step.and_then(|step| i64::try_from(step).ok()) else {
        return Ok(false);
    };
    // One operation: a code that verifies but was accepted before, by this
    // request or by one that ran beside it, is refused, and so is a code of a
    // secret replaced since it was read.
    Ok(work
        .accept_totp_step(person, sealed_secret, step, used_for, now)
        .await?)
}

/// Proves that a person holds their authenticator application, and gives
/// back the brake the code was counted under, for the flow to clear.
///
/// The code is counted under the name, with the guesses of the password: a
/// person who knows the password gets no fresh allowance for the code. A
/// browser the realm keeps for this person answers for its own failures, as
/// it does for the password. Nothing is hashed here: the attempt is not
/// counted against its address. A wrong code, a code already used and a
/// locked name are one refusal, and so are codes suspended: ten wrong in a
/// row, counted under a person who has an application whatever their
/// address, and the right code too is refused until an administrator
/// resumes them or a key of the person proves itself. A locked name and
/// suspended codes are refused before the secret is opened.
///
/// # Errors
///
/// Returns [`ErrorCode::CodeRejected`] for every refusal above, or the
/// storage failure.
pub(crate) async fn verify_code(
    app: &App,
    scope: RealmScope,
    person: &Person,
    code: &str,
    caller: Option<IpAddr>,
    known_browsers: &[DeviceMark],
) -> Result<Brake, Failure> {
    let rejected = || Failure::new(ErrorCode::CodeRejected);
    // The name of a person is written as the brake counts what is typed.
    let typed = person.username.as_str();
    let mut brake = Brake::of(app, scope, typed, caller)?;
    let now = app.now();
    let proven = prove_device_marks(app, scope, known_browsers, typed, now)?;

    let mut work = app.storage.begin(scope).await?;
    if let Some(device) = find_known_browser(work.as_mut(), &proven, Some(person), now).await? {
        brake.count_browser_apart(app, scope, typed, device)?;
    }
    if brake.is_name_locked(work.as_mut(), now).await? {
        work.commit().await?;
        return Err(rejected());
    }
    let authenticator = work
        .read_totp(person.id)
        .await?
        .filter(|known| known.confirmed_at.is_some());
    let (accepted, attempts) = match &authenticator {
        // Counted before it is judged, and only for a person who has codes:
        // attempts that run beside each other wait on one row, and none past
        // the bound is judged.
        Some(known) => {
            let attempts = work.count_code_attempt(person.id, now).await?;
            let sign_in = TotpUse::SignIn;
            let accepted = attempts <= MAX_CODE_FAILURES
                && accept_code(
                    app,
                    work.as_mut(),
                    person.id,
                    &known.sealed_secret,
                    code,
                    sign_in,
                )
                .await?;
            (accepted, Some(attempts))
        }
        None => (false, None),
    };
    if accepted {
        work.clear_code_attempts(person.id).await?;
    } else {
        brake.record_failure(work.as_mut(), now).await?;
    }
    // Last, after the counters, in the order the opening of a session takes
    // them: the head of the chain stays locked from the event to the commit.
    if !accepted && attempts == Some(MAX_CODE_FAILURES) {
        let suspended = json!({ "person_id": person.id.to_string() });
        record_event(app, work.as_mut(), EventKind::CodesSuspended, suspended).await?;
    }
    work.commit().await?;
    if accepted { Ok(brake) } else { Err(rejected()) }
}
