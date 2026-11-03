//! The mark a browser keeps once a person signed in from it.
//!
//! It proves, under a key the database does not hold, that this browser
//! knew the password of this name. It opens nothing: a session is still a
//! password away. It lets this browser be counted apart from the guesses
//! made on the name from elsewhere, so that they cannot lock the person out.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::app::App;
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::tenancy::RealmScope;

/// How long a browser stays known after its last sign-in.
pub const DEVICE_MARK_LIFETIME: Duration = Duration::days(90);

/// The kind of what is digested for a mark, apart from every counter of the brake.
const MARK_KIND: u8 = 8;

/// How many marks one cookie carries: one per person who signs in on a
/// shared browser, the latest first.
pub const MOST_MARKS: usize = 4;

/// How many browsers the realm keeps for one person: the ones that expire
/// last. A mark whose browser is no longer kept is believed no more.
pub const MOST_BROWSERS_PER_PERSON: u32 = 10;

#[derive(Clone, PartialEq, Eq)]
pub struct DeviceMark {
    pub device: Uuid,
    /// Whole seconds since the epoch: what the browser was told.
    pub expires_at: i64,
    mac: Vec<u8>,
}

// Written by hand: the MAC is what the cookie carries, and what a thief would.
impl fmt::Debug for DeviceMark {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceMark")
            .field("device", &self.device)
            .field("expires_at", &self.expires_at)
            .field("mac", &"..")
            .finish()
    }
}

impl DeviceMark {
    /// The value of the cookie.
    #[must_use]
    pub fn write(&self) -> String {
        format!(
            "{}.{}.{}",
            self.expires_at,
            self.device,
            URL_SAFE_NO_PAD.encode(&self.mac)
        )
    }

    /// Reads the value of a cookie. Anything else than an instant, an
    /// identifier and 32 bytes of MAC is no mark.
    #[must_use]
    pub fn parse(cookie: &str) -> Option<Self> {
        let mut parts = cookie.split('.');
        let (expires_at, device, mac) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() || !expires_at.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let mac = URL_SAFE_NO_PAD.decode(mac).ok()?;
        (mac.len() == 32).then_some(())?;
        Some(Self {
            device: Uuid::parse_str(device).ok()?,
            expires_at: expires_at.parse().ok()?,
            mac,
        })
    }
}

/// The MAC of a mark: the name typed, the device and the expiry, each
/// closed, under the key of the realm for typed names.
fn compute_mark_mac(
    app: &App,
    scope: RealmScope,
    typed: &str,
    device: Uuid,
    expires_at: i64,
) -> Result<Vec<u8>, Failure> {
    let mut written = vec![MARK_KIND];
    written.extend_from_slice(typed.as_bytes());
    written.push(0);
    written.extend_from_slice(device.as_bytes());
    written.extend_from_slice(&expires_at.to_be_bytes());
    app.sealer
        .digest_typed_name(scope.tenant().as_uuid(), scope.realm().as_uuid(), &written)
        .map_err(|_| Failure::new(ErrorCode::CryptoUnavailable))
}

/// Reads the marks of a cookie, the latest first. What is not a mark is
/// left out; past the first few, nothing is read.
#[must_use]
pub fn read_device_marks(cookie: &str) -> Vec<DeviceMark> {
    cookie
        .split('~')
        .take(MOST_MARKS)
        .filter_map(DeviceMark::parse)
        .collect()
}

/// The value of a cookie that carries these marks.
#[must_use]
pub fn write_device_marks(marks: &[DeviceMark]) -> String {
    marks
        .iter()
        .map(DeviceMark::write)
        .collect::<Vec<_>>()
        .join("~")
}

/// What a browser keeps after a sign-in: the new mark first, then the marks
/// it brought that are of other browsers and still live, a few at most.
#[must_use]
pub fn keep_device_marks(
    new: DeviceMark,
    presented: &[DeviceMark],
    now: OffsetDateTime,
) -> Vec<DeviceMark> {
    let replaced = new.device;
    let others = presented
        .iter()
        .filter(move |mark| mark.device != replaced && mark.expires_at > now.unix_timestamp())
        .take(MOST_MARKS - 1)
        .cloned();
    std::iter::once(new).chain(others).collect()
}

/// Makes the mark of a browser that just signed in with this name. A
/// browser the realm knew keeps its device: its count stays its own.
///
/// # Errors
///
/// Returns [`ErrorCode::RandomUnavailable`] or [`ErrorCode::CryptoUnavailable`].
pub(crate) fn issue_device_mark(
    app: &App,
    scope: RealmScope,
    typed: &str,
    known: Option<Uuid>,
) -> Result<DeviceMark, Failure> {
    let device = match known {
        Some(device) => device,
        None => mint_id(app)?,
    };
    let expires_at = (app.now() + DEVICE_MARK_LIFETIME).unix_timestamp();
    let mac = compute_mark_mac(app, scope, typed, device, expires_at)?;
    Ok(DeviceMark {
        device,
        expires_at,
        mac,
    })
}

/// Tells whether a mark was made for this name, in this realm, and has not
/// expired at `now`. Compared in constant time.
///
/// # Errors
///
/// Returns [`ErrorCode::CryptoUnavailable`].
pub(crate) fn recognize_device_mark(
    app: &App,
    scope: RealmScope,
    mark: &DeviceMark,
    typed: &str,
    now: OffsetDateTime,
) -> Result<bool, Failure> {
    let expected = compute_mark_mac(app, scope, typed, mark.device, mark.expires_at)?;
    let proven = app.digester.equal_in_constant_time(&mark.mac, &expected);
    Ok(proven && mark.expires_at > now.unix_timestamp())
}

#[cfg(test)]
mod tests {
    use time::Duration;
    use uuid::Uuid;

    use super::{
        DeviceMark, issue_device_mark, keep_device_marks, read_device_marks, recognize_device_mark,
        write_device_marks,
    };
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::create_realm;
    use crate::testkit::memory::MemoryStorage;

    #[test]
    fn a_mark_is_read_back_from_the_cookie_it_wrote() {
        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let mark = issue_device_mark(&app, scope, "ada", None).expect("a mark");

        assert_eq!(DeviceMark::parse(&mark.write()), Some(mark));
        for cookie in [
            "",
            "1.2",
            "abc.0198c2f4-7a3e-7c11-9b6e-2f1d3c4b5a69.AAAA",
            "1.not-a-uuid.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "-1.0198c2f4-7a3e-7c11-9b6e-2f1d3c4b5a69.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "1.0198c2f4-7a3e-7c11-9b6e-2f1d3c4b5a69.AAAA.extra",
        ] {
            assert_eq!(DeviceMark::parse(cookie), None, "{cookie:?}");
        }
    }

    #[test]
    fn a_mark_is_known_for_its_name_and_realm_until_it_expires_and_not_once_altered() {
        let (app, _storage, clock) = MemoryStorage::wire_with_clock();
        let scope = complete(create_realm(&app, "acme"));
        let other = complete(create_realm(&app, "globex"));
        let mark = issue_device_mark(&app, scope, "ada", None).expect("a mark");
        let known = |mark: &DeviceMark, scope, typed| {
            recognize_device_mark(&app, scope, mark, typed, app.now()).expect("a verdict")
        };

        assert!(known(&mark, scope, "ada"));
        assert!(!known(&mark, scope, "bob"), "made for another name");
        assert!(!known(&mark, other, "ada"), "made in another realm");
        let moved = DeviceMark {
            device: Uuid::from_u128(7),
            ..mark.clone()
        };
        assert!(
            !known(&moved, scope, "ada"),
            "another device under the same MAC"
        );
        let stretched = DeviceMark {
            expires_at: mark.expires_at + 86_400,
            ..mark.clone()
        };
        assert!(
            !known(&stretched, scope, "ada"),
            "a later expiry under the same MAC"
        );
        clock.advance(std::time::Duration::from_secs(
            u64::try_from((Duration::days(90) + Duration::seconds(1)).whole_seconds())
                .expect("a duration"),
        ));
        assert!(!known(&mark, scope, "ada"), "expired");
    }

    #[test]
    fn a_cookie_carries_a_few_marks_the_latest_first_and_drops_what_is_spent() {
        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let marks: Vec<DeviceMark> = ["ada", "bob", "eve", "joe", "max"]
            .into_iter()
            .map(|name| issue_device_mark(&app, scope, name, None).expect("a mark"))
            .collect();

        let cookie = write_device_marks(&marks);
        assert_eq!(
            read_device_marks(&cookie),
            marks[..4],
            "four are read, no more"
        );
        assert_eq!(
            read_device_marks(&format!("junk~{}", marks[0].write())),
            [marks[0].clone()]
        );

        let again = issue_device_mark(&app, scope, "bob", Some(marks[1].device)).expect("a mark");
        assert_eq!(
            again.device, marks[1].device,
            "a known browser keeps its device"
        );
        let expired = DeviceMark {
            expires_at: app.now().unix_timestamp(),
            ..marks[2].clone()
        };
        let presented = [
            marks[0].clone(),
            marks[1].clone(),
            expired,
            marks[3].clone(),
        ];
        assert_eq!(
            keep_device_marks(again.clone(), &presented, app.now()),
            [again, marks[0].clone(), marks[3].clone()],
            "the new mark first, the one it replaces and the spent one gone"
        );
    }
}
