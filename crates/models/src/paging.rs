//! What a collection endpoint accepts, and the window it resolves to.

use serde::Deserialize;

/// The page size a caller gets when it does not ask.
pub const DEFAULT_MAX: i64 = 100;

/// The largest page the server will assemble.
///
/// A caller asking for more is clamped, not refused: a cap that errors teaches
/// clients to paginate badly around it, and the point is to bound the work
/// rather than to punish the request.
pub const MAX_MAX: i64 = 500;

/// How deep an offset scan is allowed to go.
///
/// Past this the server spends more discarding rows than the page is worth, and
/// a caller this deep is enumerating rather than browsing. Unlike `max` this one
/// fails the request: serving page 1 to someone who asked for page 4000 would be
/// worse than saying no.
pub const MAX_FIRST: i64 = 100_000;

/// A window a caller asked for that cannot be served.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PagingError {
    #[error("first must not be negative")]
    NegativeFirst,
    #[error("first must not exceed {MAX_FIRST}")]
    FirstTooDeep,
    #[error("max must be positive")]
    NonPositiveMax,
}

/// The rows to read: where to start, how many, and whether the ask was reduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub first: i64,
    pub max: i64,
    /// Whether `max` was cut down to [`MAX_MAX`], so the caller can be told
    /// rather than left to infer it from a page shorter than it asked for.
    pub clamped: bool,
}

/// What a collection endpoint accepts.
///
/// `first`/`max` is the documented spelling, chosen because it is Keycloak's:
/// migrating off Keycloak is a product goal, and an operator porting a script
/// should not have to rename parameters. `page_index`/`page_size` is the house
/// spelling and stays supported — one resolution against one migration paper cut.
///
/// Every field is `Option` so a malformed value reaches the endpoint's error
/// handling rather than being rejected by the extractor with a shape the client
/// cannot interpret.
#[derive(Debug, Default, Deserialize)]
pub struct PagingParams {
    /// Offset of the first row. Refused past [`MAX_FIRST`].
    pub first: Option<i64>,
    /// Page size. Clamped to [`MAX_MAX`] rather than refused.
    pub max: Option<i64>,
    /// Whether to compute the total. Off by default: `COUNT(*)` under most
    /// predicates is a sequential scan, and one per keystroke of a search box is
    /// how an admin console becomes unusable.
    pub count: Option<bool>,

    /// House spelling, kept for the callers that already use it.
    pub page_index: Option<u64>,
    /// House spelling, kept for the callers that already use it.
    pub page_size: Option<u64>,
}

impl PagingParams {
    /// The window, resolving the two spellings and applying the ceilings.
    ///
    /// `first`/`max` wins when both spellings are given — it is the documented
    /// form, and silently averaging or erroring on a caller that sent both would
    /// be worse than naming a winner.
    ///
    /// Absent means the first page, never everything. That is the point of this
    /// type: treating missing parameters as "return the realm" is a denial of
    /// service the server performs on itself.
    ///
    /// The bounds are applied here rather than left to the layer that reads the
    /// rows, because a caller that forgets to ask for them is exactly the caller
    /// that needs them.
    pub fn window(&self) -> Result<Window, PagingError> {
        let (max, clamped) = self.resolve_max()?;
        Ok(Window {
            first: self.resolve_first()?,
            max,
            clamped,
        })
    }

    pub fn wants_count(&self) -> bool {
        self.count.unwrap_or(false)
    }

    fn resolve_max(&self) -> Result<(i64, bool), PagingError> {
        // Widened before anything is compared, so a `page_size` past `i64::MAX`
        // is an oversized page rather than a negative one.
        let requested: i128 = match (self.max, self.page_size) {
            (Some(max), _) => max.into(),
            (None, Some(size)) => size.into(),
            (None, None) => return Ok((DEFAULT_MAX, false)),
        };

        if requested <= 0 {
            return Err(PagingError::NonPositiveMax);
        }
        if requested > i128::from(MAX_MAX) {
            return Ok((MAX_MAX, true));
        }
        Ok((requested as i64, false))
    }

    fn resolve_first(&self) -> Result<i64, PagingError> {
        let requested: i128 = match (self.first, self.page_index, self.page_size) {
            (Some(first), _, _) => first.into(),
            // Multiplied wide: a page index and size that overflow are a scan
            // deeper than anything served, not an offset that wrapped into a
            // small number the reader would honour.
            (None, Some(index), Some(size)) => match i128::from(index).checked_mul(size.into()) {
                Some(product) => product,
                None => return Err(PagingError::FirstTooDeep),
            },
            _ => return Ok(0),
        };

        if requested < 0 {
            return Err(PagingError::NegativeFirst);
        }
        if requested > i128::from(MAX_FIRST) {
            return Err(PagingError::FirstTooDeep);
        }
        Ok(requested as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> PagingParams {
        PagingParams::default()
    }

    /// No query string means the first page, never the whole realm.
    #[test]
    fn absent_parameters_are_a_page_not_everything() {
        let window = params().window().unwrap();
        assert_eq!(window.first, 0);
        assert_eq!(window.max, DEFAULT_MAX);
        assert!(!window.clamped);
        assert!(!params().wants_count());
    }

    /// Both spellings resolve, and the documented one wins when both appear.
    #[test]
    fn the_two_spellings_resolve_and_the_documented_one_wins() {
        let house = PagingParams {
            page_index: Some(3),
            page_size: Some(20),
            ..params()
        }
        .window()
        .unwrap();
        assert_eq!(
            (house.first, house.max),
            (60, 20),
            "page 3 of 20 starts at 60"
        );

        let keycloak = PagingParams {
            first: Some(60),
            max: Some(20),
            ..params()
        }
        .window()
        .unwrap();
        assert_eq!((keycloak.first, keycloak.max), (60, 20));

        let both = PagingParams {
            first: Some(0),
            max: Some(5),
            page_index: Some(9),
            page_size: Some(50),
            ..params()
        }
        .window()
        .unwrap();
        assert_eq!((both.first, both.max), (0, 5), "first/max is documented");
    }

    /// A page index without a size resolves to the first page rather than to
    /// index rows in, which is what treating the missing size as 1 would do.
    #[test]
    fn a_page_index_without_a_size_is_the_first_page() {
        let window = PagingParams {
            page_index: Some(7),
            ..params()
        }
        .window()
        .unwrap();
        assert_eq!(window.first, 0);
    }

    /// An oversized page is served short and said to be short.
    #[test]
    fn an_oversized_page_is_clamped_and_reported() {
        let window = PagingParams {
            max: Some(MAX_MAX + 1),
            ..params()
        }
        .window()
        .unwrap();
        assert_eq!(window.max, MAX_MAX);
        assert!(window.clamped);

        let exact = PagingParams {
            max: Some(MAX_MAX),
            ..params()
        }
        .window()
        .unwrap();
        assert_eq!(exact.max, MAX_MAX);
        assert!(!exact.clamped, "asking for the ceiling is not a reduction");
    }

    /// A page of nothing is a caller's arithmetic, not an empty result.
    #[test]
    fn a_non_positive_page_size_is_refused() {
        for max in [0, -1, i64::MIN] {
            assert_eq!(
                PagingParams {
                    max: Some(max),
                    ..params()
                }
                .window(),
                Err(PagingError::NonPositiveMax),
                "max {max} should be refused"
            );
        }
    }

    /// An offset before the beginning has no meaning, and reading it as zero
    /// would hide the arithmetic that produced it.
    #[test]
    fn a_negative_offset_is_refused() {
        assert_eq!(
            PagingParams {
                first: Some(-1),
                ..params()
            }
            .window(),
            Err(PagingError::NegativeFirst)
        );
    }

    /// Depth is refused, not clamped: page 1 in answer to page 4000 is a lie.
    #[test]
    fn an_offset_past_the_ceiling_is_refused() {
        assert_eq!(
            PagingParams {
                first: Some(MAX_FIRST + 1),
                ..params()
            }
            .window(),
            Err(PagingError::FirstTooDeep)
        );
        assert_eq!(
            PagingParams {
                first: Some(MAX_FIRST),
                ..params()
            }
            .window()
            .unwrap()
            .first,
            MAX_FIRST,
            "the ceiling itself is served"
        );
    }

    /// The house spelling multiplies two numbers the caller chose. Neither the
    /// product nor either operand may come back through the other side as a
    /// small, plausible offset.
    #[test]
    fn a_page_index_that_overflows_is_too_deep_not_wrapped() {
        assert_eq!(
            PagingParams {
                page_index: Some(u64::MAX),
                page_size: Some(u64::MAX),
                ..params()
            }
            .window(),
            Err(PagingError::FirstTooDeep)
        );

        assert_eq!(
            PagingParams {
                page_index: Some(1 << 40),
                page_size: Some(1 << 40),
                ..params()
            }
            .window(),
            Err(PagingError::FirstTooDeep),
            "a product that fits in i128 but not in the ceiling is still refused"
        );
    }

    /// A page size past `i64::MAX` is an oversized page, not a negative one.
    #[test]
    fn a_page_size_past_the_signed_range_is_clamped() {
        let window = PagingParams {
            page_size: Some(u64::MAX),
            ..params()
        }
        .window()
        .unwrap();
        assert_eq!(window.max, MAX_MAX);
        assert!(window.clamped);
    }

    /// A count is never implicit.
    #[test]
    fn counting_is_opt_in() {
        assert!(!params().wants_count());
        assert!(
            PagingParams {
                count: Some(true),
                ..params()
            }
            .wants_count()
        );
    }
}
