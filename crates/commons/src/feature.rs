//! What this build can do, and what this deployment asked it to do.
//!
//! A capability resolves on two axes: whether it was compiled in, and whether
//! the deployment wants it. It is on only if both. Asking for one that was not
//! compiled is a startup failure, never a silent no-op — an operator who
//! enabled a feature and got a binary without it should be told, not left
//! running something else.
//!
//! Nothing here has a dependency, so any layer can ask.

/// How finished a capability is, which decides whether it is on by default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lifecycle {
    /// Supported. On unless turned off.
    Stable,
    /// Complete, not guaranteed. Opt in.
    Preview,
    /// May change or vanish. Opt in.
    Experimental,
    /// Still works, on its way out. On, and says so.
    Deprecated,
}

impl Lifecycle {
    pub const fn default_enabled(self) -> bool {
        matches!(self, Self::Stable | Self::Deprecated)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Preview => "preview",
            Self::Experimental => "experimental",
            Self::Deprecated => "deprecated",
        }
    }
}

/// Where a capability can be turned off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gating {
    /// A link-time choice only.
    CompileOnly,
    /// Always compiled; a runtime switch.
    RuntimeOnly,
    /// Compiled sets the bound, runtime moves within it.
    Both,
}

impl Gating {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompileOnly => "compile-only",
            Self::RuntimeOnly => "runtime-only",
            Self::Both => "both",
        }
    }
}

/// Declare the registry.
///
/// One table, and the enum, the list and the specs all come from it. Kept this
/// way because the alternative carries an invariant a comment has to state —
/// that a hand-written list stays in the enum's order — and a test can only
/// check what that list already contains.
macro_rules! registry {
    ($($variant:ident = $slug:literal, $lifecycle:ident, $gating:ident, $doc:literal;)+) => {
        /// A capability this build may or may not have.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum Feature {
            $(#[doc = $doc] $variant,)+
        }

        impl Feature {
            /// Every capability, in registry order, complete by construction.
            pub const ALL: &'static [Feature] = &[$(Feature::$variant,)+];

            pub const fn spec(self) -> FeatureSpec {
                match self {
                    $(Self::$variant => FeatureSpec {
                        slug: $slug,
                        lifecycle: Lifecycle::$lifecycle,
                        gating: Gating::$gating,
                        doc: $doc,
                    },)+
                }
            }
        }
    };
}

/// What a capability is, independent of any deployment.
#[derive(Clone, Copy, Debug)]
pub struct FeatureSpec {
    pub slug: &'static str,
    pub lifecycle: Lifecycle,
    pub gating: Gating,
    pub doc: &'static str,
}

registry! {
    ChaCha20 = "chacha20", Preview, CompileOnly,
        "ChaCha20-Poly1305, for hardware without AES acceleration. Not FIPS.";
    PqHybrid = "pq-hybrid", Preview, CompileOnly,
        "ML-DSA signatures and ML-KEM encapsulation. Needs libcrypto 3.5 or newer.";
    FipsStrict = "fips-strict", Preview, CompileOnly,
        "Pin the validated FIPS provider; excludes the algorithms it does not cover.";
    Pkcs11 = "pkcs11", Preview, CompileOnly,
        "A key store inside a PKCS#11 token, where the private key never leaves.";
    TracingJson = "tracing-json", Stable, CompileOnly,
        "Structured logging through a tracing subscriber.";
}

impl Feature {
    pub const fn slug(self) -> &'static str {
        self.spec().slug
    }

    fn index(self) -> usize {
        self as usize
    }

    /// The capability a slug names.
    pub fn by_slug(slug: &str) -> Option<Feature> {
        Self::ALL.iter().copied().find(|f| f.slug() == slug)
    }
}

/// Why a capability ended where it did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeatureSource {
    /// Left at its lifecycle default.
    Default,
    /// Named to be turned on.
    EnabledByRequest,
    /// Named to be turned off.
    DisabledByRequest,
}

impl FeatureSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::EnabledByRequest => "requested-on",
            Self::DisabledByRequest => "requested-off",
        }
    }
}

/// Where one capability ended up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeatureStatus {
    pub feature: Feature,
    /// On for this process: wanted and compiled.
    pub enabled: bool,
    /// Whether this build contains it at all.
    pub compiled: bool,
    pub source: FeatureSource,
}

/// Why a set could not be resolved.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FeatureError {
    #[error("feature '{0}' was requested but is not compiled into this build")]
    NotCompiled(String),
    #[error("unknown feature '{0}'")]
    UnknownSlug(String),
    #[error("feature '{0}' was asked to be both on and off")]
    Contradictory(String),
}

/// The resolved set, fixed for the life of the process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeatureSet {
    statuses: Vec<FeatureStatus>,
}

impl FeatureSet {
    /// Resolve what is on.
    ///
    /// `requested` is the raw list — `+x,-y`, or a bare slug meaning on.
    /// `compiled` reports whether each was linked, which only the crate that can
    /// see every `cfg!` knows.
    ///
    /// A capability left at its default and not compiled is quietly off: nobody
    /// asked for it. One that was *asked* for and is not compiled is an error,
    /// because the alternative is a deployment running without something it
    /// requested and no way to find out.
    pub fn resolve(
        requested: &str,
        compiled: impl Fn(Feature) -> bool,
    ) -> Result<Self, FeatureError> {
        let mut wanted_on = vec![false; Feature::ALL.len()];
        let mut wanted_off = vec![false; Feature::ALL.len()];

        for token in requested
            .split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
        {
            let (on, slug) = match token.strip_prefix('-') {
                Some(rest) => (false, rest.trim()),
                None => (true, token.strip_prefix('+').unwrap_or(token).trim()),
            };

            let feature = Feature::by_slug(slug)
                .ok_or_else(|| FeatureError::UnknownSlug(slug.to_string()))?;

            // A name given twice, once each way, is a contradiction rather than
            // a last-one-wins: nobody meant both, and guessing which they meant
            // is how a capability ends up in the state they did not ask for.
            if on {
                wanted_on[feature.index()] = true;
            } else {
                wanted_off[feature.index()] = true;
            }
        }

        let mut statuses = Vec::with_capacity(Feature::ALL.len());
        for feature in Feature::ALL.iter().copied() {
            let index = feature.index();
            let compiled = compiled(feature);

            if wanted_on[index] && wanted_off[index] {
                return Err(FeatureError::Contradictory(feature.slug().to_string()));
            }
            if wanted_on[index] && !compiled {
                return Err(FeatureError::NotCompiled(feature.slug().to_string()));
            }

            let wanted = (feature.spec().lifecycle.default_enabled() || wanted_on[index])
                && !wanted_off[index];

            statuses.push(FeatureStatus {
                feature,
                enabled: wanted && compiled,
                compiled,
                source: if wanted_on[index] {
                    FeatureSource::EnabledByRequest
                } else if wanted_off[index] {
                    FeatureSource::DisabledByRequest
                } else {
                    FeatureSource::Default
                },
            });
        }

        Ok(Self { statuses })
    }

    pub fn is_enabled(&self, feature: Feature) -> bool {
        self.statuses[feature.index()].enabled
    }

    pub fn status(&self, feature: Feature) -> FeatureStatus {
        self.statuses[feature.index()]
    }

    /// Every status, in registry order.
    pub fn statuses(&self) -> &[FeatureStatus] {
        &self.statuses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;

    /// Everything compiled, which is the baseline the other tests vary from.
    fn all_compiled(_: Feature) -> bool {
        true
    }

    fn resolve(requested: &str) -> Result<FeatureSet, FeatureError> {
        FeatureSet::resolve(requested, all_compiled)
    }

    /// No two capabilities answer to the same name.
    #[test]
    fn every_feature_is_its_own_slug() {
        let mut seen = HashSet::new();

        for feature in Feature::ALL {
            assert!(seen.insert(feature.slug()), "{feature:?} reuses a slug");
            assert!(!feature.slug().is_empty(), "{feature:?}");
            assert!(!feature.spec().doc.is_empty(), "{feature:?}");
        }
    }

    /// A slug names the capability it belongs to, and nothing names one that
    /// does not exist.
    #[test]
    fn a_slug_finds_its_own_feature() {
        for feature in Feature::ALL.iter().copied() {
            assert_eq!(Feature::by_slug(feature.slug()), Some(feature));
        }

        for unknown in ["", "chacha", "CHACHA20", "pkcs#11", "metrics"] {
            assert_eq!(Feature::by_slug(unknown), None, "{unknown:?}");
        }
    }

    /// What each lifecycle means, tested on the lifecycle rather than through
    /// a capability that happens to have it.
    ///
    /// No registered feature is deprecated or experimental today, so nothing
    /// else reaches those two — and the day one is, its default has to be the
    /// one that was decided here, not the one nobody checked.
    #[test]
    fn a_lifecycle_decides_on_its_own() {
        assert!(Lifecycle::Stable.default_enabled());
        assert!(
            Lifecycle::Deprecated.default_enabled(),
            "still works, so still on"
        );
        assert!(!Lifecycle::Preview.default_enabled());
        assert!(!Lifecycle::Experimental.default_enabled());

        let mut named = HashSet::new();
        for lifecycle in [
            Lifecycle::Stable,
            Lifecycle::Preview,
            Lifecycle::Experimental,
            Lifecycle::Deprecated,
        ] {
            assert!(
                named.insert(lifecycle.as_str()),
                "{lifecycle:?} reuses a name"
            );
        }
    }

    /// Likewise for the gates.
    #[test]
    fn each_gate_has_its_own_name() {
        let mut named = HashSet::new();

        for gating in [Gating::CompileOnly, Gating::RuntimeOnly, Gating::Both] {
            assert!(named.insert(gating.as_str()), "{gating:?} reuses a name");
        }
    }

    /// The lifecycle decides the default, and nothing else does.
    #[test]
    fn the_lifecycle_decides_the_default() {
        let set = resolve("").unwrap();

        for feature in Feature::ALL.iter().copied() {
            assert_eq!(
                set.is_enabled(feature),
                feature.spec().lifecycle.default_enabled(),
                "{feature:?}"
            );
            assert_eq!(set.status(feature).source, FeatureSource::Default);
        }
    }

    /// A request turns one on or off, whichever way it is written.
    #[test]
    fn a_request_moves_one_capability() {
        for written in ["pkcs11", "+pkcs11", " pkcs11 ", "tracing-json,+pkcs11"] {
            let set = resolve(written).unwrap();

            assert!(set.is_enabled(Feature::Pkcs11), "{written:?}");
            assert_eq!(
                set.status(Feature::Pkcs11).source,
                FeatureSource::EnabledByRequest
            );
        }

        let set = resolve("-tracing-json").unwrap();
        assert!(!set.is_enabled(Feature::TracingJson));
        assert_eq!(
            set.status(Feature::TracingJson).source,
            FeatureSource::DisabledByRequest
        );

        // And the others are untouched by a request about one.
        assert!(!set.is_enabled(Feature::Pkcs11));
    }

    /// Asking for something this build does not contain is a failure.
    ///
    /// The whole point of the registry. An operator who enabled a capability and
    /// got a binary without it must be told at startup — the alternative is a
    /// deployment running without something it asked for, and no way to find
    /// out short of noticing the absence.
    #[test]
    fn asking_for_what_is_not_compiled_fails() {
        let none_compiled = |_: Feature| false;

        assert_eq!(
            FeatureSet::resolve("pkcs11", none_compiled).unwrap_err(),
            FeatureError::NotCompiled("pkcs11".to_string())
        );

        // Only an explicit request. A capability left at a default it cannot
        // have is quietly off, because nobody asked.
        let set = FeatureSet::resolve("", none_compiled).unwrap();
        assert!(!set.is_enabled(Feature::TracingJson));
        assert!(!set.status(Feature::TracingJson).compiled);
        assert_eq!(
            set.status(Feature::TracingJson).source,
            FeatureSource::Default
        );
    }

    /// Turning off something absent is not an error: the deployment and the
    /// build already agree.
    #[test]
    fn turning_off_what_is_absent_is_not_a_failure() {
        let set = FeatureSet::resolve("-pkcs11", |_| false).unwrap();

        assert!(!set.is_enabled(Feature::Pkcs11));
    }

    /// A name nobody registered is refused rather than ignored.
    #[test]
    fn an_unknown_name_is_refused() {
        for written in ["metrics", "+ciba", "-sms", "chacha"] {
            assert!(
                matches!(resolve(written), Err(FeatureError::UnknownSlug(_))),
                "{written:?} was ignored"
            );
        }
    }

    /// Both at once is a contradiction, not a last-one-wins.
    ///
    /// Nobody meant both, and picking one leaves the capability in the state
    /// they did not ask for — with the request that says so still in the file.
    #[test]
    fn asking_both_ways_is_refused() {
        for written in [
            "pkcs11,-pkcs11",
            "-pkcs11,+pkcs11",
            "+pkcs11,pkcs11,-pkcs11",
        ] {
            assert_eq!(
                resolve(written).unwrap_err(),
                FeatureError::Contradictory("pkcs11".to_string()),
                "{written:?}"
            );
        }
    }

    /// Blank and separators alone mean nothing was asked.
    #[test]
    fn an_empty_request_asks_for_nothing() {
        for written in ["", "   ", ",", ", ,", "\t,\n"] {
            let set = resolve(written).unwrap();

            assert_eq!(set, resolve("").unwrap(), "{written:?}");
        }
    }

    /// On means wanted *and* compiled, never one of the two.
    #[test]
    fn on_means_both() {
        let only_tracing = |feature: Feature| feature == Feature::TracingJson;

        let set = FeatureSet::resolve("", only_tracing).unwrap();
        assert!(set.is_enabled(Feature::TracingJson), "wanted and compiled");
        assert!(
            !set.is_enabled(Feature::ChaCha20),
            "compiled but not wanted"
        );

        let set = FeatureSet::resolve("-tracing-json", only_tracing).unwrap();
        assert!(
            !set.is_enabled(Feature::TracingJson),
            "compiled but turned off"
        );
    }

    /// Every capability has a status, in registry order.
    #[test]
    fn the_set_reports_every_capability() {
        let set = resolve("").unwrap();
        let reported: Vec<Feature> = set.statuses().iter().map(|s| s.feature).collect();

        assert_eq!(reported, Feature::ALL.to_vec());
    }
}
