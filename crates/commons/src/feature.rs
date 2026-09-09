/// How finished a capability is. It promises support and a migration path,
/// and it decides nothing about whether the capability is on: `Standing` does
/// that, because the two questions part company the moment a capability that
/// already shipped gains a switch.
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
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Preview => "preview",
            Self::Experimental => "experimental",
            Self::Deprecated => "deprecated",
        }
    }
}

/// How far down a capability can be switched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    /// The process decides, once, at boot. A realm cannot move it, because
    /// what it changes is not a realm's to change: what was linked, what the
    /// node exports, which provider the crypto goes through.
    Process,
    /// The process sets the ceiling and a realm moves within it. A realm may
    /// close a capability the process carries; it may never open one the
    /// process does not, or a deployment could not say what it is running.
    Realm,
}

impl Reach {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Realm => "realm",
        }
    }
}

/// Whether a deployment that says nothing runs it.
///
/// Told apart from the lifecycle on purpose. How finished a capability is and
/// whether it is on are two questions, and deriving the second from the first
/// makes declaring an existing capability a silent removal: everything this
/// build already runs ungated has to stay on the day it gains a switch,
/// whatever its maturity. A capability born gated says `Off` and is opted
/// into; one being retrofitted says `On` and nothing moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    On,
    Off,
}

impl Standing {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
        }
    }
}

/// What closing a capability does to the people behind it.
///
/// The ceiling says a realm cannot reach above the process. It says nothing
/// about which way a switch points, and the two are not the same question. A
/// capability whose absence is simply one surface fewer is safe to close on a
/// hunch. One whose absence takes away a defence that was in force is not,
/// and an administrator closing it to harden a realm would be doing the
/// opposite. The registry says which, so the console can say it too.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closing {
    /// One surface fewer, and nothing that was protecting anybody is gone.
    Narrows,
    /// A protection that was in force goes with it.
    Weakens,
}

impl Closing {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Narrows => "narrows",
            Self::Weakens => "weakens",
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
    ($($variant:ident = $slug:literal, $lifecycle:ident, $gating:ident, $reach:ident, $closing:ident, $standing:ident, $doc:literal;)+) => {
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
                        reach: Reach::$reach,
                        closing: Closing::$closing,
                        standing: Standing::$standing,
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
    pub reach: Reach,
    /// What goes away with it, which is not the same question as who may
    /// turn it off.
    pub closing: Closing,
    /// Whether a deployment that says nothing runs it.
    pub standing: Standing,
    pub doc: &'static str,
}

registry! {
    ChaCha20 = "chacha20", Preview, CompileOnly, Process, Narrows, Off,
        "ChaCha20-Poly1305, for hardware without AES acceleration. Not FIPS.";
    PqHybrid = "pq-hybrid", Preview, CompileOnly, Process, Weakens, Off,
        "ML-DSA signatures and ML-KEM encapsulation. Needs libcrypto 3.5 or newer.";
    FipsStrict = "fips-strict", Preview, CompileOnly, Process, Weakens, Off,
        "Pin the validated FIPS provider; excludes the algorithms it does not cover.";
    Pkcs11 = "pkcs11", Preview, CompileOnly, Process, Weakens, Off,
        "A key store inside a PKCS#11 token, where the private key never leaves.";
    TracingJson = "tracing-json", Stable, CompileOnly, Process, Narrows, On,
        "Structured logging through a tracing subscriber.";
    Metrics = "metrics", Stable, Both, Process, Narrows, On,
        "Request metrics on the operations port, in the Prometheus text form.";
    Otel = "otel", Stable, Both, Process, Narrows, On,
        "Span export over OTLP. Dials nothing until a collector is named.";
    TokenExchange = "token-exchange", Stable, RuntimeOnly, Realm, Narrows, On,
        "Trade a token for another audience, or for a subject being acted for.";
    Scim = "scim", Stable, RuntimeOnly, Realm, Narrows, On,
        "A SCIM 2.0 root for an external directory to provision accounts through.";
    UssdBridge = "ussd-bridge", Stable, RuntimeOnly, Realm, Narrows, On,
        "Answer USSD sessions opened on an operator short code.";
    Authorization = "authorization", Stable, RuntimeOnly, Realm, Narrows, On,
        "Resources, scopes and policies served to this realm's resource servers.";
    RebacStore = "rebac-store", Experimental, RuntimeOnly, Realm, Narrows, On,
        "Relation tuples backing the ReBAC side of the authorization engine.";
    Organization = "organization", Preview, RuntimeOnly, Realm, Narrows, On,
        "Group accounts under an organization carrying its own brokers and domains.";
    PhoneFirstLogin = "phone-first-login", Stable, RuntimeOnly, Realm, Narrows, On,
        "Accept a proven phone number anywhere a username is expected.";
    WebAuthn = "web-authn", Stable, RuntimeOnly, Realm, Weakens, On,
        "Passkeys and roaming authenticators as a factor. Closing it sends people back to what is left.";
    SmsOtp = "sms-otp", Stable, RuntimeOnly, Realm, Weakens, On,
        "A code delivered by the SMS gateway, as a first or second factor. Closing it takes a factor away.";
}

/// Whether the capabilities this crate itself carries were linked. Only
/// this crate sees its own cfg; the rest answer through their own crates.
pub fn locally_compiled(feature: Feature) -> bool {
    matches!(feature, Feature::TracingJson) && cfg!(feature = "tracing-json")
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
    #[error("feature '{0}' is the process's to set, not a realm's")]
    NotARealmsToMake(String),
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
            // A runtime switch is in every build by construction, which is
            // what its gating says. Asking the caller would mean each of them
            // remembering to answer yes for a capability that belongs to no
            // crate's `cfg!`, and the one that forgets ships it switched off.
            let compiled = match feature.spec().gating {
                Gating::RuntimeOnly => true,
                Gating::CompileOnly | Gating::Both => compiled(feature),
            };

            if wanted_on[index] && wanted_off[index] {
                return Err(FeatureError::Contradictory(feature.slug().to_string()));
            }
            if wanted_on[index] && !compiled {
                return Err(FeatureError::NotCompiled(feature.slug().to_string()));
            }

            let wanted =
                (feature.spec().standing == Standing::On || wanted_on[index]) && !wanted_off[index];

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

    /// What one realm is running, given what it has asked for.
    ///
    /// The process is the ceiling and the realm moves under it. A realm that
    /// has asked for nothing runs what the process runs, so a deployment that
    /// upgrades into this finds every realm exactly where it was.
    pub fn within_realm(&self, asked: &RealmWishes) -> RealmFeatures {
        let mut enabled = vec![false; Feature::ALL.len()];
        for feature in Feature::ALL.iter().copied() {
            let above = self.is_enabled(feature);
            enabled[feature.index()] = match feature.spec().reach {
                Reach::Process => above,
                Reach::Realm => above && asked.wants(feature).unwrap_or(true),
            };
        }
        RealmFeatures { enabled }
    }
}

/// The set this process resolved at boot, readable from any layer.
///
/// It lived in the serving crate while only that crate asked. A capability is
/// refused where it is used, and the places it is used are spread across the
/// engine as much as the doors, so a set only the outermost layer can read is
/// a set the inner ones have to be handed by every caller. One process, one
/// answer, asked wherever the question comes up.
static INSTALLED: std::sync::OnceLock<FeatureSet> = std::sync::OnceLock::new();

/// Fix the set for the life of the process. The second call is ignored: this
/// is decided once, at boot, before anything serves.
pub fn install(resolved: FeatureSet) {
    let _ = INSTALLED.set(resolved);
}

/// What the process is running. Before `install`, every compiled default,
/// which is what a test that never boots a server should see.
pub fn installed() -> &'static FeatureSet {
    INSTALLED.get_or_init(|| FeatureSet::resolve("", |_| false).expect("an empty request resolves"))
}

/// What one realm has said about the capabilities it may move.
///
/// Absent means "as the process has it", which is why this holds an option
/// per capability rather than a set: a realm that has never been asked is not
/// the same as one that has turned everything off.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RealmWishes {
    asked: Vec<(Feature, bool)>,
}

impl RealmWishes {
    pub fn none() -> Self {
        Self::default()
    }

    /// Take one wish. A slug this build does not know is refused rather than
    /// dropped: a realm carrying a name nothing answers to is a realm whose
    /// operator believes something that is not so.
    pub fn with_wish(mut self, slug: &str, enabled: bool) -> Result<Self, FeatureError> {
        let feature =
            Feature::by_slug(slug).ok_or_else(|| FeatureError::UnknownSlug(slug.to_string()))?;
        if feature.spec().reach != Reach::Realm {
            return Err(FeatureError::NotARealmsToMake(slug.to_string()));
        }
        self.asked.retain(|(held, _)| *held != feature);
        self.asked.push((feature, enabled));
        Ok(self)
    }

    fn wants(&self, feature: Feature) -> Option<bool> {
        self.asked
            .iter()
            .find(|(held, _)| *held == feature)
            .map(|(_, enabled)| *enabled)
    }
}

/// What one realm is actually running.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmFeatures {
    enabled: Vec<bool>,
}

impl RealmFeatures {
    pub fn is_enabled(&self, feature: Feature) -> bool {
        self.enabled[feature.index()]
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

        for unknown in ["", "chacha", "CHACHA20", "pkcs#11", "prometheus"] {
            assert_eq!(Feature::by_slug(unknown), None, "{unknown:?}");
        }
    }

    /// What each lifecycle means, tested on the lifecycle rather than through
    /// a capability that happens to have it.
    #[test]
    fn a_lifecycle_decides_on_its_own() {
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
    fn the_standing_decides_the_default() {
        let set = resolve("").unwrap();

        for feature in Feature::ALL.iter().copied() {
            assert_eq!(
                set.is_enabled(feature),
                feature.spec().standing == Standing::On,
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

    /// The first Both-gated capability: what is compiled sets the bound, and
    /// the runtime switch moves within it.
    #[test]
    fn a_runtime_switch_turns_a_compiled_capability_off() {
        let compiled = |feature: Feature| matches!(feature, Feature::Metrics);

        let resting = FeatureSet::resolve("", compiled).unwrap();
        assert!(
            resting.is_enabled(Feature::Metrics),
            "stable and compiled did not start on"
        );

        let turned = FeatureSet::resolve("-metrics", compiled).unwrap();
        assert!(!turned.is_enabled(Feature::Metrics));
        assert!(
            turned.status(Feature::Metrics).compiled,
            "off is a choice here, not an absence"
        );
    }

    /// A name nobody registered is refused rather than ignored.
    #[test]
    fn an_unknown_name_is_refused() {
        for written in ["prometheus", "+ciba", "-sms", "chacha"] {
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

    /// A realm may close what the process carries.
    #[test]
    fn a_realm_may_shut_a_capability_the_process_runs() {
        let process = resolve("").expect("the process resolves");
        assert!(process.is_enabled(Feature::TokenExchange));

        let asked = RealmWishes::none()
            .with_wish("token-exchange", false)
            .expect("a realm may name it");

        assert!(
            !process
                .within_realm(&asked)
                .is_enabled(Feature::TokenExchange)
        );
    }

    /// A realm may not open what the process does not carry. This is the whole
    /// of the ceiling: without it a realm's own settings would decide what the
    /// deployment is running, and an operator turning a capability off for the
    /// node would not have turned it off.
    #[test]
    fn a_realm_may_not_open_what_the_process_shut() {
        let process = resolve("-token-exchange").expect("the process resolves");
        assert!(!process.is_enabled(Feature::TokenExchange));

        let asked = RealmWishes::none()
            .with_wish("token-exchange", true)
            .expect("a realm may name it");

        assert!(
            !process
                .within_realm(&asked)
                .is_enabled(Feature::TokenExchange),
            "a realm reached above the process"
        );
    }

    /// A realm that has asked for nothing runs what the process runs, so an
    /// upgrade into this changes nothing anywhere.
    #[test]
    fn a_realm_that_asked_for_nothing_runs_what_the_process_runs() {
        let process = resolve("").expect("the process resolves");
        let quiet = process.within_realm(&RealmWishes::none());

        for feature in Feature::ALL.iter().copied() {
            assert_eq!(
                quiet.is_enabled(feature),
                process.is_enabled(feature),
                "{feature:?} moved for a realm that said nothing"
            );
        }
    }

    /// What the process alone decides stays the process's.
    #[test]
    fn a_realm_is_refused_a_capability_that_is_not_its_to_move() {
        for feature in Feature::ALL.iter().copied() {
            let asked = RealmWishes::none().with_wish(feature.slug(), false);
            match feature.spec().reach {
                Reach::Realm => assert!(asked.is_ok(), "{feature:?} is a realm's to move"),
                Reach::Process => assert_eq!(
                    asked.unwrap_err(),
                    FeatureError::NotARealmsToMake(feature.slug().to_string()),
                ),
            }
        }
    }

    /// An unknown name is refused rather than ignored.
    #[test]
    fn a_realm_is_refused_a_name_this_build_does_not_know() {
        assert_eq!(
            RealmWishes::none()
                .with_wish("declarative-user-profile", true)
                .unwrap_err(),
            FeatureError::UnknownSlug("declarative-user-profile".to_string()),
        );
    }

    /// A runtime switch is carried by every build, whatever a caller that
    /// only knows its own crate would answer.
    #[test]
    fn a_runtime_switch_is_in_the_build_whoever_is_asked() {
        let resolved = FeatureSet::resolve("", |_| false).expect("it resolves");

        for feature in Feature::ALL.iter().copied() {
            if feature.spec().gating == Gating::RuntimeOnly {
                assert!(
                    resolved.status(feature).compiled,
                    "{feature:?} is a runtime switch and was reported absent"
                );
            }
        }
    }

    /// A capability a realm may move says which way closing it points, and
    /// the two that take a factor away are the two that say so.
    #[test]
    fn a_capability_says_what_closing_it_costs() {
        for feature in Feature::ALL.iter().copied() {
            let spec = feature.spec();
            let weakens = spec.closing == Closing::Weakens;
            let takes_a_factor = matches!(feature, Feature::WebAuthn | Feature::SmsOtp);
            if takes_a_factor {
                assert!(
                    weakens,
                    "{feature:?} takes a factor away and does not say so"
                );
            }
        }
    }

    /// Everything a realm may move is a runtime switch, because a realm cannot
    /// relink the build it is served by.
    #[test]
    fn what_a_realm_may_move_is_a_runtime_switch() {
        for feature in Feature::ALL.iter().copied() {
            if feature.spec().reach == Reach::Realm {
                assert_eq!(
                    feature.spec().gating,
                    Gating::RuntimeOnly,
                    "{feature:?} is a realm's to move but is not a runtime switch"
                );
            }
        }
    }

    /// Nothing a build already runs is switched off by being declared.
    ///
    /// A capability gains its switch after it has been shipping, and a
    /// deployment that upgrades has said nothing about it. If declaring it
    /// turned it off, the upgrade would take away what was working, which is
    /// the one thing a registry must never do to a realm holding real people.
    #[test]
    fn declaring_a_capability_that_already_ran_does_not_take_it_away() {
        let resolved = FeatureSet::resolve("", |_| true).expect("it resolves");

        for feature in Feature::ALL.iter().copied() {
            if feature.spec().reach == Reach::Realm {
                assert!(
                    resolved.is_enabled(feature),
                    "{feature:?} is a realm's to close and a silent deployment does not run it"
                );
            }
        }
    }
}
