//! Where spans go, and how many.

use crate::ConfigError;

/// The collector traces are exported to, e.g. `http://collector:4318/v1/traces`.
///
/// Absent means no export and no dialling, however the build was made and
/// whatever the feature switch says: an exporter with nowhere to send is
/// not started at all.
pub fn endpoint() -> Option<String> {
    crate::optional("OTEL_ENDPOINT")
}

/// The head-sampling ratio, parent-based: a request arriving inside a
/// sampled trace stays sampled, a fresh one is kept at this rate.
///
/// One in ten unless said. Outside [0, 1] is refused rather than clamped:
/// a clamped value samples at a rate the operator did not choose.
pub fn sample_ratio() -> Result<f64, ConfigError> {
    let ratio = crate::parse_or("OTEL_SAMPLE", 0.1_f64)?;
    if !(0.0..=1.0).contains(&ratio) {
        return Err(ConfigError::Invalid {
            key: "SAFFUI_OTEL_SAMPLE".to_owned(),
            expected: "ratio between 0 and 1".to_owned(),
        });
    }
    Ok(ratio)
}
