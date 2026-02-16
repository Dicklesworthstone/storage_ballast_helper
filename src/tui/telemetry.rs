//! Telemetry hook scaffolding for timeline/explainability panes.

#![allow(missing_docs)]

/// Minimal telemetry sample used by early runtime instrumentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetrySample {
    pub source: String,
    pub kind: String,
    pub detail: String,
}

impl TelemetrySample {
    #[must_use]
    pub fn new(source: impl Into<String>, kind: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            kind: kind.into(),
            detail: detail.into(),
        }
    }
}

/// Hook point for ingesting runtime telemetry events.
pub trait TelemetryHook {
    fn record(&mut self, sample: TelemetrySample);
}

/// No-op telemetry hook used in scaffold mode.
#[derive(Debug, Default)]
pub struct NullTelemetryHook;

impl TelemetryHook for NullTelemetryHook {
    fn record(&mut self, _sample: TelemetrySample) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_hook_accepts_samples_without_panicking() {
        let mut hook = NullTelemetryHook;
        hook.record(TelemetrySample::new("runtime", "tick", "ok"));
    }
}
