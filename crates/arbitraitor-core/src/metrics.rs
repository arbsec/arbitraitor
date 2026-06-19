//! In-memory operation metrics and structured operation logs.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Metrics captured for one completed artifact analysis operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationMetrics {
    /// Total scan duration in milliseconds.
    pub scan_duration_ms: u64,
    /// Total findings emitted by all detectors.
    pub finding_count: usize,
    /// Final operation verdict.
    pub verdict: String,
    /// Exact artifact size in bytes.
    pub artifact_size: u64,
    /// Classified artifact type.
    pub artifact_type: String,
    /// Number of detectors that ran.
    pub detector_count: usize,
    /// Number of detectors that ended with an error or timeout.
    pub detector_errors: usize,
}

/// In-memory collector for operation metrics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MetricsCollector {
    operations: Vec<OperationMetrics>,
}

impl MetricsCollector {
    /// Creates an empty metrics collector.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            operations: Vec::new(),
        }
    }

    /// Records metrics for one completed operation.
    pub fn record(&mut self, metrics: OperationMetrics) {
        self.operations.push(metrics);
    }

    /// Returns an aggregate summary for all recorded operations.
    #[must_use]
    pub fn summary(&self) -> MetricsSummary {
        let total_operations = self.operations.len();
        let total_findings = self
            .operations
            .iter()
            .map(|metrics| metrics.finding_count)
            .sum();
        let total_scan_duration_ms: u64 = self
            .operations
            .iter()
            .map(|metrics| metrics.scan_duration_ms)
            .sum();
        let mut verdict_distribution = HashMap::new();
        let mut detector_count = 0usize;
        let mut detector_errors = 0usize;

        for metrics in &self.operations {
            *verdict_distribution
                .entry(metrics.verdict.clone())
                .or_insert(0) += 1;
            detector_count += metrics.detector_count;
            detector_errors += metrics.detector_errors;
        }

        MetricsSummary {
            total_operations,
            avg_scan_duration_ms: average_duration(total_scan_duration_ms, total_operations),
            verdict_distribution,
            total_findings,
            error_rate: error_rate(detector_errors, detector_count),
        }
    }
}

/// Aggregate metrics across recorded operations.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsSummary {
    /// Number of completed operations recorded.
    pub total_operations: usize,
    /// Average scan duration in milliseconds.
    pub avg_scan_duration_ms: u64,
    /// Count of operations by final verdict.
    pub verdict_distribution: HashMap<String, usize>,
    /// Total findings emitted across all operations.
    pub total_findings: usize,
    /// Detector error ratio across all recorded detector executions.
    pub error_rate: f64,
}

/// Emits structured fields for a completed operation.
pub fn log_operation(metrics: &OperationMetrics) {
    tracing::info!(
        target: "arbitraitor.operation",
        scan_duration_ms = metrics.scan_duration_ms,
        finding_count = metrics.finding_count,
        verdict = %metrics.verdict,
        artifact_size = metrics.artifact_size,
        artifact_type = %metrics.artifact_type,
        detector_count = metrics.detector_count,
        detector_errors = metrics.detector_errors,
        "operation completed"
    );
}

fn average_duration(total_scan_duration_ms: u64, total_operations: usize) -> u64 {
    if total_operations == 0 {
        0
    } else {
        total_scan_duration_ms / u64::try_from(total_operations).unwrap_or(u64::MAX)
    }
}

fn error_rate(detector_errors: usize, detector_count: usize) -> f64 {
    if detector_count == 0 {
        0.0
    } else {
        let errors = u32::try_from(detector_errors).unwrap_or(u32::MAX);
        let count = u32::try_from(detector_count).unwrap_or(u32::MAX);
        f64::from(errors) / f64::from(count)
    }
}

#[cfg(test)]
mod tests {
    use super::{MetricsCollector, OperationMetrics};

    fn metrics(verdict: &str, detector_count: usize, detector_errors: usize) -> OperationMetrics {
        OperationMetrics {
            scan_duration_ms: 10,
            finding_count: 2,
            verdict: verdict.to_owned(),
            artifact_size: 128,
            artifact_type: "ShellScript(Bash)".to_owned(),
            detector_count,
            detector_errors,
        }
    }

    #[test]
    fn record_operation_summary_computes_totals() {
        let mut collector = MetricsCollector::new();
        collector.record(metrics("pass", 2, 0));
        collector.record(OperationMetrics {
            scan_duration_ms: 30,
            finding_count: 4,
            verdict: "warn".to_owned(),
            artifact_size: 256,
            artifact_type: "GenericText".to_owned(),
            detector_count: 2,
            detector_errors: 1,
        });

        let summary = collector.summary();

        assert_eq!(summary.total_operations, 2);
        assert_eq!(summary.avg_scan_duration_ms, 20);
        assert_eq!(summary.total_findings, 6);
    }

    #[test]
    fn verdict_distribution_is_counted() {
        let mut collector = MetricsCollector::new();
        collector.record(metrics("pass", 1, 0));
        collector.record(metrics("pass", 1, 0));
        collector.record(metrics("block", 1, 0));

        let summary = collector.summary();

        assert_eq!(summary.verdict_distribution.get("pass"), Some(&2));
        assert_eq!(summary.verdict_distribution.get("block"), Some(&1));
    }

    #[test]
    fn error_rate_uses_detector_executions() {
        let mut collector = MetricsCollector::new();
        collector.record(metrics("incomplete", 3, 1));
        collector.record(metrics("incomplete", 1, 1));

        let summary = collector.summary();

        assert!((summary.error_rate - 0.5).abs() < 1e-10);
    }

    #[test]
    fn metrics_serialize_to_json() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = serde_json::to_string(&metrics("pass", 2, 0))?;

        assert!(encoded.contains("\"scan_duration_ms\":10"));
        assert!(encoded.contains("\"verdict\":\"pass\""));
        Ok(())
    }
}
