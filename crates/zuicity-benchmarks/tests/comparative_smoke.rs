//! Smoke tests for upstream-vs-Rust comparative benchmark helpers.

use std::time::Duration;

use zuicity_benchmarks::{
    run_upstream_vs_rust_tcp_latency_comparison, run_upstream_vs_rust_udp_latency_comparison,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_vs_rust_tcp_latency_comparison_smoke() -> anyhow::Result<()> {
    let iterations = 3;
    let comparison = tokio::time::timeout(
        Duration::from_secs(300),
        run_upstream_vs_rust_tcp_latency_comparison(iterations),
    )
    .await??;

    eprintln!(
        "upstream_vs_rust_tcp_latency_comparison iterations={} upstream_mean_ns={} rust_mean_ns={} upstream_min_ns={} upstream_max_ns={} rust_min_ns={} rust_max_ns={}",
        comparison.iterations,
        comparison.upstream_mean.as_nanos(),
        comparison.rust_mean.as_nanos(),
        comparison.upstream_min.as_nanos(),
        comparison.upstream_max.as_nanos(),
        comparison.rust_min.as_nanos(),
        comparison.rust_max.as_nanos()
    );

    assert_eq!(comparison.iterations, iterations);
    assert_eq!(comparison.upstream_completed, iterations);
    assert_eq!(comparison.rust_completed, iterations);
    assert!(comparison.upstream_total > 0);
    assert!(comparison.rust_total > 0);
    assert!(comparison.upstream_min <= comparison.upstream_mean);
    assert!(comparison.upstream_mean <= comparison.upstream_max);
    assert!(comparison.rust_min <= comparison.rust_mean);
    assert!(comparison.rust_mean <= comparison.rust_max);
    assert!(comparison.upstream_mean > Duration::ZERO);
    assert!(comparison.rust_mean > Duration::ZERO);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_vs_rust_udp_latency_comparison_smoke() -> anyhow::Result<()> {
    let iterations = 3;
    let comparison = tokio::time::timeout(
        Duration::from_secs(300),
        run_upstream_vs_rust_udp_latency_comparison(iterations),
    )
    .await??;

    eprintln!(
        "upstream_vs_rust_udp_latency_comparison iterations={} upstream_mean_ns={} rust_mean_ns={} upstream_min_ns={} upstream_max_ns={} rust_min_ns={} rust_max_ns={}",
        comparison.iterations,
        comparison.upstream_mean.as_nanos(),
        comparison.rust_mean.as_nanos(),
        comparison.upstream_min.as_nanos(),
        comparison.upstream_max.as_nanos(),
        comparison.rust_min.as_nanos(),
        comparison.rust_max.as_nanos()
    );

    assert_eq!(comparison.iterations, iterations);
    assert_eq!(comparison.upstream_completed, iterations);
    assert_eq!(comparison.rust_completed, iterations);
    assert!(comparison.upstream_total > 0);
    assert!(comparison.rust_total > 0);
    assert!(comparison.upstream_min <= comparison.upstream_mean);
    assert!(comparison.upstream_mean <= comparison.upstream_max);
    assert!(comparison.rust_min <= comparison.rust_mean);
    assert!(comparison.rust_mean <= comparison.rust_max);
    assert!(comparison.upstream_mean > Duration::ZERO);
    assert!(comparison.rust_mean > Duration::ZERO);
    Ok(())
}
