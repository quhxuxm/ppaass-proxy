use crate::error::ProxyServerError;

use std::path::Path;
use tracing::level_filters::LevelFilter;
use tracing_appender::non_blocking::WorkerGuard;

pub(crate) fn init_tracing(
    trace_file_dir: &Path,
    trace_file_name_prefix: &str,
    max_level: LevelFilter,
) -> Result<WorkerGuard, ProxyServerError> {
    let (trace_file_appender, trace_appender_guard) = tracing_appender::non_blocking(
        tracing_appender::rolling::daily(trace_file_dir, trace_file_name_prefix),
    );
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(max_level)
        .with_writer(trace_file_appender)
        .with_line_number(true)
        .with_level(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_timer(tracing_subscriber::fmt::time::ChronoUtc::rfc_3339())
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).map_err(|e| {
        ProxyServerError::Other(format!(
            "Fail to initialize tracing system because of error: {e:?}"
        ))
    })?;
    Ok(trace_appender_guard)
}
