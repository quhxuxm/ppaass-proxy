use crate::error::ProxyServerError;

use std::path::Path;

use tracing::level_filters::LevelFilter;

use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::fmt::format::{DefaultFields, Format, Full};
use tracing_subscriber::fmt::time::ChronoUtc;
use tracing_subscriber::fmt::Subscriber;

const TRACE_FILE_DIR_PATH: &str = "log";

pub(crate) type TraceSubscriber =
    Subscriber<DefaultFields, Format<Full, ChronoUtc>, LevelFilter, NonBlocking>;

pub(crate) fn init_global_tracing_subscriber(
    trace_file_name_prefix: &str,
    max_level: LevelFilter,
) -> Result<(TraceSubscriber, WorkerGuard), ProxyServerError> {
    let (trace_file_appender, trace_appender_guard) = tracing_appender::non_blocking(
        tracing_appender::rolling::daily(Path::new(TRACE_FILE_DIR_PATH), trace_file_name_prefix),
    );
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(max_level)
        .with_writer(trace_file_appender)
        .with_line_number(true)
        .with_level(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_timer(ChronoUtc::rfc_3339())
        .with_ansi(false)
        .finish();
    Ok((subscriber, trace_appender_guard))
}
