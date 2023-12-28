use crate::error::ProxyServerError;

use derive_more::Display;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::level_filters::LevelFilter;
use tracing::trace;

use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::fmt::format::{DefaultFields, Format, Full};
use tracing_subscriber::fmt::time::ChronoUtc;
use tracing_subscriber::fmt::Subscriber;

const TRACE_FILE_DIR_PATH: &str = "log";

#[derive(Debug, Display)]
#[display(fmt = "{}")]
pub(crate) enum TransportTraceType {
    #[display(fmt = "CREATE")]
    Create,
    #[display(fmt = "DROP_TCP")]
    DropTcp,
    #[display(fmt = "DROP_Udp")]
    DropUdp,
    #[display(fmt = "DROP_UNKNOWN")]
    DropUnknown,
}

pub(crate) fn trace_transport(
    subscriber: Arc<Subscriber<DefaultFields, Format<Full, ChronoUtc>, LevelFilter, NonBlocking>>,
    transport_trace_type: TransportTraceType,
    transport_id: &str,
    transport_number: Arc<AtomicU64>,
) {
    tracing::subscriber::with_default(subscriber, || {
        trace!(
            "{transport_trace_type},{},{transport_id}",
            transport_number.load(Ordering::Relaxed)
        )
    });
}

pub(crate) fn init_tracing_subscriber(
    trace_file_name_prefix: &str,
    max_level: LevelFilter,
) -> Result<
    (
        Subscriber<DefaultFields, Format<Full, ChronoUtc>, LevelFilter, NonBlocking>,
        WorkerGuard,
    ),
    ProxyServerError,
> {
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
        .with_timer(tracing_subscriber::fmt::time::ChronoUtc::rfc_3339())
        .with_ansi(false)
        .finish();
    Ok((subscriber, trace_appender_guard))
}
