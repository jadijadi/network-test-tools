use std::fmt::Debug;
use std::fs::File;
use std::future::Future;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Writes a timestamped log (mirroring the bash script's MARKER/START/END/EXIT lines) while
/// also echoing everything to stdout.
pub struct Report {
    file: File,
    pub path: PathBuf,
}

impl Report {
    pub fn new(path: PathBuf) -> anyhow::Result<Self> {
        let file = File::create(&path)?;
        Ok(Self { file, path })
    }

    fn timestamp() -> String {
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "unknown-time".to_string())
    }

    pub fn line(&mut self, msg: &str) {
        println!("{msg}");
        let _ = writeln!(self.file, "{msg}");
    }

    pub fn mark(&mut self, msg: &str) {
        self.line(&format!("MARKER[{}]: {msg}", Self::timestamp()));
    }

    /// Runs `fut` under a hard `timeout`, logging START/END/EXIT markers the way the original
    /// bash script's `run()` helper did around `timeout --signal=KILL`.
    pub async fn run<F, T, E>(&mut self, label: &str, timeout: Duration, fut: F) -> Option<T>
    where
        F: Future<Output = Result<T, E>>,
        T: Debug,
        E: Debug,
    {
        self.mark(&format!("START {label}"));
        let started = Instant::now();
        let outcome = tokio::time::timeout(timeout, fut).await;
        let elapsed = started.elapsed();

        let result = match outcome {
            Ok(Ok(value)) => {
                self.line(&format!(
                    "  OK   {label} ({:.3}s): {value:?}",
                    elapsed.as_secs_f64()
                ));
                Some(value)
            }
            Ok(Err(err)) => {
                self.line(&format!(
                    "  FAIL {label} ({:.3}s): {err:?}",
                    elapsed.as_secs_f64()
                ));
                None
            }
            Err(_) => {
                self.line(&format!(
                    "  TIMEOUT {label} (>{:.3}s)",
                    timeout.as_secs_f64()
                ));
                None
            }
        };
        self.mark(&format!("END {label}"));
        result
    }
}
