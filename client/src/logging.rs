//! File logging with a runtime toggle.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tracing::Level;
use tracing_subscriber::fmt::writer::MakeWriter;
use tracing_subscriber::FmtSubscriber;

struct LogController {
    enabled: AtomicBool,
    file: Mutex<Option<std::fs::File>>,
    path: PathBuf,
}

impl LogController {
    fn new(path: PathBuf, enabled: bool) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            file: Mutex::new(None),
            path,
        }
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
        if !enabled {
            if let Ok(mut file) = self.file.lock() {
                *file = None;
            }
        }
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        if !self.is_enabled() {
            return Ok(buf.len());
        }

        let mut file_guard = self
            .file
            .lock()
            .map_err(|_| io::Error::other("client log file lock poisoned"))?;

        if file_guard.is_none() {
            if let Some(parent) = self.path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            *file_guard = Some(file);
        }

        match file_guard.as_mut() {
            Some(file) => file.write(buf),
            None => Err(io::Error::other("client log file unavailable")),
        }
    }

    fn flush(&self) -> io::Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }

        let mut file_guard = self
            .file
            .lock()
            .map_err(|_| io::Error::other("client log file lock poisoned"))?;

        if let Some(file) = file_guard.as_mut() {
            file.flush()
        } else {
            Ok(())
        }
    }
}

#[derive(Clone)]
struct FileLogWriter {
    controller: Arc<LogController>,
}

impl<'a> MakeWriter<'a> for FileLogWriter {
    type Writer = FileLogGuard;

    fn make_writer(&'a self) -> Self::Writer {
        FileLogGuard {
            controller: self.controller.clone(),
        }
    }
}

struct FileLogGuard {
    controller: Arc<LogController>,
}

impl Write for FileLogGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.controller.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.controller.flush()
    }
}

static LOG_CONTROLLER: OnceLock<Arc<LogController>> = OnceLock::new();

pub fn init(enabled: bool) {
    let log_path = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|dir| dir.join("log.txt")))
        .unwrap_or_else(|| std::env::temp_dir().join("reboot-client.log"));

    let controller = Arc::new(LogController::new(log_path.clone(), enabled));
    let writer = FileLogWriter {
        controller: controller.clone(),
    };

    let _ = LOG_CONTROLLER.set(controller);

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_file(true)
        .with_line_number(true)
        .with_ansi(false)
        .with_writer(writer)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");

    if enabled {
        tracing::info!("Reboot Client starting...");
        tracing::info!("Logging to {:?}", log_path);
        if let Ok(exe_path) = std::env::current_exe() {
            tracing::info!("Executable path: {:?}", exe_path);
        }
    }
}

pub fn set_enabled(enabled: bool) {
    if let Some(controller) = LOG_CONTROLLER.get() {
        controller.set_enabled(enabled);
        if enabled {
            tracing::info!("Client debug logging enabled");
            tracing::info!("Logging to {:?}", controller.path);
        }
    }
}

pub fn log_path() -> Option<PathBuf> {
    LOG_CONTROLLER.get().map(|controller| controller.path.clone())
}
