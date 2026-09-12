//! Shared log-capture subscriber for integration tests.
//!
//! `tracing::subscriber::set_global_default` can only be called once
//! per process. Multiple integration test binaries share a `MakeWriter`
//! that appends every emitted line to an `Arc<Mutex<Vec<u8>>>`. Tests
//! read a byte offset before the exercised action and inspect the
//! delta afterwards.
//!
//! Fresh subscriber has ANSI off (fleet-strongholds §1.1) so raw ESC
//! bytes cannot appear from the tracing_subscriber formatter itself —
//! the byte-count assertion in `security_log_ansi_off.rs` therefore
//! only detects source-level ANSI (attacker-injected via headers or
//! path, not colour codes added by the formatter).

use std::io;
use std::sync::{Arc, Mutex, OnceLock};

use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
pub struct SharedBuf {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl SharedBuf {
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn snapshot(&self) -> Vec<u8> {
        self.inner.lock().unwrap().clone()
    }

    pub fn slice_from(&self, offset: usize) -> Vec<u8> {
        let g = self.inner.lock().unwrap();
        if offset >= g.len() {
            Vec::new()
        } else {
            g[offset..].to_vec()
        }
    }
}

impl io::Write for SharedBuf {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.inner.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedBuf {
    type Writer = SharedBuf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

static CAPTURE: OnceLock<SharedBuf> = OnceLock::new();

/// Install a process-global `tracing` subscriber on first call. Every
/// subsequent call returns a handle to the same shared buffer, so
/// tests can observe log output emitted by TIM code paths.
pub fn install() -> SharedBuf {
    CAPTURE
        .get_or_init(|| {
            let buf = SharedBuf::default();
            // ANSI off so log content is comparable byte-for-byte, and
            // the ESC-byte assertion in security_log_ansi_off.rs is a
            // reliable signal of attacker-injected escapes (not
            // formatter colour codes).
            let subscriber = tracing_subscriber::fmt()
                .with_writer(buf.clone())
                .with_ansi(false)
                .with_target(true)
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
            buf
        })
        .clone()
}
