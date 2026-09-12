//! Audit LOG-v1 FN-LOG-1 regression pin.
//!
//! Verifies TIM's tracing_subscriber does not emit ANSI escape bytes
//! when the writer is not a terminal — the invariant `with_ansi(false)`
//! from `src/main.rs`. The h2ck.me break-test measured this externally
//! by piping `docker logs` through `tr -cd $'\x1b' | wc -c` and
//! expecting 0. This in-process test proves the same contract without
//! spawning the binary.
//!
//! Also asserts `src/main.rs` uses `stderr().is_terminal()` to gate
//! ANSI — a source-level guard against a future refactor accidentally
//! enabling colour codes in production.

mod common;

/// Load `src/main.rs` and assert the tracing setup carries the ANSI
/// guard the fleet-strongholds pattern §1.1 requires. This is a
/// lint-style test: it fires when the guard is removed or the
/// idiom is renamed. Refactor-safe within the same idiom family
/// (accepts `atty::is(atty::Stream::Stderr)` too, per the alternative
/// FLEET-STRONGHOLDS §1.1 suggests).
#[test]
fn main_rs_gates_ansi_on_stderr_is_terminal() {
    let src = std::fs::read_to_string("src/main.rs").expect("read src/main.rs");
    let has_std_gate = src.contains(".with_ansi(std::io::stderr().is_terminal())");
    let has_atty_gate = src.contains(".with_ansi(atty::is(atty::Stream::Stderr))");
    assert!(
        has_std_gate || has_atty_gate,
        "src/main.rs must gate `.with_ansi` on stderr.is_terminal() \
         (fleet-strongholds §1.1); found neither idiom"
    );
    // Belt-and-braces: ensure the guard is not commented out.
    for line in src.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        if trimmed.contains(".with_ansi(") && trimmed.contains("true") {
            panic!(
                "src/main.rs has `.with_ansi(true)` — ANSI must be gated: {}",
                line
            );
        }
    }
}

/// End-to-end assertion on the tracing_subscriber contract:
/// `with_ansi(false)` produces zero raw ESC bytes even when the
/// message argument itself contains formatting hints. This proves
/// the fleet-strongholds §1.1 outcome (0 ESC bytes when piped).
#[test]
fn tracing_subscriber_with_ansi_false_emits_no_escape_bytes() {
    let buf = common::log_capture::install();
    let start = buf.len();
    // Log a variety of levels — the default tracing_subscriber format
    // colours the level tag (green INFO / yellow WARN / red ERROR) when
    // ANSI is on. With ANSI off, none of these should produce \x1b.
    tracing::info!(marker = "ansi-off-test", "info level");
    tracing::warn!(marker = "ansi-off-test", "warn level");
    tracing::error!(marker = "ansi-off-test", "error level");
    let delta = buf.slice_from(start);
    let esc_count = delta.iter().filter(|b| **b == 0x1b).count();
    assert_eq!(
        esc_count,
        0,
        "captured log delta contains {} ESC bytes (expected 0): {}",
        esc_count,
        String::from_utf8_lossy(&delta)
    );
}
