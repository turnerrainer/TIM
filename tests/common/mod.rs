//! Shared test helpers for integration tests.
//!
//! `serialize_binary` gates a test binary behind a session-scoped
//! Postgres advisory lock. All integration test binaries share one
//! Postgres in CI and each `setup()` starts with a `TRUNCATE` of the
//! shared tables — without a cross-process lock, binary B's TRUNCATE
//! wipes binary A's in-flight denylist rows, flipping expected-409
//! (idempotent second revoke) responses to 200. Holding the lock on
//! a dedicated connection stored in a `static OnceCell` keeps it
//! alive for the binary's lifetime; process exit closes the socket
//! and Postgres releases the lock so the next binary can proceed.
//!
//! `log_capture` installs a process-global tracing subscriber whose
//! output is a shared `Vec<u8>`. Tests inspect it to verify per-request
//! access log lines are emitted (§1.2) and that attacker-controlled
//! canaries never appear (§1.3, §1.4 of FLEET-STRONGHOLDS.md).

#[allow(dead_code)] // used only by log-hygiene test binaries
pub mod log_capture;

use sqlx::{Connection, PgConnection};
use tokio::sync::OnceCell;

// Arbitrary int64 lock ID shared by every test binary. ASCII for
// "TIMTESTS" — chosen to be unlikely to collide with any real
// application-level advisory lock the app might one day take.
#[allow(dead_code)] // not every test binary needs Postgres serialisation
const TEST_ADVISORY_LOCK_ID: i64 = 0x54_49_4D_54_45_53_54_53;

#[allow(dead_code)] // not every test binary needs Postgres serialisation
static LOCK_CONN: OnceCell<PgConnection> = OnceCell::const_new();

#[allow(dead_code)] // not every test binary needs Postgres serialisation
pub async fn serialize_binary(db_url: &str) {
    LOCK_CONN
        .get_or_init(|| async {
            let mut conn = PgConnection::connect(db_url)
                .await
                .expect("integration-test lock: connect");
            sqlx::query("SELECT pg_advisory_lock($1)")
                .bind(TEST_ADVISORY_LOCK_ID)
                .execute(&mut conn)
                .await
                .expect("integration-test lock: pg_advisory_lock");
            conn
        })
        .await;
}
