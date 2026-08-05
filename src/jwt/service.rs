use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::JwtConfig;
use crate::crypto::JwtSigner;
use crate::error::{Result, TimError};
use crate::jwt::api::*;

/// The standard-plus-custom claims we sign into every JWT.
///
/// `serde(flatten)` on `extra` picks up caller-supplied custom claims
/// (whatever `content` was in the request) so validators see them
/// alongside the RFC 7519 registered claims.
#[derive(Debug, Serialize, Deserialize)]
pub struct StandardClaims {
    pub iss: String,
    pub sub: Option<String>,
    pub aud: Option<Vec<String>>,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

pub struct JwtService {
    pool: PgPool,
    signer: JwtSigner,
    cfg: JwtConfig,
}

impl JwtService {
    pub fn new(pool: PgPool, signer: JwtSigner, cfg: JwtConfig) -> Self {
        Self { pool, signer, cfg }
    }

    pub fn cfg(&self) -> &JwtConfig {
        &self.cfg
    }

    pub fn signer(&self) -> &JwtSigner {
        &self.signer
    }

    // --------------------- generate ---------------------

    pub async fn generate(&self, req: GenerateRequest) -> Result<TokenResponse> {
        if req.expiration_in_minutes <= 0 {
            return Err(TimError::BadRequest(
                "expirationInMinutes must be > 0".into(),
            ));
        }
        let claims_bytes = serde_json::to_vec(&req.content).unwrap_or_default();
        if claims_bytes.len() > self.cfg.max_claims_bytes {
            return Err(TimError::PayloadTooLarge {
                max: self.cfg.max_claims_bytes,
            });
        }

        let aud = self.resolve_audience(req.audience)?;
        let subject = req
            .content
            .get("sub")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let jti = Uuid::new_v4();
        let now = Utc::now();
        let exp = now + Duration::minutes(req.expiration_in_minutes);

        let mut extra = strip_reserved(req.content.clone());
        // Finding 17: inject `token_type: "custom_jwt"` so the JWT
        // itself declares its type — matches JVM 2.0
        // CustomJwtService.generate.
        extra.insert("token_type".into(), Value::String("custom_jwt".into()));
        let claims = StandardClaims {
            iss: self.cfg.issuer.clone(),
            sub: subject.clone(),
            aud: Some(aud.clone()),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            jti: jti.to_string(),
            extra,
        };
        let token = self.signer.sign(&claims)?;

        // Finding 19: use the *signed* set of claim keys (i.e. after
        // strip_reserved + token_type injection) so audit rows are
        // consistent between `generate` and `extend`.
        let claim_keys = claims
            .extra
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(",");
        let aud_str = aud.join(",");

        sqlx::query(
            r#"
            INSERT INTO custom_jwt.jwt_metadata
                (id, jwt_uuid, claim_keys, issued_at, expires_at,
                 subject, jwt_name, audience, issuer,
                 supersedes, original_jwt_uuid)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(jti)
        .bind(&claim_keys)
        .bind(now)
        .bind(exp)
        .bind(subject.as_deref())
        .bind(&req.jwt_name)
        .bind(&aud_str)
        .bind(&self.cfg.issuer)
        .bind(Option::<Uuid>::None)
        .bind(jti) // original_jwt_uuid == jti for a fresh token (chain root)
        .execute(&self.pool)
        .await?;

        Ok(TokenResponse {
            // Finding 16: JVM returns "created" on generate.
            status: "created".into(),
            jwt_name: req.jwt_name,
            token,
            expires_at: exp,
        })
    }

    fn resolve_audience(&self, requested: Option<Audience>) -> Result<Vec<String>> {
        let aud = requested
            .map(Audience::into_vec)
            .unwrap_or_else(|| vec![self.cfg.audience.default.clone()]);
        if self.cfg.audience.validation_enabled && !self.cfg.audience.allowed.is_empty() {
            for a in &aud {
                if !self.cfg.audience.allowed.contains(a) {
                    return Err(TimError::Unprocessable(format!(
                        "audience '{a}' not in allowed set"
                    )));
                }
            }
        }
        Ok(aud)
    }

    // --------------------- validate ---------------------

    pub async fn validate(&self, req: ValidateRequest) -> Result<ValidateResponse> {
        // First parse without validation to inspect claims / route.
        let v = permissive_validation();
        let decoded = match self.signer.verify::<StandardClaims>(&req.token, &v) {
            Ok(d) => d,
            Err(e) => {
                tracing::debug!(error = %e, "validate: token decode failed");
                let reason = if format!("{e}").to_lowercase().contains("expired") {
                    "expired"
                } else {
                    "signature_mismatch"
                };
                return Ok(ValidateResponse {
                    valid: false,
                    active: false,
                    reason: Some(reason.into()),
                    subject: None,
                    issuer: None,
                    audience: None,
                    expires_at: None,
                    issued_at: None,
                    jwt_id: None,
                    claims: None,
                });
            }
        };

        let claims = decoded.claims;
        let now = Utc::now().timestamp();

        // Issuer check (optional).
        if let Some(want_iss) = &req.issuer {
            if want_iss != &claims.iss {
                return Ok(response_from(&claims, false, false, "issuer_mismatch"));
            }
        }

        // Audience check (optional).
        if let Some(want_aud) = &req.audience {
            let matches = claims
                .aud
                .as_ref()
                .map(|list| list.iter().any(|a| a == want_aud))
                .unwrap_or(false);
            if !matches {
                return Ok(response_from(&claims, true, false, "audience_mismatch"));
            }
        }
        if self.cfg.audience.validation_enabled && !self.cfg.audience.allowed.is_empty() {
            let ok = claims
                .aud
                .as_ref()
                .map(|list| list.iter().any(|a| self.cfg.audience.allowed.contains(a)))
                .unwrap_or(false);
            if !ok {
                return Ok(response_from(&claims, true, false, "audience_mismatch"));
            }
        }

        // Expiration.
        if claims.exp < now {
            return Ok(response_from(&claims, true, false, "expired"));
        }

        // Denylist.
        let jti = Uuid::parse_str(&claims.jti)
            .map_err(|_| TimError::BadRequest("token jti is not a UUID".into()))?;
        if self.is_denylisted(jti).await? {
            return Ok(response_from(&claims, true, false, "revoked"));
        }

        Ok(response_from_valid(&claims))
    }

    async fn is_denylisted(&self, jti: Uuid) -> Result<bool> {
        self.denylist_lookup(jti).await
    }

    /// Public helper: exposes the same permissive-validation
    /// Validation used internally, so tests / introspect / any caller
    /// wanting to peek at claims can round-trip through the signer.
    pub fn permissive_validation() -> Validation {
        permissive_validation()
    }

    /// Bearer-token authenticator for `POST /jwt/custom/list/me`
    /// (finding 13). Enforces signature + exp + denylist and returns
    /// the token's `sub` claim on success. Any failure is a 401.
    pub async fn authenticate_bearer(&self, token: &str) -> Result<String> {
        let mut v = Validation::new(Algorithm::RS256);
        v.validate_exp = true;
        v.validate_aud = false;
        v.required_spec_claims.clear();
        let decoded = self
            .signer
            .verify::<StandardClaims>(token, &v)
            .map_err(|e| {
                tracing::debug!(error = %e, "authenticate_bearer: decode failed");
                TimError::Unauthorized
            })?;
        let claims = decoded.claims;
        let jti = Uuid::parse_str(&claims.jti).map_err(|_| TimError::Unauthorized)?;
        if self.denylist_lookup(jti).await? {
            return Err(TimError::Unauthorized);
        }
        claims.sub.ok_or(TimError::Unauthorized)
    }

    /// Public denylist-check helper; the introspection module uses this
    /// to answer RFC 7662 `active` without duplicating the query.
    pub async fn denylist_lookup(&self, jti: Uuid) -> Result<bool> {
        let row: Option<(Uuid,)> =
            sqlx::query_as("SELECT jwt_uuid FROM custom_jwt.denylist WHERE jwt_uuid = $1")
                .bind(jti)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.is_some())
    }

    // --------------------- revoke ---------------------

    /// Revoke by `jti` alone — used by the legacy `POST /jwt/blacklist?jwt=<uuid>`
    /// endpoint (finding 31). Looks up the token's expiry in the
    /// metadata table so the denylist row can be swept when it
    /// expires. Returns:
    ///   - `Ok(Some(true))` — newly revoked
    ///   - `Ok(Some(false))` — was already denylisted (idempotent)
    ///   - `Ok(None)` — no metadata for this jti (never issued by
    ///     this TIM); caller returns 404.
    pub async fn revoke_by_jti(&self, jti: Uuid, reason: Option<String>) -> Result<Option<bool>> {
        let row: Option<(DateTime<Utc>,)> = sqlx::query_as(
            r#"
            SELECT expires_at FROM custom_jwt.jwt_metadata
             WHERE jwt_uuid = $1
             ORDER BY created_at DESC
             LIMIT 1
            "#,
        )
        .bind(jti)
        .fetch_optional(&self.pool)
        .await?;
        let Some((exp,)) = row else {
            return Ok(None);
        };
        let result = sqlx::query(
            r#"
            INSERT INTO custom_jwt.denylist (jwt_uuid, expires_at, reason)
            VALUES ($1, $2, $3)
            ON CONFLICT (jwt_uuid) DO NOTHING
            "#,
        )
        .bind(jti)
        .bind(exp)
        .bind(reason.as_deref())
        .execute(&self.pool)
        .await?;
        Ok(Some(result.rows_affected() == 1))
    }

    /// Returns `true` if newly revoked; `false` if already denylisted.
    pub async fn revoke(&self, token: &str, reason: Option<String>) -> Result<bool> {
        let v = permissive_validation();
        let decoded = self
            .signer
            .verify::<StandardClaims>(token, &v)
            .map_err(|e| {
                tracing::debug!(error = %e, "revoke: token decode failed");
                TimError::BadRequest("token signature invalid; nothing to revoke".into())
            })?;
        let claims = decoded.claims;
        let jti = Uuid::parse_str(&claims.jti)
            .map_err(|_| TimError::BadRequest("token jti is not a UUID".into()))?;
        let exp = DateTime::<Utc>::from_timestamp(claims.exp, 0)
            .ok_or_else(|| TimError::BadRequest("token exp out of range".into()))?;

        let result = sqlx::query(
            r#"
            INSERT INTO custom_jwt.denylist (jwt_uuid, expires_at, reason)
            VALUES ($1, $2, $3)
            ON CONFLICT (jwt_uuid) DO NOTHING
            "#,
        )
        .bind(jti)
        .bind(exp)
        .bind(reason.as_deref())
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn bulk_revoke(&self, req: BulkRevokeRequest) -> Result<BulkRevokeResponse> {
        if req.tokens.is_empty() {
            return Err(TimError::BadRequest("tokens must not be empty".into()));
        }
        if req.tokens.len() > self.cfg.bulk_revoke_max {
            return Err(TimError::BadRequest(format!(
                "tokens exceeds bulk_revoke_max ({})",
                self.cfg.bulk_revoke_max
            )));
        }

        let mut results = Vec::with_capacity(req.tokens.len());
        let mut newly = 0;
        let mut already = 0;
        let mut failed = 0;
        for tok in req.tokens {
            match self.revoke(&tok, req.reason.clone()).await {
                Ok(true) => {
                    newly += 1;
                    results.push(BulkRevokeItem {
                        token: tok,
                        status: "revoked".into(),
                        reason: None,
                    });
                }
                Ok(false) => {
                    already += 1;
                    results.push(BulkRevokeItem {
                        token: tok,
                        status: "already".into(),
                        reason: None,
                    });
                }
                Err(e) => {
                    failed += 1;
                    results.push(BulkRevokeItem {
                        token: tok,
                        status: "failed".into(),
                        reason: Some(format!("{e}")),
                    });
                }
            }
        }
        Ok(BulkRevokeResponse {
            newly_revoked: newly,
            already_revoked: already,
            failed,
            results,
        })
    }

    // --------------------- extend ---------------------

    pub async fn extend(&self, req: ExtendRequest) -> Result<TokenResponse> {
        let v = permissive_validation();
        let decoded = self
            .signer
            .verify::<StandardClaims>(&req.token, &v)
            .map_err(|e| {
                tracing::debug!(error = %e, "extend: token decode failed");
                TimError::BadRequest("token signature invalid; cannot extend".into())
            })?;
        let old = decoded.claims;
        let now = Utc::now();
        if old.exp < now.timestamp() {
            return Err(TimError::Unprocessable("token already expired".into()));
        }
        let old_jti = Uuid::parse_str(&old.jti)
            .map_err(|_| TimError::BadRequest("token jti is not a UUID".into()))?;
        if self.is_denylisted(old_jti).await? {
            return Err(TimError::Unprocessable("token already revoked".into()));
        }

        // Ancestor chain root.
        let (original_jwt_uuid, prev_row_id, jwt_name) = {
            let row: Option<(Uuid, Uuid, Option<String>)> = sqlx::query_as(
                r#"
                SELECT original_jwt_uuid, id, jwt_name
                  FROM custom_jwt.jwt_metadata
                 WHERE jwt_uuid = $1
                 ORDER BY created_at DESC
                 LIMIT 1
                "#,
            )
            .bind(old_jti)
            .fetch_optional(&self.pool)
            .await?;
            match row {
                Some((orig, id, name)) => (orig, Some(id), name),
                None => (old_jti, None, None),
            }
        };

        // Finding 18: JVM defaults to 60 minutes when the caller
        // omits expirationInMinutes.
        let exp_minutes = req.expiration_in_minutes.unwrap_or(60);
        if exp_minutes <= 0 {
            return Err(TimError::BadRequest(
                "expirationInMinutes must be > 0".into(),
            ));
        }
        let new_exp = now + Duration::minutes(exp_minutes);
        let new_jti = Uuid::new_v4();
        let mut new_extra = old.extra.clone();
        // Finding 17: ensure extended tokens carry token_type even if
        // the ancestor pre-dated that behaviour.
        new_extra
            .entry("token_type".into())
            .or_insert_with(|| Value::String("custom_jwt".into()));
        let new_claims = StandardClaims {
            iss: self.cfg.issuer.clone(),
            sub: old.sub.clone(),
            aud: old.aud.clone(),
            exp: new_exp.timestamp(),
            iat: now.timestamp(),
            jti: new_jti.to_string(),
            extra: new_extra,
        };
        let new_token = self.signer.sign(&new_claims)?;

        // Finding 19: use the *signed* extra set (new_claims.extra),
        // which mirrors what generate stores.
        let claim_keys = new_claims
            .extra
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(",");
        let aud_str = old.aud.as_ref().map(|v| v.join(",")).unwrap_or_default();

        let mut tx = self.pool.begin().await?;
        sqlx::query(
            r#"
            INSERT INTO custom_jwt.jwt_metadata
                (id, jwt_uuid, claim_keys, issued_at, expires_at,
                 subject, jwt_name, audience, issuer,
                 supersedes, original_jwt_uuid)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(new_jti)
        .bind(&claim_keys)
        .bind(now)
        .bind(new_exp)
        .bind(old.sub.as_deref())
        .bind(jwt_name.as_deref())
        .bind(&aud_str)
        .bind(&self.cfg.issuer)
        .bind(prev_row_id)
        .bind(original_jwt_uuid)
        .execute(&mut *tx)
        .await?;

        let old_exp = DateTime::<Utc>::from_timestamp(old.exp, 0)
            .ok_or_else(|| TimError::BadRequest("old exp out of range".into()))?;
        sqlx::query(
            r#"
            INSERT INTO custom_jwt.denylist (jwt_uuid, expires_at, reason)
            VALUES ($1, $2, $3)
            ON CONFLICT (jwt_uuid) DO NOTHING
            "#,
        )
        .bind(old_jti)
        .bind(old_exp)
        .bind(Some("superseded_by_extend"))
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(TokenResponse {
            // Finding 16: JVM uses "extended" status + literal
            // "EXTENDED_TOKEN" jwt_name for callers keying off this.
            status: "extended".into(),
            jwt_name: jwt_name.unwrap_or_else(|| "EXTENDED_TOKEN".to_string()),
            token: new_token,
            expires_at: new_exp,
        })
    }

    // --------------------- list ---------------------

    pub async fn list_for_subject(&self, subject: &str, req: ListRequest) -> Result<ListResponse> {
        // Finding 14: JVM defaults are page=0, size=20; cap size at
        // 200. Row-based callers can opt in via by_row=true.
        let size = req.limit.unwrap_or(20).clamp(1, 200);
        let (page, row_offset) = if req.by_row {
            let off = req.offset.unwrap_or(0).max(0);
            (off / size, off)
        } else {
            let p = req.offset.unwrap_or(0).max(0);
            (p, p * size)
        };

        type TokenRow = (
            Uuid,
            Option<String>,
            Option<String>,
            DateTime<Utc>,
            DateTime<Utc>,
            Option<String>,
            Option<String>,
        );
        let rows: Vec<TokenRow> = sqlx::query_as(
            r#"
            SELECT jwt_uuid, subject, jwt_name, issued_at, expires_at, issuer, audience
              FROM custom_jwt.jwt_metadata
             WHERE subject = $1
               AND ($2::timestamptz IS NULL OR issued_at >= $2)
               AND ($3::timestamptz IS NULL OR issued_at <= $3)
               AND ($4::timestamptz IS NULL OR expires_at >= $4)
               AND ($5::timestamptz IS NULL OR expires_at <= $5)
               AND ($6::text IS NULL OR jwt_name = $6)
             ORDER BY issued_at DESC
             LIMIT $7 OFFSET $8
            "#,
        )
        .bind(subject)
        .bind(req.issued_after)
        .bind(req.issued_before)
        .bind(req.expires_after)
        .bind(req.expires_before)
        .bind(req.jwt_name.as_deref())
        .bind(size)
        .bind(row_offset)
        .fetch_all(&self.pool)
        .await?;

        let (total,): (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)
              FROM custom_jwt.jwt_metadata
             WHERE subject = $1
               AND ($2::timestamptz IS NULL OR issued_at >= $2)
               AND ($3::timestamptz IS NULL OR issued_at <= $3)
               AND ($4::timestamptz IS NULL OR expires_at >= $4)
               AND ($5::timestamptz IS NULL OR expires_at <= $5)
               AND ($6::text IS NULL OR jwt_name = $6)
            "#,
        )
        .bind(subject)
        .bind(req.issued_after)
        .bind(req.issued_before)
        .bind(req.expires_after)
        .bind(req.expires_before)
        .bind(req.jwt_name.as_deref())
        .fetch_one(&self.pool)
        .await?;

        let now = Utc::now();
        let mut tokens = Vec::with_capacity(rows.len());
        for (jti, sub, name, iat, exp, iss, aud) in rows {
            let (revoked_at, revocation_reason) = self.denylist_entry(jti).await?;
            let status = if revoked_at.is_some() {
                "revoked"
            } else if exp < now {
                "expired"
            } else {
                "active"
            }
            .to_string();
            tokens.push(TokenSummary {
                jti: jti.to_string(),
                subject: sub,
                jwt_name: name,
                issued_at: iat,
                expires_at: exp,
                issuer: iss,
                audience: aud,
                status,
                revoked_at,
                revocation_reason,
            });
        }

        let total_pages = if size == 0 {
            0
        } else {
            (total + size - 1) / size
        };
        Ok(ListResponse {
            tokens,
            pagination: Pagination {
                total,
                offset: row_offset,
                limit: size,
                page,
                size,
                total_pages,
            },
        })
    }

    async fn denylist_entry(&self, jti: Uuid) -> Result<(Option<DateTime<Utc>>, Option<String>)> {
        let row: Option<(DateTime<Utc>, Option<String>)> = sqlx::query_as(
            "SELECT denylisted_at, reason FROM custom_jwt.denylist WHERE jwt_uuid = $1",
        )
        .bind(jti)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some((t, r)) => (Some(t), r),
            None => (None, None),
        })
    }
}

/// Registered JWT claim names (RFC 7519 §4.1). We never let these
/// appear in `#[serde(flatten)] extra` because that would produce
/// a duplicate field alongside the explicitly-typed member and
/// jsonwebtoken's decode would reject the token as malformed.
const RESERVED_CLAIM_NAMES: &[&str] = &["iss", "sub", "aud", "exp", "iat", "jti", "nbf"];

fn strip_reserved(mut map: BTreeMap<String, Value>) -> BTreeMap<String, Value> {
    for k in RESERVED_CLAIM_NAMES {
        map.remove(*k);
    }
    map
}

/// Validation config for internal decode passes where we want to
/// inspect claims without enforcing exp / aud / iss (those are
/// applied by the caller once claims are inspected).
fn permissive_validation() -> Validation {
    let mut v = Validation::new(Algorithm::RS256);
    v.validate_exp = false;
    v.validate_aud = false;
    v.required_spec_claims.clear();
    v
}

fn response_from(
    claims: &StandardClaims,
    valid: bool,
    active: bool,
    reason: &str,
) -> ValidateResponse {
    ValidateResponse {
        valid,
        active,
        reason: Some(reason.into()),
        subject: claims.sub.clone(),
        issuer: Some(claims.iss.clone()),
        audience: claims.aud.clone(),
        expires_at: DateTime::<Utc>::from_timestamp(claims.exp, 0),
        issued_at: DateTime::<Utc>::from_timestamp(claims.iat, 0),
        jwt_id: Some(claims.jti.clone()),
        claims: Some(claims.extra.clone()),
    }
}

fn response_from_valid(claims: &StandardClaims) -> ValidateResponse {
    ValidateResponse {
        valid: true,
        active: true,
        reason: None,
        subject: claims.sub.clone(),
        issuer: Some(claims.iss.clone()),
        audience: claims.aud.clone(),
        expires_at: DateTime::<Utc>::from_timestamp(claims.exp, 0),
        issued_at: DateTime::<Utc>::from_timestamp(claims.iat, 0),
        jwt_id: Some(claims.jti.clone()),
        claims: Some(claims.extra.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::JwtSigner;

    const TEST_KEY: &str = include_str!("../../tests/fixtures/test-jwt-private.pem");

    fn signer() -> JwtSigner {
        JwtSigner::from_pkcs8_pem(TEST_KEY, "kid".into()).unwrap()
    }

    #[test]
    fn strip_reserved_removes_registered_names() {
        let mut m = BTreeMap::new();
        m.insert("sub".into(), Value::String("s".into()));
        m.insert("iat".into(), Value::Number(1.into()));
        m.insert("role".into(), Value::String("admin".into()));
        let out = strip_reserved(m);
        assert!(!out.contains_key("sub"));
        assert!(!out.contains_key("iat"));
        assert_eq!(out.get("role"), Some(&Value::String("admin".into())));
    }

    #[test]
    fn sign_and_decode_round_trip_with_standard_claims() {
        let s = signer();
        let now = Utc::now().timestamp();
        let claims = StandardClaims {
            iss: "TIM".into(),
            sub: Some("u".into()),
            aud: Some(vec!["a".into()]),
            exp: now + 60,
            iat: now,
            jti: Uuid::new_v4().to_string(),
            extra: BTreeMap::new(),
        };
        let token = s.sign(&claims).unwrap();
        let v = permissive_validation();
        let out = s.verify::<StandardClaims>(&token, &v).unwrap();
        assert_eq!(out.claims.sub.as_deref(), Some("u"));
    }
}
