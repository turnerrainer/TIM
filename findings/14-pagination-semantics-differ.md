# 14 — `POST /jwt/custom/list/me` pagination semantics differ from JVM

**Severity:** MEDIUM (API compatibility break)
**Area:** Custom JWT / API
**Files:**

- `src/jwt/service.rs:448-529` (Rust `list_for_subject`)
- `src/jwt/api.rs:106-133` (Rust request/response types)

## What happens

The Rust API keeps the field names `offset` and `limit` but changes
their meaning and defaults, and drops fields from the response.

| Field         | Java (`.../custom-jwt/.../service/CustomJwtService.java:166-168, 182-186`)                        | Rust (`src/jwt/service.rs:449-450, 521-529`) |
|---------------|----------------------------------------------------------------------------------------------------|-----------------------------------------------|
| `offset`      | **PAGE number** (0-based). `PageRequest.of(page, size)`.                                          | **ROW offset** (0-based).                     |
| `limit`       | **Page size**, default **20**.                                                                     | **Row count**, default **50**.                |
| resp `page`   | Present.                                                                                           | Absent.                                       |
| resp `size`   | Present.                                                                                           | Renamed to `limit`.                           |
| resp `totalPages` | Present.                                                                                       | Absent.                                       |

A Java client sending `{"offset": 2, "limit": 20}` expects rows 40-59
(third page of 20). The Rust server returns rows 2-21. Silent data
skew.

Additionally, the Java version accepts `jwtName` as a filter (via
`findByUserFilters`) though Java's `listUserTokens` calls
`findBySubject` and drops the filter — a Java bug. Rust implements
date filters correctly but does not accept `jwtName` at all.

## Reference — Buerostack Java TIM

Response shape (`app/custom-jwt/src/main/java/buerostack/jwt/api/JwtListResponse.java`
via `PaginationInfo`):

```json
{
  "tokens": [...],
  "pagination": {
    "total": 42,
    "page": 1,
    "size": 20,
    "totalPages": 3
  }
}
```

Rust response:

```json
{
  "tokens": [...],
  "pagination": {
    "total": 42,
    "offset": 20,
    "limit": 20
  }
}
```

## Impact

- Any client that pages through more than one screen of results now
  returns duplicates on page 2 (rows 1-50 vs rows 50-99 vs
  rows 100-149 in Rust semantics; Java caller passing `offset: 1`
  gets rows 20-39 in Java, rows 1-50 in Rust).
- Frontend that consumed `pagination.totalPages` breaks silently
  (JavaScript `undefined` compared as `> 0` returns `false` → "no
  more pages").
- No migration note in `CHANGELOG.md`.
