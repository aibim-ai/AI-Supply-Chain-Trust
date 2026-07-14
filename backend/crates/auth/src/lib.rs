//! Scoped JWT and bearer token authentication — matches `auth.py`.

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Verifies a JWT with HS256 signature matching Python's `verify_scoped_jwt()`.
pub fn verify_jwt(
    token: &str,
    secret: &str,
    audience: &str,
    issuer: &str,
    required_scope: &str,
) -> Result<Claims, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("invalid token format".into());
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    // Verify signature
    let expected_sig = hs256_sign(format!("{header_b64}.{payload_b64}"), secret);
    if !constant_time_eq(signature_b64.as_bytes(), expected_sig.as_bytes()) {
        return Err("invalid signature".into());
    }

    // Decode payload
    let payload_json = b64_decode(payload_b64)?;
    let claims: Claims =
        serde_json::from_str(&payload_json).map_err(|e| format!("invalid payload: {e}"))?;

    // Verify expiration
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    if claims.exp < now {
        return Err("token expired".into());
    }

    // Verify audience
    if claims.aud.as_deref() != Some(audience)
        && !claims
            .aud
            .as_deref()
            .map(|a| a.contains(audience))
            .unwrap_or(false)
    {
        return Err("audience mismatch".into());
    }

    // Verify issuer
    if claims.iss.as_deref() != Some(issuer) {
        return Err("issuer mismatch".into());
    }

    // Verify scope
    if let Some(ref scopes) = claims.scopes {
        if !scopes.iter().any(|s| s == required_scope) {
            return Err(format!("missing scope: {required_scope}"));
        }
    } else {
        return Err("no scopes in token".into());
    }

    Ok(claims)
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Claims {
    pub sub: Option<String>,
    pub iss: Option<String>,
    pub aud: Option<String>,
    pub exp: i64,
    pub iat: Option<i64>,
    pub scopes: Option<Vec<String>>,
}

/// HS256: HMAC-SHA256(signing_input, secret)
fn hs256_sign(input: impl AsRef<str>, secret: impl AsRef<str>) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_ref().as_bytes()).expect("HMAC key");
    mac.update(input.as_ref().as_bytes());
    let result = mac.finalize();
    b64_encode(&result.into_bytes())
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn b64_decode(s: &str) -> Result<String, String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("base64 error: {e}"))?;
    String::from_utf8(bytes).map_err(|e| format!("utf8 error: {e}"))
}

fn b64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Verify Bearer token with SHA-256 digest (scheduler auth).
pub fn verify_bearer_token(token: &str, expected_digest: &str) -> bool {
    if token.is_empty() || expected_digest.is_empty() {
        return false;
    }
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    let digest = format!("{:x}", h.finalize());
    constant_time_eq(digest.as_bytes(), expected_digest.as_bytes())
}

pub fn extract_bearer(header: &str) -> Option<&str> {
    header.strip_prefix("Bearer ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_token_match() {
        let mut h = Sha256::new();
        h.update(b"test");
        let d = format!("{:x}", h.finalize());
        assert!(verify_bearer_token("test", &d));
        assert!(!verify_bearer_token("wrong", &d));
    }

    #[test]
    fn invalid_jwt_rejected() {
        assert!(verify_jwt("a.b.c", "secret", "aud", "iss", "scope").is_err());
    }

    #[test]
    fn extract_bearer_works() {
        assert_eq!(extract_bearer("Bearer abc123"), Some("abc123"));
        assert_eq!(extract_bearer("Basic xyz"), None);
    }
}
