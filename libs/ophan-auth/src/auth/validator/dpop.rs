use std::sync::atomic::{AtomicU64, Ordering};

use ahash::AHashMap;
use dashmap::{DashMap, mapref::entry::Entry};
use jsonwebtoken::{Algorithm, AlgorithmFamily, DecodingKey, Validation, decode, decode_header, jwk::ThumbprintHash};
use sha2::{Digest, Sha256};

use crate::{
    auth::{CnfClaim, DPoPRequestContext, DpopProofClaims},
    error::{DpopError, Error},
    serialization::{b64_encode, get_current_timestamp},
};

const MAX_PROOF_AGE_SECS: u64 = 300;

/// Default number of proof identifiers remembered for replay detection.
const DEFAULT_REPLAY_CAPACITY: usize = 1 << 20;

/// Interval between sweeps of expired proof identifiers.
const REPLAY_SWEEP_INTERVAL_SECS: u64 = 10;

const PROOF_ALGORITHMS: [Algorithm; 9] = [
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::EdDSA,
];

#[inline]
fn is_fresh(iat: usize, now: u64) -> bool {
    let issued_at = u64::try_from(iat).unwrap_or(u64::MAX);
    issued_at <= now.saturating_add(MAX_PROOF_AGE_SECS) && now.saturating_sub(issued_at) <= MAX_PROOF_AGE_SECS
}

#[inline]
fn constant_time_eq(left: &str, right: &str) -> bool {
    let mut difference = left.len() ^ right.len();
    for (a, b) in left.bytes().zip(right.bytes()) {
        difference |= usize::from(a ^ b);
    }
    difference == 0
}

/// Splits an authority into host and optional port. Userinfo is rejected.
fn split_authority(authority: &str) -> Option<(&str, Option<u16>)> {
    if authority.is_empty() || authority.contains('@') {
        return None;
    }

    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']')?;
        let (host, rest) = authority.split_at(end + 1);
        match rest {
            "" => (host, None),
            rest => (host, Some(rest.strip_prefix(':')?)),
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };

    let port = match port {
        None | Some("") => None,
        Some(port) => Some(port.parse().ok()?),
    };

    (!host.is_empty()).then_some((host, port))
}

fn effective_port(scheme: &str, port: Option<u16>) -> Option<u16> {
    port.or_else(|| {
        if scheme.eq_ignore_ascii_case("https") {
            Some(443)
        } else if scheme.eq_ignore_ascii_case("http") {
            Some(80)
        } else {
            None
        }
    })
}

#[inline]
fn strip_query_and_fragment(value: &str) -> &str {
    value.find(['?', '#']).map_or(value, |end| &value[..end])
}

#[inline]
fn normalize_path(path: &str) -> &str {
    if path.is_empty() { "/" } else { path }
}

/// RFC 9449 §4.3: compares the proof's `htu` with the request URI, ignoring
/// query and fragment, with the scheme and host compared case-insensitively
/// and default ports elided (RFC 3986 §6.2.2-6.2.3).
fn htu_matches(htu: &str, ctx: &DPoPRequestContext) -> bool {
    let htu = strip_query_and_fragment(htu);
    let Some((scheme, rest)) = htu.split_once("://") else {
        return false;
    };
    let (authority, path) = rest.find('/').map_or((rest, ""), |start| rest.split_at(start));

    let (Some((proof_host, proof_port)), Some((request_host, request_port))) =
        (split_authority(authority), split_authority(ctx.authority))
    else {
        return false;
    };

    scheme.eq_ignore_ascii_case(ctx.scheme)
        && proof_host.eq_ignore_ascii_case(request_host)
        && effective_port(scheme, proof_port) == effective_port(ctx.scheme, request_port)
        && normalize_path(path) == normalize_path(strip_query_and_fragment(ctx.path))
}

/// Bounded record of recently accepted proof identifiers.
///
/// Entries live until their proof can no longer pass the `iat` freshness
/// check. When the record is full of live entries new proofs are refused
/// rather than risking an undetected replay.
struct ReplayCache {
    seen: DashMap<u128, u64>,
    capacity: usize,
    last_sweep: AtomicU64,
}

impl ReplayCache {
    fn new(capacity: usize) -> Self {
        Self {
            seen: DashMap::new(),
            capacity,
            last_sweep: AtomicU64::new(0),
        }
    }

    fn key(jkt: &str, jti: &str) -> u128 {
        let digest = Sha256::new().chain_update(jkt).chain_update([0]).chain_update(jti).finalize();
        let mut key = [0u8; 16];
        key.copy_from_slice(&digest[..16]);
        u128::from_le_bytes(key)
    }

    fn sweep(&self, now: u64, full: bool) {
        let last = self.last_sweep.load(Ordering::Relaxed);
        let due = now >= last.saturating_add(REPLAY_SWEEP_INTERVAL_SECS) || (full && now > last);
        if due && self.last_sweep.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
            self.seen.retain(|_, expires_at| *expires_at > now);
        }
    }

    /// Records the proof, failing if it was already seen and is still live.
    fn insert(&self, key: u128, expires_at: u64, now: u64) -> Result<(), DpopError> {
        let full = self.seen.len() >= self.capacity;
        self.sweep(now, full);
        if full && self.seen.len() >= self.capacity {
            return Err(DpopError::ReplayCacheFull);
        }

        match self.seen.entry(key) {
            Entry::Occupied(entry) if *entry.get() > now => Err(DpopError::Replayed),
            Entry::Occupied(mut entry) => {
                entry.insert(expires_at);
                Ok(())
            },
            Entry::Vacant(entry) => {
                entry.insert(expires_at);
                Ok(())
            },
        }
    }
}

/// The DPoP Validator
/// RFC 9449
pub struct DpopValidator {
    validations: AHashMap<Algorithm, Validation>,
    replay: ReplayCache,
}

impl Default for DpopValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl DpopValidator {
    pub fn new() -> Self {
        Self::with_replay_capacity(DEFAULT_REPLAY_CAPACITY)
    }

    /// Creates a validator remembering at most `capacity` live proof
    /// identifiers for replay detection.
    pub fn with_replay_capacity(capacity: usize) -> Self {
        let validations = PROOF_ALGORITHMS
            .into_iter()
            .map(|algorithm| {
                let mut validation = Validation::new(algorithm);
                validation.validate_exp = false;
                validation.validate_aud = false;

                // These claims are required by the DPoP proof format and are
                // validated against the current HTTP request below.
                validation.required_spec_claims = ["jti", "htm", "htu", "iat"].into_iter().map(String::from).collect();
                (algorithm, validation)
            })
            .collect();

        Self { validations, replay: ReplayCache::new(capacity.max(1)) }
    }

    pub fn validate(&self, dpop_proof: &str, access_token: &str, cnf: &CnfClaim, ctx: DPoPRequestContext) -> Result<(), Error> {
        let header = decode_header(dpop_proof)?;

        // DPoP proof typ must be "dpop+jwt".
        if header.typ.as_deref() != Some("dpop+jwt") {
            return Err(Error::Dpop(DpopError::InvalidType));
        }

        // DPoP requires an asymmetric signature verified against the public JWK
        match header.alg.family() {
            AlgorithmFamily::Ec | AlgorithmFamily::Rsa | AlgorithmFamily::Ed => {},
            _ => return Err(Error::Dpop(DpopError::InvalidFormat)),
        }

        let validation = self.validations.get(&header.alg).ok_or(Error::Dpop(DpopError::InvalidFormat))?;
        let jwk = header.jwk.as_ref().ok_or(Error::Dpop(DpopError::InvalidFormat))?;

        let client_public_key = DecodingKey::from_jwk(jwk)?;

        let decoded = decode::<DpopProofClaims>(dpop_proof, &client_public_key, validation)?;
        let proof_claims = decoded.claims;

        let now = get_current_timestamp().as_secs();

        // DPoP proofs are short-lived to limit the window in which a stolen proof
        // can be replayed. Clock skew is tolerated within the same window.
        if !is_fresh(proof_claims.iat, now) {
            return Err(Error::Dpop(DpopError::InvalidFormat));
        }

        // Validate JWK Thumbprint matches the token's cnf.jkt.
        let actual_jkt = jwk.thumbprint(ThumbprintHash::SHA256)?;
        if !constant_time_eq(&cnf.jkt, &actual_jkt) {
            return Err(Error::Dpop(DpopError::ThumbprintMismatch));
        }

        // htm (HTTP Method) comparison must be case-sensitive.
        if proof_claims.htm != ctx.method {
            return Err(Error::Dpop(DpopError::HtmMismatch));
        }

        if !htu_matches(&proof_claims.htu, &ctx) {
            return Err(Error::Dpop(DpopError::HtuMismatch));
        }

        // If the server provided a DPoP-Nonce, the proof must include it.
        if let Some(expected_nonce) = ctx.nonce {
            match &proof_claims.nonce {
                Some(proof_nonce) if proof_nonce == expected_nonce => {},
                _ => return Err(Error::Dpop(DpopError::NonceMismatch)),
            }
        }

        // ath must be present and match the SHA-256 hash of the access token.
        let actual_ath = b64_encode(Sha256::digest(access_token.as_bytes()));
        if !constant_time_eq(&proof_claims.ath, &actual_ath) {
            return Err(Error::Dpop(DpopError::AthMismatch));
        }

        // Only fully verified proofs are recorded, so unsigned or mismatching
        // proofs cannot fill the replay record.
        let issued_at = u64::try_from(proof_claims.iat).unwrap_or(u64::MAX);
        let expires_at = issued_at.saturating_add(MAX_PROOF_AGE_SECS).saturating_add(1);
        self.replay
            .insert(ReplayCache::key(&actual_jkt, &proof_claims.jti), expires_at, now)
            .map_err(Error::Dpop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, jwk::Jwk};
    use p256::{ecdsa::SigningKey, pkcs8::EncodePrivateKey};
    use rand::thread_rng;
    use serde_json::json;

    const ACCESS_TOKEN: &str = "access-token";

    fn ctx<'a>(scheme: &'a str, authority: &'a str, path: &'a str) -> DPoPRequestContext<'a> {
        DPoPRequestContext {
            method: "GET",
            scheme,
            authority,
            path,
            nonce: None,
            dpop_proof: None,
        }
    }

    struct ProofKey {
        encoding: EncodingKey,
        jwk: Jwk,
        jkt: String,
    }

    fn proof_key() -> ProofKey {
        let signing_key = SigningKey::random(&mut thread_rng());
        let point = signing_key.verifying_key().to_encoded_point(false);
        let jwk: Jwk = serde_json::from_value(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": b64_encode(point.x().unwrap()),
            "y": b64_encode(point.y().unwrap()),
        }))
        .unwrap();
        let jkt = jwk.thumbprint(ThumbprintHash::SHA256).unwrap();
        let encoding = EncodingKey::from_ec_der(signing_key.to_pkcs8_der().unwrap().as_bytes());
        ProofKey { encoding, jwk, jkt }
    }

    fn proof(key: &ProofKey, jti: &str, htu: &str) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("dpop+jwt".into());
        header.jwk = Some(key.jwk.clone());
        let claims = DpopProofClaims {
            jti: jti.into(),
            htm: "GET".into(),
            htu: htu.into(),
            iat: get_current_timestamp().as_secs() as usize,
            ath: b64_encode(Sha256::digest(ACCESS_TOKEN.as_bytes())),
            nonce: None,
        };
        jsonwebtoken::encode(&header, &claims, &key.encoding).unwrap()
    }

    #[test]
    fn proof_iat_accepts_clock_skew_window() {
        assert!(is_fresh(1_000, 1_000));
        assert!(is_fresh(700, 1_000));
        assert!(is_fresh(1_300, 1_000));
    }

    #[test]
    fn proof_iat_rejects_stale_and_future_proofs() {
        assert!(!is_fresh(699, 1_000));
        assert!(!is_fresh(1_301, 1_000));
    }

    #[test]
    fn htu_is_compared_as_absolute_uri() {
        let request = ctx("https", "api.example.com", "/resource");
        assert!(htu_matches("https://api.example.com/resource", &request));
        assert!(htu_matches("HTTPS://API.Example.COM/resource", &request));
        assert!(htu_matches("https://api.example.com:443/resource", &request));
        assert!(htu_matches("https://api.example.com/resource?x=1#frag", &request));

        assert!(!htu_matches("/resource", &request));
        assert!(!htu_matches("http://api.example.com/resource", &request));
        assert!(!htu_matches("https://evil.example.com/resource", &request));
        assert!(!htu_matches("https://api.example.com:8443/resource", &request));
        assert!(!htu_matches("https://api.example.com/Resource", &request));
        assert!(!htu_matches("https://user@api.example.com/resource", &request));
    }

    #[test]
    fn htu_normalizes_request_authority_and_path() {
        assert!(htu_matches("http://localhost/", &ctx("http", "LOCALHOST:80", "")));
        assert!(htu_matches(
            "https://api.example.com:8443/a",
            &ctx("https", "api.example.com:8443", "/a?q=1")
        ));
        assert!(htu_matches("https://[::1]/a", &ctx("https", "[::1]:443", "/a")));
        assert!(!htu_matches("https://[::1]/a", &ctx("https", "[::2]", "/a")));
    }

    #[test]
    fn validates_proof_and_rejects_replayed_jti() {
        let validator = DpopValidator::new();
        let key = proof_key();
        let cnf = CnfClaim { jkt: key.jkt.clone() };
        let request = || ctx("https", "api.example.com", "/resource");

        let first = proof(&key, "jti-1", "https://api.example.com/resource");
        validator.validate(&first, ACCESS_TOKEN, &cnf, request()).expect("fresh proof must be accepted");

        let replay = validator.validate(&first, ACCESS_TOKEN, &cnf, request());
        assert!(matches!(replay, Err(Error::Dpop(DpopError::Replayed))));

        let second = proof(&key, "jti-2", "https://api.example.com/resource");
        assert!(validator.validate(&second, ACCESS_TOKEN, &cnf, request()).is_ok());
    }

    #[test]
    fn rejected_proofs_are_not_recorded() {
        let validator = DpopValidator::new();
        let key = proof_key();
        let cnf = CnfClaim { jkt: key.jkt.clone() };

        let proof = proof(&key, "jti-1", "https://api.example.com/resource");
        let mismatch = validator.validate(&proof, ACCESS_TOKEN, &cnf, ctx("https", "api.example.com", "/other"));
        assert!(matches!(mismatch, Err(Error::Dpop(DpopError::HtuMismatch))));

        assert!(validator.validate(&proof, ACCESS_TOKEN, &cnf, ctx("https", "api.example.com", "/resource")).is_ok());
    }

    #[test]
    fn replay_cache_refuses_new_proofs_when_full_of_live_entries() {
        let cache = ReplayCache::new(2);
        assert!(cache.insert(1, 100, 10).is_ok());
        assert!(cache.insert(2, 100, 10).is_ok());
        assert!(matches!(cache.insert(3, 100, 10), Err(DpopError::ReplayCacheFull)));

        assert!(cache.insert(3, 200, 150).is_ok());
        assert!(matches!(cache.insert(3, 200, 151), Err(DpopError::Replayed)));
    }
}
