//! What the NIFs do, in plain Rust.
//!
//! Nothing here knows about the BEAM: the functions take and give ordinary
//! values, so `cargo test` can hold them to account without a VM. The NIFs in
//! `ojak-nif` only turn terms into these values and results back into terms.
//! They are apart because a library that calls `enif_*` cannot be linked into
//! a test binary: the VM provides those.
//!
//! Like the crates under it, this does no I/O. It never reads the clock: the
//! time is an argument. The one thing it asks the system for is the
//! randomness a new key is made from.

use ojak_jsonld::{ContextCache, Limits, ProcessedContext, Registry};
use ojak_sig::integrity::{self, PublicKey};
use ojak_sig::rfc9421;
use ojak_sig::signature::{self, PrivateKey};
use ojak_sig::verification::{self, Key, Policy, PublishedKey, Request, Signature};
use ojak_sig::{did, digest, linked_data};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

/// Why a call did not succeed, as a term the Elixir side can match on:
/// `:kind` when there is nothing to add, `{:kind, "text"}` or `{:kind, 12}`
/// when there is.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Failure {
    pub kind: &'static str,
    pub detail: Detail,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Detail {
    None,
    Text(String),
    Int(i64),
}

pub type Outcome<T> = Result<T, Failure>;

impl Failure {
    pub fn new(kind: &'static str, detail: Detail) -> Self {
        Self { kind, detail }
    }

    /// An argument that cannot be what it has to be, such as a header that is
    /// not UTF-8.
    pub fn argument(text: impl Into<String>) -> Self {
        Self::new("invalid_argument", Detail::Text(text.into()))
    }
}

impl From<ojak_sig::Error> for Failure {
    fn from(error: ojak_sig::Error) -> Self {
        use ojak_sig::Error as E;
        match error {
            E::Key(why) => Self::new("key", Detail::Text(why)),
            E::Malformed(why) => Self::new("malformed", Detail::Text(why)),
            E::Missing(what) => Self::new("missing", Detail::Text(what)),
            E::Unsupported(what) => Self::new("unsupported", Detail::Text(what)),
            E::WrongKey(why) => Self::new("wrong_key", Detail::Text(why)),
            E::DigestMismatch => Self::new("digest_mismatch", Detail::None),
            E::Invalid => Self::new("invalid", Detail::None),
            // A reason a later ojak-sig adds: still an error, with its words.
            other => Self::new("error", Detail::Text(other.to_string())),
        }
    }
}

impl From<verification::Rejection> for Failure {
    fn from(rejection: verification::Rejection) -> Self {
        use verification::Rejection as R;
        match rejection {
            R::Unsigned => Self::new("unsigned", Detail::None),
            R::Malformed(why) => Self::new("malformed", Detail::Text(why)),
            R::NotCovered(what) => Self::new("not_covered", Detail::Text(what)),
            R::MissingHeader(name) => Self::new("missing_header", Detail::Text(name.into())),
            R::DigestMismatch => Self::new("digest_mismatch", Detail::None),
            R::Stale { seconds } => Self::new("stale", Detail::Int(seconds)),
            R::Expired { seconds } => Self::new("expired", Detail::Int(seconds)),
            R::WrongHost(host) => Self::new("wrong_host", Detail::Text(host)),
            R::Invalid(why) => Self::new("invalid", Detail::Text(why)),
        }
    }
}

impl From<ojak_jsonld::Error> for Failure {
    fn from(error: ojak_jsonld::Error) -> Self {
        Self::new("jsonld", Detail::Text(error.to_string()))
    }
}

// ---------------------------------------------------------------- keys ----

/// A new 2048-bit RSA key pair: the private key as PKCS#8 PEM, the public key
/// as SPKI PEM.
pub fn rsa_generate_keypair() -> Outcome<(String, String)> {
    Ok(signature::generate_rsa_keypair(&mut system_rng())?)
}

/// An RSA private key, parsed once. Parsing costs more than signing, so the
/// Elixir side keeps what this returns.
pub fn rsa_private_key(pem: &str) -> Outcome<PrivateKey> {
    Ok(PrivateKey::from_pem(pem)?)
}

pub fn ed25519_generate_seed() -> [u8; 32] {
    integrity::generate_ed25519_seed(&mut system_rng())
}

pub fn ed25519_public_key(seed: &[u8; 32]) -> [u8; 32] {
    integrity::ed25519_public_key(seed)
}

pub fn ed25519_multikey_encode(public_key: &[u8; 32]) -> String {
    integrity::encode_ed25519_multikey(public_key)
}

/// The key a Multikey carries: `("ed25519", 32 bytes)` or `("mldsa44", 1312
/// bytes)`.
pub fn multikey_decode(multibase: &str) -> Outcome<(&'static str, Vec<u8>)> {
    Ok(match integrity::decode_multikey(multibase)? {
        PublicKey::Ed25519(bytes) => ("ed25519", bytes.to_vec()),
        PublicKey::MlDsa44(bytes) => ("mldsa44", bytes.into_vec()),
    })
}

pub fn did_key(public_key: &[u8; 32]) -> String {
    did::did_key(public_key)
}

fn system_rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
    rand_core::UnwrapErr(getrandom::SysRng)
}

// ------------------------------------------------------------- signing ----

/// A request as it arrived. Header names are lower-cased here, so the Elixir
/// side need not.
pub struct RequestParts<'a> {
    method: &'a str,
    path_and_query: &'a str,
    headers: Vec<(String, &'a str)>,
    body: &'a [u8],
}

impl<'a> RequestParts<'a> {
    pub fn new(
        method: &'a str,
        path_and_query: &'a str,
        headers: impl IntoIterator<Item = (&'a str, &'a str)>,
        body: &'a [u8],
    ) -> Self {
        Self {
            method,
            path_and_query,
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.to_ascii_lowercase(), value))
                .collect(),
            body,
        }
    }

    fn with<R>(&self, then: impl FnOnce(&Request<'_>) -> R) -> R {
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), *value))
            .collect();
        then(&Request {
            method: self.method,
            path_and_query: self.path_and_query,
            headers: &headers,
            body: self.body,
        })
    }
}

/// The headers draft-cavage signing gives: `(signature, date, digest)`.
pub fn sign_draft_cavage(
    method: &str,
    url: &str,
    body: &[u8],
    key_id: &str,
    key: &PrivateKey,
    extra_headers: &[(&str, &str)],
    now: i64,
) -> Outcome<(String, String, String)> {
    let signed =
        signature::sign_request_with_key(method, url, body, key_id, key, extra_headers, now)?;
    Ok((signed.signature, signed.date, signed.digest))
}

/// The key an RFC 9421 signature is made with.
pub enum SigningKeyIn<'a> {
    Rsa(&'a PrivateKey),
    Ed25519(&'a [u8; 32]),
}

/// The headers RFC 9421 signing gives: `(signature_input, signature,
/// content_digest)`; there is a digest when there is a body.
pub fn sign_rfc9421(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    key_id: &str,
    key: &SigningKeyIn<'_>,
    now: i64,
) -> Outcome<(String, String, Option<String>)> {
    let key = match key {
        SigningKeyIn::Rsa(key) => rfc9421::SigningKey::Rsa(key),
        SigningKeyIn::Ed25519(seed) => rfc9421::SigningKey::Ed25519(seed),
    };
    let signed = rfc9421::sign_request(method, url, body, key_id, &key, now)?;
    Ok((
        signed.signature_input,
        signed.signature,
        signed.content_digest,
    ))
}

pub fn digest_matches(header: &str, body: &[u8]) -> bool {
    digest::digest_matches(header, body)
}

pub fn content_digest_matches(header: &str, body: &[u8]) -> bool {
    digest::content_digest_matches(header, body)
}

pub fn content_digest(body: &[u8]) -> String {
    rfc9421::content_digest(body)
}

// -------------------------------------------------------- verification ----

/// What a signature says about itself, before anyone has trusted it.
pub struct SignatureInfo {
    pub scheme: &'static str,
    pub key_id: String,
    pub covered: Vec<String>,
    pub created: Option<i64>,
    pub expires: Option<i64>,
}

/// Step one: read the signature on a request.
pub fn signature_parse(request: &RequestParts<'_>) -> Outcome<(Signature, SignatureInfo)> {
    let signature = request.with(verification::parse)?;
    let info = SignatureInfo {
        scheme: match signature.scheme {
            verification::Scheme::DraftCavage => "draft_cavage",
            verification::Scheme::Rfc9421 => "rfc9421",
        },
        key_id: signature.key_id.clone(),
        covered: signature.covered.clone(),
        created: signature.created,
        expires: signature.expires,
    };
    Ok((signature, info))
}

/// Step two: hold a signature to the policy, before its key is fetched.
pub fn signature_check(
    signature: &Signature,
    request: &RequestParts<'_>,
    hosts: &[&str],
    max_skew_seconds: i64,
    now: i64,
) -> Outcome<()> {
    let policy = Policy {
        hosts,
        max_skew_seconds,
    };
    request.with(|request| verification::check(signature, request, &policy, now))?;
    Ok(())
}

/// The key a signature is checked against.
pub enum VerifyKeyIn<'a> {
    RsaPem(&'a str),
    Ed25519(&'a [u8; 32]),
}

/// Step three: check a signature against a key the caller found.
pub fn signature_verify(
    signature: &Signature,
    request: &RequestParts<'_>,
    key: &VerifyKeyIn<'_>,
) -> Outcome<()> {
    let key = match key {
        VerifyKeyIn::RsaPem(pem) => Key::RsaPem(pem),
        VerifyKeyIn::Ed25519(bytes) => Key::Ed25519(bytes),
    };
    request.with(|request| verification::verify(signature, request, key))?;
    Ok(())
}

pub fn key_owner(key_id: &str) -> &str {
    verification::key_owner(key_id)
}

/// The key `actor` publishes under `key_id`, if it does: the other half of the
/// claim a key ID makes.
pub fn published_key(actor: &Value, key_id: &str) -> Option<PublishedKey> {
    verification::published_key(actor, key_id)
}

// ----------------------------------------------------------- integrity ----

/// A proof an object carries, and what is needed to find its key.
pub struct ProofInfo {
    pub proof: Map<String, Value>,
    pub cryptosuite: &'static str,
    pub verification_method: String,
}

/// Every usable integrity proof on `document` at `now`.
pub fn integrity_proofs(document: &Value, now: i64) -> Vec<ProofInfo> {
    integrity::integrity_proofs(document, now)
        .into_iter()
        .map(|(proof, suite, verification_method)| ProofInfo {
            proof,
            cryptosuite: suite.as_str(),
            verification_method,
        })
        .collect()
}

/// The key an integrity proof is checked against.
pub enum ProofKeyIn {
    Ed25519([u8; 32]),
    MlDsa44(Vec<u8>),
}

pub fn integrity_verify(
    document: &Value,
    proof: &Map<String, Value>,
    key: ProofKeyIn,
) -> Outcome<()> {
    let key = match key {
        ProofKeyIn::Ed25519(bytes) => PublicKey::Ed25519(Box::new(bytes)),
        ProofKeyIn::MlDsa44(bytes) => PublicKey::MlDsa44(bytes.into_boxed_slice()),
    };
    Ok(integrity::verify_object_integrity_proof(
        document, proof, &key,
    )?)
}

/// `document` with an `eddsa-jcs-2022` proof, and the Data Integrity context a
/// reader needs to find it.
pub fn integrity_sign(
    document: &Value,
    verification_method: &str,
    seed: &[u8; 32],
    now: i64,
) -> Outcome<Value> {
    let prepared = integrity::with_data_integrity_context(document.clone())
        .ok_or_else(|| Failure::argument("a document to sign is a JSON object"))?;
    Ok(integrity::sign_object_integrity_proof(
        &prepared,
        verification_method,
        seed,
        now,
    )?)
}

// -------------------------------------------------------------- JSON-LD ----

/// The most processed contexts a [`Jsonld`] keeps. Nearly every document a
/// server receives uses a few contexts, so this is plenty; a full cache is
/// emptied, not grown, so that senders cannot make it unbounded by inventing
/// contexts.
const CACHE_CAPACITY: usize = 256;

/// A registry of contexts, with the processed contexts it has been asked for.
///
/// The cache belongs to the registry because what a context means depends on
/// the contexts the registry holds; one registry's cache is never read by
/// another.
pub struct Jsonld {
    registry: Registry,
    cache: Contexts,
}

#[derive(Default)]
struct Contexts(Mutex<HashMap<String, Arc<ProcessedContext>>>);

impl ContextCache for Contexts {
    fn get(&self, key: &str) -> Option<Arc<ProcessedContext>> {
        // The map only ever holds finished values, so a panic elsewhere
        // cannot have left it half-written: a poisoned lock is safe to use.
        let map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        map.get(key).cloned()
    }

    fn put(&self, key: String, context: Arc<ProcessedContext>) {
        let mut map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if map.len() >= CACHE_CAPACITY && !map.contains_key(&key) {
            map.clear();
        }
        map.insert(key, context);
    }
}

impl Jsonld {
    /// The contexts ojak ships, and any of the caller's own: `(iri, document)`
    /// pairs, each document being what the IRI would have served.
    pub fn new(extra: impl IntoIterator<Item = (String, Value)>) -> Self {
        let registry = extra
            .into_iter()
            .fold(Registry::bundled(), |registry, (iri, document)| {
                registry.with(iri, document)
            });
        Self {
            registry,
            cache: Contexts::default(),
        }
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Every key becomes the IRI it stands for. Also the contexts that could
    /// not be resolved, which is not an error but worth logging.
    pub fn expand(&self, document: &Value) -> Outcome<(Value, Vec<String>)> {
        let processed = ojak_jsonld::expand(&self.registry, document)?;
        Ok(split(processed))
    }

    pub fn compact(&self, expanded: &Value, context: &Value) -> Outcome<(Value, Vec<String>)> {
        let processed = ojak_jsonld::compact(&self.registry, expanded, context)?;
        Ok(split(processed))
    }

    /// A document in ojak's own spelling, whatever aliases it arrived with.
    pub fn normalize(&self, document: &Value) -> Outcome<(Value, Vec<String>)> {
        let processed = ojak_jsonld::normalize_with_cache(
            &self.registry,
            document,
            Limits::default(),
            &self.cache,
        )?;
        Ok(split(processed))
    }
}

fn split(processed: ojak_jsonld::Processed) -> (Value, Vec<String>) {
    let unresolved = processed.unresolved_contexts().to_vec();
    (processed.into_document(), unresolved)
}

/// The `creator` of a Linked Data Signature, which says nothing about whether
/// it verifies.
pub fn linked_data_creator(document: &Value) -> Option<&str> {
    linked_data::creator(document)
}

pub fn linked_data_verify(
    jsonld: &Jsonld,
    document: &Value,
    public_key_pem: &str,
    now: i64,
) -> Outcome<()> {
    Ok(linked_data::verify(
        jsonld.registry(),
        document,
        public_key_pem,
        now,
    )?)
}

pub fn linked_data_sign(
    jsonld: &Jsonld,
    document: &Value,
    key_id: &str,
    key: &PrivateKey,
    created: i64,
    expires: i64,
) -> Outcome<Value> {
    Ok(linked_data::sign(
        jsonld.registry(),
        document,
        key_id,
        key,
        created,
        expires,
    )?)
}

/// `PublishedKey`, as terms the Elixir side reads.
pub enum Published {
    RsaPem(String),
    Ed25519([u8; 32]),
}

impl From<PublishedKey> for Published {
    fn from(key: PublishedKey) -> Self {
        match key {
            PublishedKey::RsaPem(pem) => Self::RsaPem(pem),
            PublishedKey::Ed25519(bytes) => Self::Ed25519(bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: i64 = 1_700_000_000;
    const URL: &str = "https://remote.example/users/bob/inbox";
    const KEY_ID: &str = "https://home.example/users/alice#main-key";

    #[test]
    fn a_signed_request_goes_through_all_three_steps() {
        let (private, public) = rsa_generate_keypair().unwrap();
        let key = rsa_private_key(&private).unwrap();
        let body = br#"{"type":"Follow"}"#;
        let (signature, date, digest) =
            sign_draft_cavage("POST", URL, body, KEY_ID, &key, &[], NOW).unwrap();

        let headers = [
            ("Host", "remote.example"),
            ("Signature", signature.as_str()),
            ("Date", date.as_str()),
            ("Digest", digest.as_str()),
        ];
        let request = RequestParts::new("POST", "/users/bob/inbox", headers, body);
        let (parsed, info) = signature_parse(&request).unwrap();
        assert_eq!(info.scheme, "draft_cavage");
        assert_eq!(info.key_id, KEY_ID);
        signature_check(&parsed, &request, &["remote.example"], 3600, NOW).unwrap();
        signature_verify(&parsed, &request, &VerifyKeyIn::RsaPem(&public)).unwrap();

        // The same signature, for a body it did not sign.
        let forged = RequestParts::new("POST", "/users/bob/inbox", headers, b"{}");
        let refused = signature_check(&parsed, &forged, &["remote.example"], 3600, NOW);
        assert_eq!(refused.unwrap_err().kind, "digest_mismatch");
    }

    #[test]
    fn a_stale_signature_says_by_how_much() {
        let seed = ed25519_generate_seed();
        let (input, signature, digest) = sign_rfc9421(
            "POST",
            URL,
            Some(b"{}"),
            KEY_ID,
            &SigningKeyIn::Ed25519(&seed),
            NOW,
        )
        .unwrap();
        let digest = digest.unwrap();
        let headers = [
            ("host", "remote.example"),
            ("signature-input", input.as_str()),
            ("signature", signature.as_str()),
            ("content-digest", digest.as_str()),
        ];
        let request = RequestParts::new("POST", "/users/bob/inbox", headers, b"{}");
        let (parsed, _) = signature_parse(&request).unwrap();
        let failure =
            signature_check(&parsed, &request, &["remote.example"], 3600, NOW + 7200).unwrap_err();
        assert_eq!(failure, Failure::new("stale", Detail::Int(-7200)));
    }

    #[test]
    fn a_proof_made_here_is_found_and_verifies_until_tampered_with() {
        let seed = ed25519_generate_seed();
        let public = ed25519_public_key(&seed);
        let note = json!({"@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://home.example/n/1", "type": "Note", "content": "hi"});
        let signed = integrity_sign(&note, KEY_ID, &seed, NOW).unwrap();

        let proofs = integrity_proofs(&signed, NOW);
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].cryptosuite, "eddsa-jcs-2022");
        integrity_verify(&signed, &proofs[0].proof, ProofKeyIn::Ed25519(public)).unwrap();

        let mut tampered = signed;
        tampered["content"] = json!("bye");
        let refused = integrity_verify(&tampered, &proofs[0].proof, ProofKeyIn::Ed25519(public));
        assert!(refused.is_err());
    }

    #[test]
    fn the_cache_is_bounded_and_does_not_change_the_answer() {
        let jsonld = Jsonld::new([]);
        let document = json!({"@context": "https://www.w3.org/ns/activitystreams",
            "type": "Note", "id": "https://r.example/n/1", "content": "hi"});
        let first = jsonld.normalize(&document).unwrap();
        // More distinct contexts than the cache holds.
        for n in 0..CACHE_CAPACITY + 10 {
            let own = json!({"@context": [{"@vocab": format!("https://v{n}.example/")}], "x": 1});
            jsonld.normalize(&own).unwrap();
        }
        assert_eq!(jsonld.normalize(&document).unwrap(), first);
        let held = jsonld.cache.0.lock().unwrap().len();
        assert!(held <= CACHE_CAPACITY, "{held} contexts kept");
    }

    #[test]
    fn a_registries_cache_is_its_own() {
        let own = json!({"@context": {"@vocab": "https://one.example/"}});
        let a = Jsonld::new([("https://c.example/ctx".to_owned(), own)]);
        let b = Jsonld::new([(
            "https://c.example/ctx".to_owned(),
            json!({"@context": {"@vocab": "https://two.example/"}}),
        )]);
        let document = json!({"@context": "https://c.example/ctx", "thing": 1});
        let (ea, _) = a.expand(&document).unwrap();
        let (eb, _) = b.expand(&document).unwrap();
        assert_ne!(ea, eb);
    }
}
