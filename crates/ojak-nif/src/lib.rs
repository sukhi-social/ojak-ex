//! Ojak's signatures and JSON-LD, as an Erlang NIF library.
//!
//! This crate is the native half of the Elixir package under *elixir/*, which
//! documents what each function takes and gives. What it builds on does no
//! I/O, and neither does this: the Elixir application fetches keys and
//! documents, queues and sends, and keeps the time; this checks and makes
//! signatures and reads JSON-LD, which is the part that is both subtle and
//! heavy.
//!
//! A few rules hold throughout, so that a call can be reasoned about:
//!
//! - **Terms in, terms out.** A JSON document is an Elixir map with binary
//!   keys, as a JSON library gives it; there is no text to parse here.
//! - **Anything that can take a millisecond runs on a dirty CPU scheduler**:
//!   RSA, JSON-LD, post-quantum signatures. A normal scheduler is never held
//!   for longer than it takes to read a header.
//! - **Time is an argument**, in seconds since the Unix epoch.
//! - **Nothing panics on what a stranger sends.** Content that is wrong
//!   comes back as `{:error, reason}`; only a call whose *shape* is wrong,
//!   which is the caller's bug, raises `ArgumentError`.
//! - **Secrets stay in resources.** A private key is parsed once into an
//!   opaque reference, and never comes back out.

use ojak_nif_core as ops;
use ops::{Detail, Failure, Jsonld, Outcome, RequestParts};
use rustler::types::atom;
use rustler::{
    Atom, Binary, Encoder, Env, ListIterator, MapIterator, OwnedBinary, Resource, ResourceArc,
    Term, TermType,
};
use serde_json::{Map, Number, Value};
use std::sync::OnceLock;

rustler::init!("Elixir.Ojak.Nif");

// ------------------------------------------------------------- resources ----

struct PrivateKeyRes(ojak_sig::signature::PrivateKey);
struct SignatureRes(ojak_sig::verification::Signature);
struct JsonldRes(Jsonld);

#[rustler::resource_impl]
impl Resource for PrivateKeyRes {}
#[rustler::resource_impl]
impl Resource for SignatureRes {}
#[rustler::resource_impl]
impl Resource for JsonldRes {}

// --------------------------------------------------------- terms <-> data ----

/// How deeply a JSON term may nest before it is refused, so that a term built
/// to be deep cannot exhaust the stack.
const MAX_JSON_DEPTH: usize = 128;

fn atom_term<'a>(env: Env<'a>, name: &str) -> Term<'a> {
    Atom::from_str(env, name)
        .map(|atom| atom.to_term(env))
        .unwrap_or_else(|_| atom::error().to_term(env))
}

fn bytes_term<'a>(env: Env<'a>, bytes: &[u8]) -> Term<'a> {
    OwnedBinary::from_slice(bytes).release(env).encode(env)
}

/// A map with atom keys.
fn record<'a>(env: Env<'a>, fields: Vec<(&str, Term<'a>)>) -> Term<'a> {
    let pairs: Vec<(Term<'a>, Term<'a>)> = fields
        .into_iter()
        .map(|(key, value)| (atom_term(env, key), value))
        .collect();
    Term::map_from_pairs(env, &pairs).unwrap_or_else(|_| atom::error().to_term(env))
}

fn tagged<'a>(env: Env<'a>, tag: &str, value: Term<'a>) -> Term<'a> {
    (atom_term(env, tag), value).encode(env)
}

fn failure_term<'a>(env: Env<'a>, failure: &Failure) -> Term<'a> {
    let kind = atom_term(env, failure.kind);
    match &failure.detail {
        Detail::None => kind,
        Detail::Text(text) => (kind, text.as_str()).encode(env),
        Detail::Int(number) => (kind, *number).encode(env),
    }
}

/// `{:ok, value}` or `{:error, reason}`.
fn value<'a>(env: Env<'a>, outcome: Outcome<Term<'a>>) -> Term<'a> {
    match outcome {
        Ok(term) => (atom::ok(), term).encode(env),
        Err(failure) => (atom::error(), failure_term(env, &failure)).encode(env),
    }
}

/// `:ok` or `{:error, reason}`.
fn done<'a>(env: Env<'a>, outcome: Outcome<()>) -> Term<'a> {
    match outcome {
        Ok(()) => atom::ok().to_term(env),
        Err(failure) => (atom::error(), failure_term(env, &failure)).encode(env),
    }
}

fn text<'a>(binary: Binary<'a>, what: &str) -> Outcome<&'a str> {
    std::str::from_utf8(binary.as_slice())
        .map_err(|_| Failure::argument(format!("{what} is not UTF-8")))
}

fn json_to_term<'a>(env: Env<'a>, json: &Value) -> Term<'a> {
    match json {
        Value::Null => atom::nil().to_term(env),
        Value::Bool(flag) => flag.encode(env),
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                integer.encode(env)
            } else if let Some(integer) = number.as_u64() {
                integer.encode(env)
            } else {
                number.as_f64().unwrap_or(0.0).encode(env)
            }
        }
        Value::String(string) => string.as_str().encode(env),
        Value::Array(items) => {
            let terms: Vec<Term<'a>> = items.iter().map(|item| json_to_term(env, item)).collect();
            terms.encode(env)
        }
        Value::Object(members) => {
            let pairs: Vec<(Term<'a>, Term<'a>)> = members
                .iter()
                .map(|(key, item)| (key.as_str().encode(env), json_to_term(env, item)))
                .collect();
            Term::map_from_pairs(env, &pairs).unwrap_or_else(|_| atom::error().to_term(env))
        }
    }
}

/// A JSON document, from the map a JSON library gives: maps with binary keys,
/// lists, binaries, numbers, booleans and `nil`.
fn json_from_term(term: Term<'_>) -> Outcome<Value> {
    json_at(term, 0)
}

fn json_at(term: Term<'_>, depth: usize) -> Outcome<Value> {
    let wrong = |what: &str| Failure::argument(format!("not JSON: {what}"));
    if depth > MAX_JSON_DEPTH {
        return Err(wrong("nested too deeply"));
    }
    match term.get_type() {
        TermType::Atom => match term.atom_to_string().as_deref() {
            Ok("nil") => Ok(Value::Null),
            Ok("true") => Ok(Value::Bool(true)),
            Ok("false") => Ok(Value::Bool(false)),
            _ => Err(wrong("an atom other than nil, true or false")),
        },
        TermType::Binary => {
            let binary = Binary::from_term(term).map_err(|_| wrong("a bitstring"))?;
            text(binary, "a string").map(|string| Value::String(string.to_owned()))
        }
        TermType::Integer => {
            if let Ok(integer) = term.decode::<i64>() {
                Ok(Value::from(integer))
            } else if let Ok(integer) = term.decode::<u64>() {
                Ok(Value::from(integer))
            } else {
                Err(wrong("an integer past 64 bits"))
            }
        }
        TermType::Float => {
            let float: f64 = term.decode().map_err(|_| wrong("a float"))?;
            Number::from_f64(float)
                .map(Value::Number)
                .ok_or_else(|| wrong("a float that is not finite"))
        }
        TermType::List => {
            let items: ListIterator = term.decode().map_err(|_| wrong("an improper list"))?;
            items
                .map(|item| json_at(item, depth + 1))
                .collect::<Outcome<Vec<_>>>()
                .map(Value::Array)
        }
        TermType::Map => {
            let entries = MapIterator::new(term).ok_or_else(|| wrong("a map"))?;
            let mut members = Map::new();
            for (key, item) in entries {
                let key =
                    Binary::from_term(key).map_err(|_| wrong("a key that is not a string"))?;
                let key = text(key, "a key")?.to_owned();
                members.insert(key, json_at(item, depth + 1)?);
            }
            Ok(Value::Object(members))
        }
        _ => Err(wrong("a term JSON has no form for")),
    }
}

/// A request: `{method, path_and_query, [{name, value}], body}`.
fn request_from_term(term: Term<'_>) -> Outcome<RequestParts<'_>> {
    type Raw<'a> = (
        Binary<'a>,
        Binary<'a>,
        Vec<(Binary<'a>, Binary<'a>)>,
        Binary<'a>,
    );
    let (method, path, headers, body): Raw<'_> = term.decode().map_err(|_| {
        Failure::argument("a request is {method, path_and_query, [{name, value}], body}")
    })?;
    let headers = headers
        .into_iter()
        .map(|(name, value)| Ok((text(name, "a header name")?, text(value, "a header value")?)))
        .collect::<Outcome<Vec<_>>>()?;
    Ok(RequestParts::new(
        text(method, "the method")?,
        text(path, "the path")?,
        headers,
        body.as_slice(),
    ))
}

fn fixed_32(binary: Binary<'_>, what: &str) -> Outcome<[u8; 32]> {
    <[u8; 32]>::try_from(binary.as_slice())
        .map_err(|_| Failure::argument(format!("{what} is 32 bytes, not {}", binary.len())))
}

/// `{kind, binary}`, the shape every key argument takes.
fn tagged_binary<'a>(term: Term<'a>, what: &str) -> Outcome<(String, Binary<'a>)> {
    let (kind, key): (Atom, Binary<'a>) = term
        .decode()
        .map_err(|_| Failure::argument(format!("{what} is {{kind, key}}")))?;
    let kind = kind
        .to_term(term.get_env())
        .atom_to_string()
        .map_err(|_| Failure::argument("a key kind is an atom"))?;
    Ok((kind, key))
}

enum VerifyKey {
    RsaPem(String),
    Ed25519([u8; 32]),
}

impl VerifyKey {
    /// `{:rsa_pem, pem}` or `{:ed25519, <<32 bytes>>}`.
    fn from_term(term: Term<'_>) -> Outcome<Self> {
        let (kind, key) = tagged_binary(term, "a verification key")?;
        match kind.as_str() {
            "rsa_pem" => Ok(Self::RsaPem(text(key, "a PEM")?.to_owned())),
            "ed25519" => Ok(Self::Ed25519(fixed_32(key, "an Ed25519 public key")?)),
            other => Err(Failure::argument(format!("no verification key {other:?}"))),
        }
    }

    fn as_ops(&self) -> ops::VerifyKeyIn<'_> {
        match self {
            Self::RsaPem(pem) => ops::VerifyKeyIn::RsaPem(pem),
            Self::Ed25519(bytes) => ops::VerifyKeyIn::Ed25519(bytes),
        }
    }
}

/// The context registry an argument names: `nil` for the contexts ojak ships.
fn default_jsonld() -> &'static Jsonld {
    static DEFAULT: OnceLock<Jsonld> = OnceLock::new();
    DEFAULT.get_or_init(|| Jsonld::new([]))
}

fn with_jsonld<R>(registry: &Option<ResourceArc<JsonldRes>>, then: impl FnOnce(&Jsonld) -> R) -> R {
    match registry {
        Some(registry) => then(&registry.0),
        None => then(default_jsonld()),
    }
}

// ------------------------------------------------------------------ keys ----

/// `{:ok, {private_pem, public_pem}}`: a new 2048-bit RSA key pair.
#[rustler::nif(schedule = "DirtyCpu")]
fn rsa_generate_keypair(env: Env<'_>) -> Term<'_> {
    value(
        env,
        ops::rsa_generate_keypair().map(|(private, public)| (private, public).encode(env)),
    )
}

/// `{:ok, key}`: an RSA private key, parsed once. The reference is opaque, and
/// the key does not come back out of it.
#[rustler::nif(schedule = "DirtyCpu")]
fn rsa_private_key<'a>(env: Env<'a>, pem: Binary<'a>) -> Term<'a> {
    let outcome = text(pem, "a PEM")
        .and_then(ops::rsa_private_key)
        .map(|key| ResourceArc::new(PrivateKeyRes(key)).encode(env));
    value(env, outcome)
}

#[rustler::nif]
fn ed25519_generate_seed(env: Env<'_>) -> Term<'_> {
    value(env, Ok(bytes_term(env, &ops::ed25519_generate_seed())))
}

#[rustler::nif]
fn ed25519_public_key<'a>(env: Env<'a>, seed: Binary<'a>) -> Term<'a> {
    let outcome = fixed_32(seed, "an Ed25519 seed")
        .map(|seed| bytes_term(env, &ops::ed25519_public_key(&seed)));
    value(env, outcome)
}

/// The Multikey (`"z6Mk…"`) an actor publishes an Ed25519 key as.
#[rustler::nif]
fn ed25519_multikey_encode<'a>(env: Env<'a>, public_key: Binary<'a>) -> Term<'a> {
    let outcome = fixed_32(public_key, "an Ed25519 public key")
        .map(|key| ops::ed25519_multikey_encode(&key).encode(env));
    value(env, outcome)
}

/// `{:ok, {:ed25519 | :mldsa44, key}}`.
#[rustler::nif]
fn multikey_decode<'a>(env: Env<'a>, multibase: Binary<'a>) -> Term<'a> {
    let outcome = text(multibase, "a Multikey")
        .and_then(ops::multikey_decode)
        .map(|(kind, key)| (atom_term(env, kind), bytes_term(env, &key)).encode(env));
    value(env, outcome)
}

/// The `did:key` of an Ed25519 public key.
#[rustler::nif]
fn did_key<'a>(env: Env<'a>, public_key: Binary<'a>) -> Term<'a> {
    let outcome =
        fixed_32(public_key, "an Ed25519 public key").map(|key| ops::did_key(&key).encode(env));
    value(env, outcome)
}

// --------------------------------------------------------------- signing ----

fn extra_headers<'a>(term: Term<'a>) -> Outcome<Vec<(&'a str, &'a str)>> {
    let pairs: Vec<(Binary<'a>, Binary<'a>)> = term
        .decode()
        .map_err(|_| Failure::argument("extra headers are [{name, value}]"))?;
    pairs
        .into_iter()
        .map(|(name, value)| Ok((text(name, "a header name")?, text(value, "a header value")?)))
        .collect()
}

/// Sign a request, draft-cavage. `{:ok, %{signature:, date:, digest:}}`: the
/// headers to send with it, which are covered, and so must be sent as given.
// The arity is Elixir's: seven arguments, and the environment a NIF is given.
#[allow(clippy::too_many_arguments)]
#[rustler::nif(schedule = "DirtyCpu")]
fn sign_draft_cavage<'a>(
    env: Env<'a>,
    method: Binary<'a>,
    url: Binary<'a>,
    body: Binary<'a>,
    key_id: Binary<'a>,
    key: ResourceArc<PrivateKeyRes>,
    extra: Term<'a>,
    now: i64,
) -> Term<'a> {
    let outcome = (|| {
        let extra = extra_headers(extra)?;
        ops::sign_draft_cavage(
            text(method, "the method")?,
            text(url, "the URL")?,
            body.as_slice(),
            text(key_id, "the key ID")?,
            &key.0,
            &extra,
            now,
        )
    })()
    .map(|(signature, date, digest)| {
        record(
            env,
            vec![
                ("signature", signature.as_str().encode(env)),
                ("date", date.as_str().encode(env)),
                ("digest", digest.as_str().encode(env)),
            ],
        )
    });
    value(env, outcome)
}

/// Sign a request, RFC 9421, with `{:rsa, key}` or `{:ed25519, seed}`.
/// `body` is `nil` for a request without one.
/// `{:ok, %{signature_input:, signature:, content_digest:}}`.
#[rustler::nif(schedule = "DirtyCpu")]
fn sign_rfc9421<'a>(
    env: Env<'a>,
    method: Binary<'a>,
    url: Binary<'a>,
    body: Option<Binary<'a>>,
    key_id: Binary<'a>,
    key: Term<'a>,
    now: i64,
) -> Term<'a> {
    let outcome = (|| {
        let (kind, inner): (Atom, Term<'a>) = key
            .decode()
            .map_err(|_| Failure::argument("a signing key is {:rsa, key} or {:ed25519, seed}"))?;
        let kind = kind
            .to_term(env)
            .atom_to_string()
            .map_err(|_| Failure::argument("a key kind is an atom"))?;
        let (method, url, key_id) = (
            text(method, "the method")?,
            text(url, "the URL")?,
            text(key_id, "the key ID")?,
        );
        let body = body.as_ref().map(Binary::as_slice);
        match kind.as_str() {
            "rsa" => {
                let key: ResourceArc<PrivateKeyRes> = inner
                    .decode()
                    .map_err(|_| Failure::argument("{:rsa, key} takes a parsed RSA key"))?;
                ops::sign_rfc9421(
                    method,
                    url,
                    body,
                    key_id,
                    &ops::SigningKeyIn::Rsa(&key.0),
                    now,
                )
            }
            "ed25519" => {
                let seed = Binary::from_term(inner)
                    .map_err(|_| Failure::argument("{:ed25519, seed} takes a binary"))
                    .and_then(|seed| fixed_32(seed, "an Ed25519 seed"))?;
                ops::sign_rfc9421(
                    method,
                    url,
                    body,
                    key_id,
                    &ops::SigningKeyIn::Ed25519(&seed),
                    now,
                )
            }
            other => Err(Failure::argument(format!("no signing key {other:?}"))),
        }
    })()
    .map(|(signature_input, signature, content_digest)| {
        record(
            env,
            vec![
                ("signature_input", signature_input.as_str().encode(env)),
                ("signature", signature.as_str().encode(env)),
                ("content_digest", content_digest.as_deref().encode(env)),
            ],
        )
    });
    value(env, outcome)
}

/// Whether a `Digest` header describes `body`.
#[rustler::nif]
fn digest_matches<'a>(header: Binary<'a>, body: Binary<'a>) -> bool {
    text(header, "a header").is_ok_and(|header| ops::digest_matches(header, body.as_slice()))
}

/// Whether a `Content-Digest` header describes `body`.
#[rustler::nif]
fn content_digest_matches<'a>(header: Binary<'a>, body: Binary<'a>) -> bool {
    text(header, "a header")
        .is_ok_and(|header| ops::content_digest_matches(header, body.as_slice()))
}

#[rustler::nif]
fn content_digest(body: Binary<'_>) -> String {
    ops::content_digest(body.as_slice())
}

// ---------------------------------------------------------- verification ----

/// Step one: read the signature on a request.
/// `{:ok, signature, %{scheme:, key_id:, covered:, created:, expires:}}`.
#[rustler::nif]
fn signature_parse<'a>(env: Env<'a>, request: Term<'a>) -> Term<'a> {
    let outcome = request_from_term(request).and_then(|request| ops::signature_parse(&request));
    match outcome {
        Ok((signature, info)) => {
            let info = record(
                env,
                vec![
                    ("scheme", atom_term(env, info.scheme)),
                    ("key_id", info.key_id.as_str().encode(env)),
                    ("covered", info.covered.encode(env)),
                    ("created", info.created.encode(env)),
                    ("expires", info.expires.encode(env)),
                ],
            );
            let signature = ResourceArc::new(SignatureRes(signature));
            (atom::ok(), signature, info).encode(env)
        }
        Err(failure) => (atom::error(), failure_term(env, &failure)).encode(env),
    }
}

/// Step two: hold the signature to the policy before its key is fetched.
/// `hosts` are the hosts this server answers to.
#[rustler::nif]
fn signature_check<'a>(
    env: Env<'a>,
    signature: ResourceArc<SignatureRes>,
    request: Term<'a>,
    hosts: Term<'a>,
    max_skew_seconds: i64,
    now: i64,
) -> Term<'a> {
    let outcome = (|| {
        let request = request_from_term(request)?;
        let hosts: Vec<Binary<'a>> = hosts
            .decode()
            .map_err(|_| Failure::argument("hosts are a list of binaries"))?;
        let hosts = hosts
            .into_iter()
            .map(|host| text(host, "a host"))
            .collect::<Outcome<Vec<_>>>()?;
        ops::signature_check(&signature.0, &request, &hosts, max_skew_seconds, now)
    })();
    done(env, outcome)
}

/// Step three: check the signature against a key the caller found, as
/// `{:rsa_pem, pem}` or `{:ed25519, public_key}`.
#[rustler::nif(schedule = "DirtyCpu")]
fn signature_verify<'a>(
    env: Env<'a>,
    signature: ResourceArc<SignatureRes>,
    request: Term<'a>,
    key: Term<'a>,
) -> Term<'a> {
    let outcome = (|| {
        let request = request_from_term(request)?;
        let key = VerifyKey::from_term(key)?;
        ops::signature_verify(&signature.0, &request, &key.as_ops())
    })();
    done(env, outcome)
}

/// The actor a key ID most likely belongs to.
#[rustler::nif]
fn key_owner<'a>(env: Env<'a>, key_id: Binary<'a>) -> Term<'a> {
    value(
        env,
        text(key_id, "a key ID").map(|key_id| ops::key_owner(key_id).encode(env)),
    )
}

/// The key `actor` publishes as `key_id`, or `nil`: `{:rsa_pem, pem}` or
/// `{:ed25519, public_key}`. Without this, anyone who can put a key document
/// on a server could sign as any actor there.
#[rustler::nif]
fn published_key<'a>(env: Env<'a>, actor: Term<'a>, key_id: Binary<'a>) -> Term<'a> {
    let outcome = (|| {
        let actor = json_from_term(actor)?;
        let key_id = text(key_id, "a key ID")?;
        Ok(ops::published_key(&actor, key_id).map(ops::Published::from))
    })();
    value(
        env,
        outcome.map(|key| match key {
            None => atom::nil().to_term(env),
            Some(ops::Published::RsaPem(pem)) => tagged(env, "rsa_pem", pem.as_str().encode(env)),
            Some(ops::Published::Ed25519(bytes)) => tagged(env, "ed25519", bytes_term(env, &bytes)),
        }),
    )
}

// ------------------------------------------------------------- integrity ----

/// The usable integrity proofs on an object at `now`:
/// `{:ok, [%{proof:, cryptosuite:, verification_method:}]}`. The caller
/// resolves each `verification_method` to a key of the matching kind.
#[rustler::nif]
fn integrity_proofs<'a>(env: Env<'a>, document: Term<'a>, now: i64) -> Term<'a> {
    let outcome = json_from_term(document).map(|document| {
        let proofs: Vec<Term<'a>> = ops::integrity_proofs(&document, now)
            .into_iter()
            .map(|proof| {
                record(
                    env,
                    vec![
                        ("proof", json_to_term(env, &Value::Object(proof.proof))),
                        ("cryptosuite", proof.cryptosuite.encode(env)),
                        (
                            "verification_method",
                            proof.verification_method.as_str().encode(env),
                        ),
                    ],
                )
            })
            .collect();
        proofs.encode(env)
    });
    value(env, outcome)
}

/// Check one proof on an object against `{:ed25519, key}` or
/// `{:mldsa44, key}`.
#[rustler::nif(schedule = "DirtyCpu")]
fn integrity_verify<'a>(
    env: Env<'a>,
    document: Term<'a>,
    proof: Term<'a>,
    key: Term<'a>,
) -> Term<'a> {
    let outcome = (|| {
        let document = json_from_term(document)?;
        let Value::Object(proof) = json_from_term(proof)? else {
            return Err(Failure::argument("a proof is a map"));
        };
        let (kind, key) = tagged_binary(key, "a proof key")?;
        let key = match kind.as_str() {
            "ed25519" => ops::ProofKeyIn::Ed25519(fixed_32(key, "an Ed25519 public key")?),
            "mldsa44" => ops::ProofKeyIn::MlDsa44(key.as_slice().to_vec()),
            other => return Err(Failure::argument(format!("no proof key {other:?}"))),
        };
        ops::integrity_verify(&document, &proof, key)
    })();
    done(env, outcome)
}

/// An object with an `eddsa-jcs-2022` proof made by `seed`, and the Data
/// Integrity context a reader needs in order to find it.
#[rustler::nif]
fn integrity_sign<'a>(
    env: Env<'a>,
    document: Term<'a>,
    verification_method: Binary<'a>,
    seed: Binary<'a>,
    now: i64,
) -> Term<'a> {
    let outcome = (|| {
        let document = json_from_term(document)?;
        let seed = fixed_32(seed, "an Ed25519 seed")?;
        ops::integrity_sign(
            &document,
            text(verification_method, "the verification method")?,
            &seed,
            now,
        )
    })()
    .map(|signed| json_to_term(env, &signed));
    value(env, outcome)
}

// ---------------------------------------------------------------- JSON-LD ----

/// `{:ok, registry}`: the contexts ojak ships and the caller's own, given as
/// `%{iri => context_document}`. The cache of processed contexts lives in the
/// registry, so a long-lived one is cheaper than a new one for each document.
#[rustler::nif(schedule = "DirtyCpu")]
fn jsonld_registry<'a>(env: Env<'a>, contexts: Term<'a>) -> Term<'a> {
    let outcome = (|| {
        let Value::Object(contexts) = json_from_term(contexts)? else {
            return Err(Failure::argument("contexts are %{iri => document}"));
        };
        Ok(ResourceArc::new(JsonldRes(Jsonld::new(contexts))).encode(env))
    })();
    value(env, outcome)
}

/// `{:ok, document, unresolved}`: `unresolved` are the context IRIs the
/// document named that the registry does not hold. That is not an error,
/// though worth logging.
fn jsonld_reply<'a>(env: Env<'a>, outcome: Outcome<(Value, Vec<String>)>) -> Term<'a> {
    match outcome {
        Ok((document, unresolved)) => {
            (atom::ok(), json_to_term(env, &document), unresolved).encode(env)
        }
        Err(failure) => (atom::error(), failure_term(env, &failure)).encode(env),
    }
}

/// Every key becomes the IRI it stands for.
#[rustler::nif(schedule = "DirtyCpu")]
fn jsonld_expand<'a>(
    env: Env<'a>,
    registry: Option<ResourceArc<JsonldRes>>,
    document: Term<'a>,
) -> Term<'a> {
    let outcome = json_from_term(document)
        .and_then(|document| with_jsonld(&registry, |jsonld| jsonld.expand(&document)));
    jsonld_reply(env, outcome)
}

/// Compact an expanded document against a `@context` value.
#[rustler::nif(schedule = "DirtyCpu")]
fn jsonld_compact<'a>(
    env: Env<'a>,
    registry: Option<ResourceArc<JsonldRes>>,
    expanded: Term<'a>,
    context: Term<'a>,
) -> Term<'a> {
    let outcome = (|| {
        let expanded = json_from_term(expanded)?;
        let context = json_from_term(context)?;
        with_jsonld(&registry, |jsonld| jsonld.compact(&expanded, &context))
    })();
    jsonld_reply(env, outcome)
}

/// A document in ojak's own spelling, whatever aliases and extension contexts
/// it arrived with.
#[rustler::nif(schedule = "DirtyCpu")]
fn jsonld_normalize<'a>(
    env: Env<'a>,
    registry: Option<ResourceArc<JsonldRes>>,
    document: Term<'a>,
) -> Term<'a> {
    let outcome = json_from_term(document)
        .and_then(|document| with_jsonld(&registry, |jsonld| jsonld.normalize(&document)));
    jsonld_reply(env, outcome)
}

// ----------------------------------------------------- Linked Data Signatures ----

/// The `creator` of an `RsaSignature2017`, or `nil`. Says nothing about
/// whether it verifies.
#[rustler::nif]
fn linked_data_creator<'a>(env: Env<'a>, document: Term<'a>) -> Term<'a> {
    let outcome = json_from_term(document).map(|document| {
        ops::linked_data_creator(&document)
            .map(str::to_owned)
            .encode(env)
    });
    value(env, outcome)
}

/// Check an `RsaSignature2017` against the PEM of the key its creator names.
#[rustler::nif(schedule = "DirtyCpu")]
fn linked_data_verify<'a>(
    env: Env<'a>,
    registry: Option<ResourceArc<JsonldRes>>,
    document: Term<'a>,
    public_key_pem: Binary<'a>,
    now: i64,
) -> Term<'a> {
    let outcome = (|| {
        let document = json_from_term(document)?;
        let pem = text(public_key_pem, "a PEM")?;
        with_jsonld(&registry, |jsonld| {
            ops::linked_data_verify(jsonld, &document, pem, now)
        })
    })();
    done(env, outcome)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn linked_data_sign<'a>(
    env: Env<'a>,
    registry: Option<ResourceArc<JsonldRes>>,
    document: Term<'a>,
    key_id: Binary<'a>,
    key: ResourceArc<PrivateKeyRes>,
    created: i64,
    expires: i64,
) -> Term<'a> {
    let outcome = (|| {
        let document = json_from_term(document)?;
        let key_id = text(key_id, "the key ID")?;
        with_jsonld(&registry, |jsonld| {
            ops::linked_data_sign(jsonld, &document, key_id, &key.0, created, expires)
        })
    })()
    .map(|signed| json_to_term(env, &signed));
    value(env, outcome)
}
