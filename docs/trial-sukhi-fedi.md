# Trying ojak-ex in sukhi-fedi (2026-10-14)

We put ojak-ex next to sukhi-fedi's own `SukhiFedi.Fedi` (signatures, LD, OIP;
about 1100 lines) and compared them. Nothing was replaced. The trial lives in a
sukhi-fedi worktree, branch `ojak-trial`, not committed.

## Setup

- ojak is pinned to `rev = 83bdba1` (the ojak-nif branch of sukhi-social/ojak).
- Rust 1.97.1 (`sfv` needs 1.95 or newer).
- macOS arm64, Elixir 1.20, OTP 28. `mix test` 57 passed, `cargo test` 5 passed.
- The ojak-nif README only tried Linux x86_64, Elixir 1.14, OTP 25. It also
  works on this newer setup.

## Does it behave the same?

- sukhi has golden fixtures made by Fedify. Ojak verifies all of them: HTTP
  signatures (cavage and RFC 9421), RsaSignature2017, FEP-8b32 proofs. 9 tests.
- Each side reads the other's signatures, for cavage and for RFC 9421.
- A swapped body is refused. A request whose signature does not cover the
  digest is refused too, by both. Ojak is as strict as sukhi.
- One difference: an LD signature whose `published` has nanoseconds.
  sukhi's own code cannot verify it (a known limit). Ojak can.

## Speed (ms per call)

| | sukhi | ojak |
|---|---|---|
| RSA sign, 2048 bit | 0.57 | 0.71 |
| RSA verify, 2048 bit | 0.04 | 0.10 |
| LD signature verify | 2.7 | 0.6 |
| FEP-8b32 proof verify | 0.32 | 0.09 |
| 400 LD verifies at once | 195 | 52 |

RSA is a little faster in sukhi (OpenSSL). JSON-LD work is 4 to 5 times faster
in Ojak. We did not measure how fast Ojak makes LD signatures.

## Rough edges

- **Private key PEM.** `Ojak.Key.from_pem/2` rejects the output of
  `:public_key.pem_encode`, which ends with an extra blank line. Trim it and it
  works. OpenSSL's PEM works. Public key PEM works. The cause is the strict PEM
  reader in RustCrypto (reproduced with the `rsa` crate alone).
- `HTTPSignature.sign` does not return a `host` header. sukhi returns every
  header the signature covers.
- Errors are tuples like `{:not_covered, "digest"}`. sukhi uses atoms like
  `:digest_not_signed`.
- sukhi's golden keys are JWK. Ojak takes PEM or a seed, so a conversion is
  needed.
- Fetching and caching keys, and retrying once with a fresh key, is the
  caller's job.

## Upkeep

- sukhi keeps less code (1112 lines become a thin wrapper). The total grows:
  about 2500 lines here, plus about 7300 lines of Rust in ojak-sig and
  ojak-jsonld.
- Adding one NIF touches five places: core, `lib.rs`, the `nif.ex` stub, tests,
  and the wrapper. The pattern is regular.
- Fixing behavior means a pull request to upstream ojak. It is young (4 stars,
  and its README says the API may change). The `rev` pin keeps it from moving.
- A Rust panic becomes an Elixir exception. A bug that is not a panic can take
  the whole VM down. It has not been fuzzed.

## Not checked yet

- The Alpine Docker build. sukhi builds on `elixir:1.20-alpine`, which has no
  Rust. Building a cdylib on musl may need extra flags. Docker was not running.
- Real keys and real servers.
- How the dirty schedulers behave under load.

## Shadow run

In sukhi we added `SukhiFedi.Fedi.OjakShadow`. After the inbox checks an HTTP
signature, it gives the same input to Ojak and logs a warning only when the two
disagree. The inbox always uses sukhi's own answer, and anything Ojak raises is
swallowed. It is off by default; set `OJAK_SHADOW=1` to turn it on. It has 8
tests: agreement is silent, disagreement warns, off does nothing, a broken PEM
is swallowed.

## Next

1. Run the shadow on dev or staging and read the disagreement logs.
2. Get the Alpine build working.
3. Decide whether to tell upstream about the PEM issue (a person reads it
   first).
