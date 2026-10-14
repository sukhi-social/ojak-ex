# ojak-ex

ActivityPub signatures and JSON-LD for Elixir, as a NIF (Rust through Rustler).

It checks and makes HTTP signatures, object integrity proofs and Linked Data
signatures, and it reads JSON-LD. It does no I/O. You fetch, queue, send and
supervise in Elixir as you do now; this part says whether a request is
genuine, and signs yours.

It is a packaging of [ojak](https://github.com/eunha-space/ojak)'s `ojak-sig`
and `ojak-jsonld` crates (pinned by commit), plus the Elixir API on top.
Status: **0.1.0, young.** Please read "Before you use it".

## What you get

| | |
|---|---|
| HTTP signatures | draft-cavage and RFC 9421, sign and verify |
| Object integrity proofs | FEP-8b32 `eddsa-jcs-2022` (sign, verify); `mldsa44-jcs-2024` (verify) |
| Linked Data signatures | `RsaSignature2017`, the kind Mastodon forwards |
| JSON-LD | expand, compact, normalize (no network fetches) |
| Keys | RSA 2048 and Ed25519; Multikey and `did:key` |

Every function returns `{:ok, value}` or `{:error, reason}`, and has a `!`
twin that raises `Ojak.Error`. The time is the current one; pass `now:` to say
otherwise, which is how you test.

## Why you might want it

These are the real reasons, and the numbers are from one comparison (below).

- **One checked implementation instead of several you write.** The easy part
  of signatures is the signing. The hard part is the rules around it: which
  headers must be covered, the clock, how a document's `@context` changes what
  its keys mean, what to do with a context you do not hold. Here those are
  written once, and a request is checked in three steps (read it, check it
  needs no key, then check the key) so a key is not fetched for a request that
  could never pass.
- **Strict where it matters.** A signature that does not cover the body's
  digest is refused, in both schemes. Verifying a signature also tells you
  *whose* key it was; binding that to the activity's `actor` is left to you,
  and the docs say so.
- **JSON-LD is where it is faster.** Verifying a Linked Data signature, which
  needs RDF canonicalization, took 0.6 ms, against 2.7 ms for a pure-Elixir
  `json_ld` + `rdf` pipeline on the same document (one Mac). With 400 at once,
  52 ms against 195 ms. It also read a signature that pipeline could not (a
  `published` with nanoseconds). Proof verification was about 3 times faster.
  We did not measure making Linked Data signatures against that pipeline.
- **No hidden I/O.** Nothing fetches or caches behind your back. You give it a
  `fetch_key` function and it calls it. The Rust side never reads the clock;
  the Elixir wrapper passes it the current time, or your `now:`.

What it is *not* better at: RSA. Erlang's `:crypto` (OpenSSL) verified about
two to four times faster in the same comparison (0.04 ms against 0.10 ms with a
2048-bit key; both are small), and signed at about the same speed. If all you
need is to verify one RSA signature, `:public_key` is enough and you do not
need this.

## A short tour

Sign what you send, with the HTTP client you already use:

```elixir
key = Ojak.Key.generate!(:rsa)

{:ok, headers} =
  Ojak.HTTPSignature.sign("POST", inbox, body, key,
    key_id: key_id,
    headers: [{"content-type", "application/activity+json"}]
  )

Req.post!(inbox, body: body, headers: headers ++ [{"content-type", "application/activity+json"}])
```

The result has no `host`: your HTTP client adds it. Verify what you receive.
You say how to find the key; it is asked for only after the request has passed
the checks that need no key:

```elixir
request = Ojak.Request.from_conn(conn, conn.assigns.raw_body)

{:ok, %{owner: owner}} =
  Ojak.HTTPSignature.verify(request,
    hosts: ["example.com"],
    fetch_key: fn key_id -> MyApp.Remote.fetch_actor(Ojak.HTTPSignature.key_owner(key_id)) end
  )
```

`fetch_key` may return the actor document (the key is looked for in it and its
owner checked) or a public key you already trust, like `{:rsa_pem, pem}`. A
valid signature says who signed the request, not that the activity in it is
theirs: check `activity["actor"] == owner`.

Read a document however it was spelled, and sign an object so it holds
wherever it is found (FEP-8b32):

```elixir
{:ok, note} = Ojak.JsonLd.normalize(document)
note["sensitive"]  # whether it said `sensitive`, `as:sensitive`, or its own alias

{:ok, ed} = Ojak.Key.generate(:ed25519)
{:ok, signed} = Ojak.Proof.sign(note, ed, verification_method: "https://example.com/users/alice#ed")
{:ok, _} = Ojak.Proof.verify(signed, fetch_key: fn _vm -> {:ok, ed.public} end)
```

More in [crates/ojak-nif/README.md](crates/ojak-nif/README.md). Each module
documents its own options.

## Install

```elixir
{:ojak, github: "sukhi-social/ojak-ex", tag: "v0.1.1"}
```

On Linux (x86_64 or aarch64, glibc or musl), `mix deps.compile` downloads the
library built for that platform from the GitHub release and uses it if its
SHA-256 matches the one published beside it. You do not need Rust. Anywhere
else, or if the download fails, it builds with `cargo`, which needs Rust 1.95
or newer (`rust-toolchain.toml` pins 1.97.1). It says which one it did.

The checksum comes from the same release as the library, so it catches a
broken download, not a tampered release. If you want to know what the library
was built from, set `OJAK_NIF_BUILD=1` and build it yourself. Other switches
are in `mix help ojak_nif.build`.

To work on ojak-ex itself, clone it. A clone, or a `path:` dependency, always
builds from source, so your changes to the Rust are not hidden by a download.

```elixir
{:ojak, path: "../ojak-ex"}
```

Tests: `mix test`.

## Before you use it

- **Licence: AGPL-3.0-only**, as ojak's. What that means for an application
  that loads this is for you to decide.
- **Tested** on macOS arm64 and on Linux (x86_64 and aarch64, glibc and musl)
  with Elixir 1.20 and OTP 28; the first version of the package was tried on Elixir 1.14 and
  OTP 25. Not tried: Windows.
- **Checked against Fedify's output, not yet against live servers.** In a trial
  in [sukhi-fedi](https://github.com/sukhi-social/sukhi-fedi), Ojak verified
  every signature in its Fedify-made golden fixtures, and read and wrote
  signatures that sukhi's own Elixir code read back. It has not federated with
  a real server from Elixir. See [the trial notes](docs/trial-sukhi-fedi.md).
- **A bug that is not a panic can take the VM down.** A Rust panic becomes an
  Elixir exception, but a NIF fault does not. It has not been fuzzed. Slow
  calls run on the dirty CPU schedulers, so bound the size of what you accept
  before you hand it over.
- **Not there yet:** signed `GET` (authorized fetch), responses, and an RSA
  public key worked out from its private one.
- **Private key PEM:** `Ojak.Key.from_pem/2` rejects the output of Erlang's
  `:public_key.pem_encode` (it ends with an extra blank line). Trim the end, or
  use OpenSSL's output.
- **The API may change.** ojak itself is young.

## More

- [docs/trial-sukhi-fedi.md](docs/trial-sukhi-fedi.md): what we measured, and
  what got in the way.
- [docs/prebuild.md](docs/prebuild.md): the prebuilt Linux libraries and the
  PGO build (which turned out to be a small gain at best).
- [crates/ojak-nif/README.md](crates/ojak-nif/README.md): the layout, and the
  modules in more detail.

## Thanks

We use this, and we like keeping it in good shape. These made that easy and
pleasant, and we are grateful for them.

- **[Ojak](https://github.com/eunha-space/ojak)**: its signature and JSON-LD
  crates are clear enough to build on. Pinning one commit just worked, and we
  can follow its changes at our own pace.
- **[Feder](https://github.com/fedify-dev/feder)**: for the way of keeping
  protocol decisions as functions of the facts they are given, apart from the
  platform around them. It tells us where a change belongs.
- **[Fedify](https://fedify.dev)**: for the behaviour servers expect, and for
  the fixtures we check against. Because of them we can change things without
  worrying whether we still agree with the fediverse.
- **[Elixir](https://elixir-lang.org)** and Erlang/OTP: for the VM, the dirty
  schedulers that let a NIF do slow work politely, and `:httpc` and
  `:public_key`, which are all the build needs to fetch and check a prebuilt
  library. No extra dependencies.
- **[Rustler](https://github.com/rusterlium/rustler)**: the NIF boundary stays
  regular and readable, so adding a function touches the same few places every
  time.

And thanks to everyone who writes down how the fediverse works, so that the
rest of us can read it.
