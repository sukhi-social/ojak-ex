ojak-nif
========

Ojak's signatures and JSON-LD, for Elixir.

An ActivityPub server in Elixir already has what Elixir is good at: processes,
queues, supervision, a network stack.  This is the part you may not want to
write again, because it is subtle and heavy: checking and making HTTP
signatures, object integrity proofs and Linked Data Signatures, and reading
JSON-LD.  It is *ojak-sig* and *ojak-jsonld* as a NIF, and does no I/O.  You
fetch, queue, send and supervise; this checks and makes.


A short tour
------------

Sign what you send, with the HTTP client you already use:

~~~~ elixir
{:ok, key} = Ojak.Key.generate(:rsa)
{:ok, signed} = Ojak.HTTPSignature.sign("POST", inbox, body, key, key_id: key_id)

Req.post!(inbox, body: body, headers: signed ++ [{"content-type", "application/activity+json"}])
~~~~

Verify what you receive.  You say how to find the key; it is not asked for
until the request has passed the checks that need no key:

~~~~ elixir
request = Ojak.Request.from_conn(conn, conn.assigns.raw_body)

{:ok, %{owner: owner}} =
  Ojak.HTTPSignature.verify(request,
    hosts: ["example.com"],
    fetch_key: fn key_id -> MyApp.Remote.fetch_actor(Ojak.HTTPSignature.key_owner(key_id)) end
  )
~~~~

A valid signature says who signed the request, not that the activity in it is
theirs.  Check `activity["actor"] == owner` yourself.

Read a document however it was spelled:

~~~~ elixir
{:ok, note} = Ojak.JsonLd.normalize(document)
note["sensitive"]  # whether it said `sensitive`, `as:sensitive`, or its own alias
~~~~

Sign an object so that it holds wherever it is found (FEP-8b32), and check one:

~~~~ elixir
{:ok, key} = Ojak.Key.generate(:ed25519)
{:ok, signed} = Ojak.Proof.sign(note, key, verification_method: "https://example.com/users/alice#ed")
{:ok, _} = Ojak.Proof.verify(signed, fetch_key: fn _vm -> {:ok, key.public} end)
~~~~

Every function that can fail returns `{:ok, value}` or `{:error, reason}`, and
has a `!` twin that raises `Ojak.Error`.  The time is the current one; `now:`
says otherwise, which is how to test.  Each module documents its own options.

 -  `Ojak.HTTPSignature`: sign and verify requests (draft-cavage, RFC 9421).
 -  `Ojak.Proof`: object integrity proofs (FEP-8b32).
 -  `Ojak.LinkedDataSignature`: `RsaSignature2017`, which Mastodon forwards.
 -  `Ojak.JsonLd`: expand, compact and normalize.
 -  `Ojak.Key`: make, keep and export keys; Multikey and `did:key`.
 -  `Ojak.Request`: a `Plug.Conn`, a tuple or a map as a request.

`Ojak.Nif` is the Rust library as it is, for these to build on.  It is not part
of the interface and may change.


What to know before you use it
------------------------------

What follows is what has not been done or has not been checked, stated plainly.

### Not shown to work

 -  **It has been run on one machine**: Linux x86\_64, Elixir 1.14, Erlang/OTP
    25.  Other platforms, and newer Elixir and OTP, are not tried.
 -  **`Ojak.Request.from_conn/2` has not met a real `Plug.Conn`.**  Plug could
    not be installed where this was written, so it was tried with a map of the
    same fields.
 -  **It has not been federated with a real server from Elixir.**  The Rust
    crates under it are held to captures from Mastodon, Fedify, Mitra and
    others by their own tests; the Elixir package is tested against itself,
    which shows that its halves agree, not that others agree with them.
 -  **ML-DSA-44 proofs are not tested from Elixir.**  The path exists.
 -  **Nothing is benchmarked.**  400 signatures and JSON-LD reads at once took
    under half a second; that is all that is known, and it was not compared
    with an Elixir implementation.
 -  **It has not been fuzzed.**  A Rust panic becomes an Elixir exception, but
    a bug that is not a panic, in a NIF, can take the VM down with it.

### Not there yet

 -  **No signed `GET`.**  Fetching with a signature (the "authorized fetch" some
    servers require) is not exposed; `ojak-sig` can, and it is not wired.
    RFC 9421 signing without a body works.  Responses are not signed or
    verified.
 -  **No fetching, no queue, no delivery.**  By design: those are yours.
    `fetch_key` is how you tell it where keys are, and a cache for them is
    yours to keep.
 -  **An RSA key's public PEM is not worked out from its private one.**  Give it
    to `Ojak.Key.from_pem/2` if you want `key.public`.  Ed25519 has both.
 -  **Keys are 2048-bit RSA, and Ed25519.**  ML-DSA-44 only verifies.
 -  **Draft-cavage is RSA only**, because that is what it is used with.

### JSON-LD is not a general processor

 -  It resolves the contexts *ojak-jsonld* ships and the ones you add, and
    fetches nothing.  A context it does not hold is not an error: its terms
    are dropped, so a document can come back with less than it said.
    `Ojak.JsonLd.normalize_with_report/2` names what was dropped.
 -  Where JSON-LD would split a property across two terms (`content` and
    `contentMap`), Ojak writes every value under one.  It is valid, and not
    always the term a given server would have chosen.
 -  A document that is too large or too deep is refused, with a reason.

### Building and running

 -  **There is no precompiled library and no Hex package.**  `mix compile`
    runs `cargo build --release`, so a Rust toolchain is needed wherever you
    build.  The Rustler Elixir package is not used (it could not be fetched
    where this was written), so the library is loaded by this project's own
    `Ojak.Nif.load_nif/0` and built by its own `ojak_nif.build` Mix task.  How
    to depend on it from another project is not worked out; start from a
    `path:` dependency.
 -  **Slow calls use the dirty CPU schedulers**, which are as many as the CPUs.
    A flood of large bodies can fill them.  Bound the size of what you accept
    before you hand it over.
 -  **The licence is AGPL-3.0-only**, as Ojak's is.  What that means for an
    application that loads this is for you to decide with the licence in hand.
 -  **Ojak is young and its API may change**, and so may this.


Layout
------

 -  *src*: The NIFs.  They turn terms into values and results back into terms,
    and nothing else.
 -  *../ojak-nif-core*: What they do, in plain Rust, tested by `cargo test`.
    It is apart because a library that calls `enif_*` cannot be linked into a
    test binary.
 -  *elixir*: The Mix project, and *elixir/test*, which tests the whole through
    a real VM:

    ~~~~ sh
    cd crates/ojak-nif/elixir
    mix test
    ~~~~

    `OJAK_NIF_PROFILE=debug` builds without optimisation, which builds faster
    and runs RSA far slower.

The split follows [Feder]'s: protocol decisions as functions of the facts they
are given, with no state kept, and the platform around them.

[Feder]: https://github.com/fedify-dev/feder
