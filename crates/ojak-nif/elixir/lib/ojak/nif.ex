defmodule Ojak.Nif do
  @moduledoc false
  # The Rust library as it is. Use `Ojak.HTTPSignature`, `Ojak.Proof`,
  # `Ojak.LinkedDataSignature`, `Ojak.JsonLd` and `Ojak.Key`; their
  # documentation says how this behaves, and this module's functions and
  # types are for them. The notes that follow are the contract they rely on.
  #
  #   * A JSON document is a map with string keys, as a JSON library decodes it.
  #   * Time is an argument, in seconds since the Unix epoch.
  #   * Anything that can take a millisecond runs on a dirty CPU scheduler.
  #   * Wrong content comes back as `{:error, reason}`; a call of the wrong
  #     shape raises `ArgumentError`.
  #   * A reason is an atom, or an atom and a detail: `:unsigned`,
  #     `{:malformed, text}`, `{:not_covered, name}`, `{:missing_header, name}`,
  #     `:digest_mismatch`, `{:stale, seconds}`, `{:expired, seconds}`,
  #     `{:wrong_host, host}`, `:invalid` and `{:invalid, text}`, `{:key, text}`,
  #     `{:wrong_key, text}`, `{:unsupported, text}`, `{:missing, text}`,
  #     `{:jsonld, text}` and `{:invalid_argument, text}`.

  @on_load :load_nif

  @typedoc "A JSON document, as a JSON library decodes it."
  @type json ::
          nil | boolean() | number() | String.t() | [json()] | %{optional(String.t()) => json()}

  @typedoc "`{method, path_and_query, [{name, value}], body}`"
  @type request :: {String.t(), String.t(), [{String.t(), String.t()}], binary()}

  @typedoc "A reason a call did not succeed. See the module documentation."
  @type reason :: atom() | {atom(), String.t() | integer()}

  @typedoc "An RSA private key, parsed once. Opaque."
  @type rsa_private_key :: reference()

  @typedoc "A signature read from a request, not yet checked. Opaque."
  @type signature :: reference()

  @typedoc "A set of JSON-LD contexts, and the contexts processed from them. Opaque."
  @type registry :: reference()

  @typedoc "A key a signature is checked against."
  @type verification_key :: {:rsa_pem, String.t()} | {:ed25519, <<_::256>>}

  @doc false
  def load_nif do
    path = :filename.join(:code.priv_dir(:ojak), ~c"ojak_nif")
    :erlang.load_nif(path, 0)
  end

  # -- keys -------------------------------------------------------------

  @doc """
  A new 2048-bit RSA key pair, as `{private_pem, public_pem}`: PKCS#8 and SPKI.
  Randomness is the system's.
  """
  @spec rsa_generate_keypair() :: {:ok, {String.t(), String.t()}} | {:error, reason()}
  def rsa_generate_keypair, do: nif_error()

  @doc "Parse an RSA private key (PKCS#8 or PKCS#1 PEM) once, for signing."
  @spec rsa_private_key(String.t()) :: {:ok, rsa_private_key()} | {:error, reason()}
  def rsa_private_key(_pem), do: nif_error()

  @doc "A new raw 32-byte Ed25519 seed, which is the private key."
  @spec ed25519_generate_seed() :: {:ok, <<_::256>>}
  def ed25519_generate_seed, do: nif_error()

  @doc "The 32-byte public key of an Ed25519 seed."
  @spec ed25519_public_key(<<_::256>>) :: {:ok, <<_::256>>} | {:error, reason()}
  def ed25519_public_key(_seed), do: nif_error()

  @doc "The Multikey (`\"z6Mk…\"`) an actor publishes an Ed25519 public key as."
  @spec ed25519_multikey_encode(<<_::256>>) :: {:ok, String.t()} | {:error, reason()}
  def ed25519_multikey_encode(_public_key), do: nif_error()

  @doc "The key a Multikey carries: Ed25519, or the post-quantum ML-DSA-44."
  @spec multikey_decode(String.t()) :: {:ok, {:ed25519 | :mldsa44, binary()}} | {:error, reason()}
  def multikey_decode(_multibase), do: nif_error()

  @doc "The `did:key` of an Ed25519 public key."
  @spec did_key(<<_::256>>) :: {:ok, String.t()} | {:error, reason()}
  def did_key(_public_key), do: nif_error()

  # -- signing ----------------------------------------------------------

  @doc """
  Sign a request with draft-cavage HTTP Signatures, which most of the network
  verifies.

  Returns the headers to send: `Signature`, `Date` and `Digest`. They are
  covered by the signature, so send them as given. `extra_headers` are headers
  you will send and want covered, such as `{"content-type", "application/activity+json"}`.
  """
  @spec sign_draft_cavage(
          String.t(),
          String.t(),
          binary(),
          String.t(),
          rsa_private_key(),
          [{String.t(), String.t()}],
          integer()
        ) ::
          {:ok, %{signature: String.t(), date: String.t(), digest: String.t()}}
          | {:error, reason()}
  def sign_draft_cavage(_method, _url, _body, _key_id, _key, _extra_headers, _now),
    do: nif_error()

  @doc """
  Sign a request with RFC 9421, with `{:rsa, key}` or `{:ed25519, seed}`. `body`
  is `nil` for a request without one.

  Returns the `Signature-Input` and `Signature` headers, and the
  `Content-Digest` when there is a body, which is covered and must be sent as
  given.
  """
  @spec sign_rfc9421(
          String.t(),
          String.t(),
          binary() | nil,
          String.t(),
          {:rsa, rsa_private_key()} | {:ed25519, <<_::256>>},
          integer()
        ) ::
          {:ok,
           %{
             signature_input: String.t(),
             signature: String.t(),
             content_digest: String.t() | nil
           }}
          | {:error, reason()}
  def sign_rfc9421(_method, _url, _body, _key_id, _key, _now), do: nif_error()

  @doc "Whether a `Digest` header describes `body`."
  @spec digest_matches(String.t(), binary()) :: boolean()
  def digest_matches(_header, _body), do: nif_error()

  @doc "Whether a `Content-Digest` header describes `body`."
  @spec content_digest_matches(String.t(), binary()) :: boolean()
  def content_digest_matches(_header, _body), do: nif_error()

  @doc "The `Content-Digest` header value for `body`."
  @spec content_digest(binary()) :: String.t()
  def content_digest(_body), do: nif_error()

  # -- verification -----------------------------------------------------

  @doc """
  Step one of checking a request: read its signature, draft-cavage or RFC
  9421. Returns an opaque signature for the next steps, and what it says about
  itself: `:scheme` (`:draft_cavage` or `:rfc9421`), `:key_id`, `:covered`,
  `:created` and `:expires` (seconds, or `nil`). Nothing in it is trusted yet.
  """
  @spec signature_parse(request()) ::
          {:ok, signature(),
           %{
             scheme: :draft_cavage | :rfc9421,
             key_id: String.t(),
             covered: [String.t()],
             created: integer() | nil,
             expires: integer() | nil
           }}
          | {:error, reason()}
  def signature_parse(_request), do: nif_error()

  @doc """
  Step two: hold the signature to what it has to meet before its key is even
  fetched. It covers the target, the host and the time, and for a request with
  a body, a digest that matches it; it was made within `max_skew_seconds` of
  `now` (Mastodon allows 3600); it has not expired; and it was made for one of
  `hosts`, the hosts this server answers to.
  """
  @spec signature_check(signature(), request(), [String.t()], integer(), integer()) ::
          :ok | {:error, reason()}
  def signature_check(_signature, _request, _hosts, _max_skew_seconds, _now), do: nif_error()

  @doc """
  Step three: check the signature against the key you found, as
  `{:rsa_pem, pem}` or `{:ed25519, public_key}`. Draft-cavage is checked with
  RSA; RFC 9421 with either.
  """
  @spec signature_verify(signature(), request(), verification_key()) ::
          :ok | {:error, reason()}
  def signature_verify(_signature, _request, _key), do: nif_error()

  @doc "The actor a key ID most likely belongs to: the key ID without its fragment."
  @spec key_owner(String.t()) :: {:ok, String.t()} | {:error, reason()}
  def key_owner(_key_id), do: nif_error()

  @doc """
  The key `actor` publishes as `key_id`, or `nil` if it does not publish it.

  The key ID says which actor a key belongs to; the actor has to say so too.
  Reads a `publicKey` (RSA) or an Ed25519 `assertionMethod` Multikey.
  """
  @spec published_key(json(), String.t()) ::
          {:ok, verification_key() | nil} | {:error, reason()}
  def published_key(_actor, _key_id), do: nif_error()

  # -- object integrity proofs (FEP-8b32) ------------------------------------

  @doc """
  The usable integrity proofs on an object at `now`. Each is a map of `:proof`,
  `:cryptosuite` and `:verification_method`; resolve the last to a key of the
  matching kind and pass it to `integrity_verify/3`. A proof that does not
  verify says nothing about the others.
  """
  @spec integrity_proofs(json(), integer()) ::
          {:ok, [%{proof: json(), cryptosuite: String.t(), verification_method: String.t()}]}
          | {:error, reason()}
  def integrity_proofs(_document, _now), do: nif_error()

  @doc "Check one proof on an object against `{:ed25519, key}` or `{:mldsa44, key}`."
  @spec integrity_verify(json(), json(), {:ed25519 | :mldsa44, binary()}) ::
          :ok | {:error, reason()}
  def integrity_verify(_document, _proof, _key), do: nif_error()

  @doc """
  The object with an `eddsa-jcs-2022` proof made by `seed`, and the Data
  Integrity context a reader needs in order to find it. `verification_method`
  is the ID of the key in the actor's `assertionMethod`.
  """
  @spec integrity_sign(json(), String.t(), <<_::256>>, integer()) ::
          {:ok, json()} | {:error, reason()}
  def integrity_sign(_document, _verification_method, _seed, _now), do: nif_error()

  # -- JSON-LD ----------------------------------------------------------

  @doc """
  A registry of contexts: the ones Ojak ships, and your own, as
  `%{iri => context_document}`. Pass `nil` where a registry is taken to use
  the contexts Ojak ships.

  Keep a registry for as long as you can. It holds the contexts it has
  processed, which nearly every document a server receives shares, so reading
  a document with a known context does not process it again.
  """
  @spec jsonld_registry(%{optional(String.t()) => json()}) ::
          {:ok, registry()} | {:error, reason()}
  def jsonld_registry(_contexts), do: nif_error()

  @doc """
  Expand a document: every key becomes the IRI it stands for. The result is
  `{:ok, expanded, unresolved}`; `unresolved` lists contexts the document named
  that the registry does not hold, whose terms were dropped. That is not an
  error, though worth logging.
  """
  @spec jsonld_expand(registry() | nil, json()) ::
          {:ok, json(), [String.t()]} | {:error, reason()}
  def jsonld_expand(_registry, _document), do: nif_error()

  @doc "Compact an expanded document against a `@context` value."
  @spec jsonld_compact(registry() | nil, json(), json()) ::
          {:ok, json(), [String.t()]} | {:error, reason()}
  def jsonld_compact(_registry, _expanded, _context), do: nif_error()

  @doc """
  Read a document however it was written, and get it back in Ojak's own
  spelling: aliases and extension vocabularies resolved, and written with the
  terms Ojak expects. The work a document may cause is bounded, so a stranger's
  document cannot make it unbounded.
  """
  @spec jsonld_normalize(registry() | nil, json()) ::
          {:ok, json(), [String.t()]} | {:error, reason()}
  def jsonld_normalize(_registry, _document), do: nif_error()

  # -- Linked Data Signatures (RsaSignature2017) ---------------------------

  @doc "The `creator` an `RsaSignature2017` names, or `nil`. It does not say the signature verifies."
  @spec linked_data_creator(json()) :: {:ok, String.t() | nil} | {:error, reason()}
  def linked_data_creator(_document), do: nif_error()

  @doc """
  Check the `RsaSignature2017` on a document against the PEM of the key its
  creator names, at `now`. You found that key, and know whose it is: the
  signature says its holder signed this document, not who the holder is.
  """
  @spec linked_data_verify(registry() | nil, json(), String.t(), integer()) ::
          :ok | {:error, reason()}
  def linked_data_verify(_registry, _document, _public_key_pem, _now), do: nif_error()

  @doc """
  The document with an `RsaSignature2017` made as `key_id`, good from `created`
  until `expires` (seconds).
  """
  @spec linked_data_sign(
          registry() | nil,
          json(),
          String.t(),
          rsa_private_key(),
          integer(),
          integer()
        ) :: {:ok, json()} | {:error, reason()}
  def linked_data_sign(_registry, _document, _key_id, _key, _created, _expires),
    do: nif_error()

  defp nif_error, do: :erlang.nif_error(:nif_not_loaded)
end
