defmodule Ojak.HTTPSignature do
  @moduledoc """
  Signing the requests you send and verifying the ones you receive: draft-cavage
  HTTP Signatures, which most of the network verifies, and RFC 9421.

  ## Sending

  `sign/5` gives the headers to send. They are covered by the signature, so
  send them as given, alongside your own:

      {:ok, key} = Ojak.Key.generate(:rsa)
      body = Jason.encode!(activity)

      {:ok, signed} =
        Ojak.HTTPSignature.sign("POST", inbox_url, body, key,
          key_id: "https://example.com/users/alice#main-key"
        )

      Req.post!(inbox_url,
        body: body,
        headers: [{"content-type", "application/activity+json"} | signed]
      )

  ## Receiving

  `verify/2` takes a request and a function that finds the key. It refuses a
  signature that does not cover the body, the host and the time *before* it
  calls that function, so a stranger cannot make you fetch a key for a request
  that was never going to pass.

      Ojak.HTTPSignature.verify(request,
        hosts: ["example.com"],
        fetch_key: fn key_id ->
          # Fetch the actor document that publishes it. A cache is yours to keep.
          MyApp.Remote.fetch_actor(Ojak.HTTPSignature.key_owner(key_id))
        end
      )
      #=> {:ok, %{key_id: "…#main-key", owner: "https://remote/users/bob", scheme: :draft_cavage, created: 1700000000}}

  The `:owner` is the actor the key belongs to, *as that actor says so too*.
  Check that the activity's `actor` is the `:owner` before you act on it: a
  valid signature says who signed the request, not that the activity in its
  body is theirs.

  A remote actor may have rotated its key since you cached it. If `verify/2`
  fails with `:invalid` on a cached key, call it again with a `fetch_key` that
  fetches afresh, as Mastodon does.

  The steps are public as well (`parse/1`, `check/3`, `verify_with_key/3`)
  for when you want to put your own work between them.
  """

  alias Ojak.{Key, Nif, Request, Util}

  @type verified :: %{
          key_id: String.t(),
          owner: String.t(),
          scheme: :draft_cavage | :rfc9421,
          created: integer() | nil
        }

  @doc """
  The headers that sign a request, as a list of `{name, value}` ready to give
  an HTTP client.

  Options:

    * `:key_id` (required) - the ID of the key, `"https://example.com/users/alice#main-key"`.
    * `:scheme` - `:draft_cavage` (the default for an RSA key) or `:rfc9421`
      (the default for an Ed25519 key, which draft-cavage cannot use).
    * `:headers` - headers you will send and want covered, such as
      `{"content-type", "application/activity+json"}`. Draft-cavage only.
    * `:now` - the time to sign at, as seconds or a `DateTime`; the current
      time by default.

  `body` is `nil` or `""` for a request without one.
  """
  @spec sign(String.t(), String.t(), binary() | nil, Key.t(), keyword()) ::
          {:ok, [{String.t(), String.t()}]} | {:error, Nif.reason()}
  def sign(method, url, body, %Key{} = key, opts) do
    key_id = Util.fetch!(opts, :key_id)
    now = Util.now(opts)

    case {Keyword.get(opts, :scheme, default_scheme(key)), key} do
      {:draft_cavage, %Key{type: :rsa, ref: ref}} ->
        extra = Keyword.get(opts, :headers, [])

        with {:ok, h} <- Nif.sign_draft_cavage(method, url, body || "", key_id, ref, extra, now) do
          {:ok, [{"signature", h.signature}, {"date", h.date}, {"digest", h.digest}]}
        end

      {:draft_cavage, _} ->
        {:error, {:unsupported, "draft-cavage signatures are made with an RSA key"}}

      {:rfc9421, key} ->
        body = if body in [nil, ""], do: nil, else: body

        with {:ok, h} <- Nif.sign_rfc9421(method, url, body, key_id, signing_key(key), now) do
          {:ok,
           [{"signature-input", h.signature_input}, {"signature", h.signature}] ++
             if(h.content_digest, do: [{"content-digest", h.content_digest}], else: [])}
        end

      {other, _} ->
        {:error, {:unsupported, "no scheme #{inspect(other)}"}}
    end
  end

  @doc "`sign/5`, raising `Ojak.Error` if it fails."
  @spec sign!(String.t(), String.t(), binary() | nil, Key.t(), keyword()) ::
          [{String.t(), String.t()}]
  def sign!(method, url, body, key, opts), do: sign(method, url, body, key, opts) |> Util.bang()

  @doc """
  Verify a signed request. See the module documentation.

  Options:

    * `:hosts` (required) - the hosts this server answers to; a request signed
      for another is refused.
    * `:fetch_key` (required) - `fn key_id -> {:ok, actor} | {:ok, public_key} |
      {:error, reason} end`. Return the actor document that publishes the key
      (a map, as a JSON library decodes it), and the key is looked for in it and
      its owner checked. Or return a public key you already trust, such as
      `{:rsa_pem, pem}`; then the owner is taken from the key ID as it is, and
      is as sure as your own cache.
    * `:max_skew` - how far, in seconds, a signature may be from now; 3600, as
      Mastodon allows.
    * `:now` - as for `sign/5`.

  Failures are `{:error, reason}` with `reason` one of those in `Ojak.Nif`,
  plus `:key_not_published` (the actor does not publish that key) and
  `{:fetch_key, reason}` (your function failed).
  """
  @spec verify(Request.source(), keyword()) :: {:ok, verified()} | {:error, term()}
  def verify(request, opts) do
    hosts = Util.fetch!(opts, :hosts)
    fetch_key = Util.fetch!(opts, :fetch_key)
    now = Util.now(opts)

    with {:ok, nif_request} <- Request.to_nif(request),
         {:ok, signature, info} <- Nif.signature_parse(nif_request),
         :ok <- Nif.signature_check(signature, nif_request, hosts, skew(opts), now),
         {:ok, owner, key} <- resolve_key(fetch_key, info.key_id),
         :ok <- Nif.signature_verify(signature, nif_request, key) do
      {:ok, %{key_id: info.key_id, owner: owner, scheme: info.scheme, created: info.created}}
    end
  end

  @doc "`verify/2`, raising `Ojak.Error` if the request does not verify."
  @spec verify!(Request.source(), keyword()) :: verified()
  def verify!(request, opts), do: request |> verify(opts) |> Util.bang()

  @doc """
  Step one: read the signature on a request, without trusting it. Returns an
  opaque signature for the next steps and what it says about itself: `:scheme`,
  `:key_id`, `:covered`, `:created` and `:expires`.
  """
  @spec parse(Request.source()) :: {:ok, reference(), map()} | {:error, term()}
  def parse(request) do
    with {:ok, nif_request} <- Request.to_nif(request), do: Nif.signature_parse(nif_request)
  end

  @doc """
  Step two: hold a parsed signature to what it has to meet before its key is
  fetched. Options `:hosts` (required), `:max_skew` and `:now`.
  """
  @spec check(reference(), Request.source(), keyword()) :: :ok | {:error, term()}
  def check(signature, request, opts) do
    with {:ok, nif_request} <- Request.to_nif(request) do
      Nif.signature_check(
        signature,
        nif_request,
        Util.fetch!(opts, :hosts),
        skew(opts),
        Util.now(opts)
      )
    end
  end

  @doc """
  Step three: check a parsed signature against a public key you found
  (`{:rsa_pem, pem}` or `{:ed25519, key}`).
  """
  @spec verify_with_key(reference(), Request.source(), Key.public()) :: :ok | {:error, term()}
  def verify_with_key(signature, request, public_key) do
    with {:ok, nif_request} <- Request.to_nif(request),
         do: Nif.signature_verify(signature, nif_request, public_key)
  end

  @doc "The actor a key ID most likely belongs to: the key ID without its fragment."
  @spec key_owner(String.t()) :: String.t()
  def key_owner(key_id) do
    {:ok, owner} = Nif.key_owner(key_id)
    owner
  end

  defp default_scheme(%Key{type: :rsa}), do: :draft_cavage
  defp default_scheme(%Key{type: :ed25519}), do: :rfc9421

  defp signing_key(%Key{type: :rsa, ref: ref}), do: {:rsa, ref}
  defp signing_key(%Key{type: :ed25519, secret: seed}), do: {:ed25519, seed}

  defp skew(opts), do: Keyword.get(opts, :max_skew, 3600)

  defp resolve_key(fetch_key, key_id) do
    case fetch_key.(key_id) do
      {:ok, %{} = actor} ->
        with {:ok, key} <- Nif.published_key(actor, key_id) do
          case key do
            nil -> {:error, :key_not_published}
            key -> {:ok, actor["id"], key}
          end
        end

      {:ok, {kind, _} = key} when kind in [:rsa_pem, :ed25519] ->
        {:ok, key_owner(key_id), key}

      {:error, reason} ->
        {:error, {:fetch_key, reason}}

      other ->
        {:error, {:fetch_key, {:unexpected, other}}}
    end
  end
end
