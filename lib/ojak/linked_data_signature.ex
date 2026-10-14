defmodule Ojak.LinkedDataSignature do
  @moduledoc """
  Linked Data Signatures (`RsaSignature2017`), as Mastodon makes them: a
  signature carried in an activity, so that it can be forwarded (a reply
  fetched through a relay, a `Delete` passed on) and still be believed.

  Nearly everything newer uses `Ojak.Proof`; this is for what Mastodon sends.

      {:ok, signed} =
        Ojak.LinkedDataSignature.sign(activity, key,
          key_id: "https://example.com/users/alice#main-key"
        )

      Ojak.LinkedDataSignature.verify(signed,
        fetch_key: fn creator -> {:ok, {:rsa_pem, pem}} end
      )
      #=> {:ok, "https://example.com/users/alice#main-key"}
  """

  alias Ojak.{Key, Nif, Util}

  @day 24 * 60 * 60

  @doc """
  The activity with an `RsaSignature2017` made as `:key_id` (required) by an
  RSA `key`, good for `:lifetime` seconds (two days by default, as Mastodon's)
  from `:now`. A registry other than the default may be given as `:registry`.
  """
  @spec sign(Nif.json(), Key.t(), keyword()) :: {:ok, Nif.json()} | {:error, Nif.reason()}
  def sign(document, %Key{type: :rsa, ref: ref}, opts) do
    now = Util.now(opts)
    lifetime = Keyword.get(opts, :lifetime, 2 * @day)

    Nif.linked_data_sign(
      Keyword.get(opts, :registry),
      document,
      Util.fetch!(opts, :key_id),
      ref,
      now,
      now + lifetime
    )
  end

  def sign(_document, %Key{}, _opts),
    do: {:error, {:unsupported, "Linked Data Signatures are made with an RSA key"}}

  @doc "`sign/3`, raising `Ojak.Error` if it fails."
  @spec sign!(Nif.json(), Key.t(), keyword()) :: Nif.json()
  def sign!(document, key, opts), do: document |> sign(key, opts) |> Util.bang()

  @doc """
  Check the signature on an activity. Returns the `creator` it names, the key
  that signed it.

  Options:

    * `:fetch_key` (required) - `fn creator -> {:ok, {:rsa_pem, pem}} |
      {:error, reason} end`, given the key ID the signature names.
    * `:registry`, `:now` - as for `sign/3`.

  The signature says its key's holder signed this document, not who that is:
  the key you return is how the creator is tied to an actor, so check that the
  creator belongs to the activity's `actor`.
  """
  @spec verify(Nif.json(), keyword()) :: {:ok, String.t()} | {:error, term()}
  def verify(document, opts) do
    fetch_key = Util.fetch!(opts, :fetch_key)

    with {:ok, creator} when is_binary(creator) <- Nif.linked_data_creator(document),
         {:ok, {:rsa_pem, pem}} <- fetch(fetch_key, creator),
         :ok <-
           Nif.linked_data_verify(Keyword.get(opts, :registry), document, pem, Util.now(opts)) do
      {:ok, creator}
    else
      {:ok, nil} -> {:error, :no_signature}
      other -> other
    end
  end

  @doc "`verify/2`, raising `Ojak.Error` if it does not verify."
  @spec verify!(Nif.json(), keyword()) :: String.t()
  def verify!(document, opts), do: document |> verify(opts) |> Util.bang()

  defp fetch(fetch_key, creator) do
    case fetch_key.(creator) do
      {:ok, {:rsa_pem, _}} = ok -> ok
      {:error, reason} -> {:error, {:fetch_key, reason}}
      other -> {:error, {:fetch_key, {:unexpected, other}}}
    end
  end
end
