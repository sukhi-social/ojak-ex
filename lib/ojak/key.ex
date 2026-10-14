defmodule Ojak.Key do
  @moduledoc """
  A key an actor signs with: RSA, which most of the network verifies, or
  Ed25519.

  A key is parsed once, when you make it, and the struct keeps it: parsing an
  RSA key costs more than signing with it, so make a key at start-up (or when
  an actor is loaded) and keep it, rather than building one for each request.

  `inspect/1` shows the type and the public key, never the secret. To store a
  key, take the secret out with `export/1` and give it back with `from_pem/2`
  or `from_seed/1`.

  A *public* key is a tuple, as `Ojak.HTTPSignature.verify/2` and
  `Ojak.Proof.verify/2` take it:

    * `{:rsa_pem, pem}`
    * `{:ed25519, <<32 bytes>>}`
  """

  alias Ojak.Nif

  @derive {Inspect, only: [:type, :public]}
  defstruct [:type, :public, :secret, :ref]

  @type public :: {:rsa_pem, String.t()} | {:ed25519, <<_::256>>}
  @type t :: %__MODULE__{
          type: :rsa | :ed25519,
          public: public() | nil,
          secret: String.t() | <<_::256>>,
          ref: reference() | nil
        }

  @doc """
  A new key, with the system's randomness. RSA keys are 2048 bits.

      {:ok, key} = Ojak.Key.generate(:ed25519)
  """
  @spec generate(:rsa | :ed25519) :: {:ok, t()} | {:error, Ojak.Nif.reason()}
  def generate(:rsa) do
    with {:ok, {private_pem, public_pem}} <- Nif.rsa_generate_keypair() do
      from_pem(private_pem, public_pem)
    end
  end

  def generate(:ed25519) do
    with {:ok, seed} <- Nif.ed25519_generate_seed(), do: from_seed(seed)
  end

  @doc "`generate/1`, raising `Ojak.Error` if it fails."
  @spec generate!(:rsa | :ed25519) :: t()
  def generate!(type), do: type |> generate() |> Ojak.Util.bang()

  @doc """
  An RSA key from its private PEM (PKCS#8 or PKCS#1). The public PEM, which is
  what an actor publishes, is not worked out from the private one; give it if
  you want `key.public` filled in.
  """
  @spec from_pem(String.t(), String.t() | nil) :: {:ok, t()} | {:error, Ojak.Nif.reason()}
  def from_pem(private_pem, public_pem \\ nil) when is_binary(private_pem) do
    with {:ok, ref} <- Nif.rsa_private_key(private_pem) do
      public = if public_pem, do: {:rsa_pem, public_pem}
      {:ok, %__MODULE__{type: :rsa, public: public, secret: private_pem, ref: ref}}
    end
  end

  @doc "An Ed25519 key from its 32-byte seed, which is the private key."
  @spec from_seed(<<_::256>>) :: {:ok, t()} | {:error, Ojak.Nif.reason()}
  def from_seed(seed) when is_binary(seed) do
    with {:ok, public} <- Nif.ed25519_public_key(seed) do
      {:ok, %__MODULE__{type: :ed25519, public: {:ed25519, public}, secret: seed}}
    end
  end

  @doc """
  The secret to store: the private PEM of an RSA key, or the seed of an Ed25519
  one. Treat it as a password.
  """
  @spec export(t()) :: String.t() | <<_::256>>
  def export(%__MODULE__{secret: secret}), do: secret

  @doc """
  The Multikey (`"z6Mk…"`) an actor publishes an Ed25519 key as in its
  `assertionMethod`.
  """
  @spec multikey(t() | public()) :: {:ok, String.t()} | {:error, Ojak.Nif.reason()}
  def multikey(%__MODULE__{public: {:ed25519, _} = public}), do: multikey(public)
  def multikey({:ed25519, public}), do: Nif.ed25519_multikey_encode(public)
  def multikey(_), do: {:error, {:unsupported, "only Ed25519 keys have a Multikey"}}

  @doc "The public key a Multikey carries: `{:ed25519, key}` or `{:mldsa44, key}`."
  @spec decode_multikey(String.t()) ::
          {:ok, {:ed25519 | :mldsa44, binary()}} | {:error, Ojak.Nif.reason()}
  defdelegate decode_multikey(multibase), to: Nif, as: :multikey_decode

  @doc "The `did:key` of an Ed25519 key."
  @spec did(t() | public()) :: {:ok, String.t()} | {:error, Ojak.Nif.reason()}
  def did(%__MODULE__{public: {:ed25519, _} = public}), do: did(public)
  def did({:ed25519, public}), do: Nif.did_key(public)
  def did(_), do: {:error, {:unsupported, "only Ed25519 keys have a did:key"}}
end
