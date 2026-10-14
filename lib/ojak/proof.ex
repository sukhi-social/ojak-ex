defmodule Ojak.Proof do
  @moduledoc """
  Object integrity proofs (FEP-8b32): a signature carried *in* an object, so
  that it holds wherever the object is found, not only on the request that
  delivered it. `eddsa-jcs-2022` is made and checked; `mldsa44-jcs-2024`, the
  post-quantum suite, is checked.

      {:ok, key} = Ojak.Key.generate(:ed25519)

      {:ok, signed} =
        Ojak.Proof.sign(note, key,
          verification_method: "https://example.com/users/alice#ed25519-key"
        )

      Ojak.Proof.verify(signed,
        fetch_key: fn verification_method ->
          # Find the actor, read the Multikey in its assertionMethod, and decode it.
          {:ok, {:ed25519, public_key}}
        end
      )
      #=> {:ok, %{verification_method: "…#ed25519-key", cryptosuite: "eddsa-jcs-2022"}}
  """

  alias Ojak.{Key, Nif, Util}

  @type json :: Nif.json()

  @doc """
  The object with a proof made by `key`, and the Data Integrity context a
  reader needs in order to find it.

  Options: `:verification_method` (required) - the ID of the key in the actor's
  `assertionMethod`; `:now`.
  """
  @spec sign(json(), Key.t(), keyword()) :: {:ok, json()} | {:error, Nif.reason()}
  def sign(document, %Key{type: :ed25519, secret: seed}, opts) do
    Nif.integrity_sign(document, Util.fetch!(opts, :verification_method), seed, Util.now(opts))
  end

  def sign(_document, %Key{}, _opts),
    do: {:error, {:unsupported, "proofs are made with an Ed25519 key"}}

  @doc "`sign/3`, raising `Ojak.Error` if it fails."
  @spec sign!(json(), Key.t(), keyword()) :: json()
  def sign!(document, key, opts), do: document |> sign(key, opts) |> Util.bang()

  @doc """
  Check that an object carries a proof that verifies, and which one.

  An object may carry several proofs, by different keys or in different suites,
  and one that does not verify says nothing about the others: this succeeds
  with the first that does.

  Options:

    * `:fetch_key` (required) - `fn verification_method -> {:ok, public_key} |
      {:error, reason} end`, the key as `{:ed25519, key}` or `{:mldsa44, key}`.
      `Ojak.Key.decode_multikey/1` reads the Multikey an actor publishes.
    * `:now` - proofs that have expired at this time are not considered.

  Fails with `:no_proof` when there is nothing usable to check, and
  `{:no_valid_proof, reasons}` when there is and none verifies.
  """
  @spec verify(json(), keyword()) ::
          {:ok, %{verification_method: String.t(), cryptosuite: String.t()}}
          | {:error, :no_proof | {:no_valid_proof, [term()]} | Nif.reason()}
  def verify(document, opts) do
    fetch_key = Util.fetch!(opts, :fetch_key)

    with {:ok, proofs} <- Nif.integrity_proofs(document, Util.now(opts)) do
      case proofs do
        [] -> {:error, :no_proof}
        proofs -> first_valid(document, proofs, fetch_key, [])
      end
    end
  end

  @doc "`verify/2`, raising `Ojak.Error` if no proof verifies."
  @spec verify!(json(), keyword()) :: %{verification_method: String.t(), cryptosuite: String.t()}
  def verify!(document, opts), do: document |> verify(opts) |> Util.bang()

  defp first_valid(_document, [], _fetch_key, errors),
    do: {:error, {:no_valid_proof, Enum.reverse(errors)}}

  defp first_valid(document, [proof | rest], fetch_key, errors) do
    outcome =
      case fetch_key.(proof.verification_method) do
        {:ok, {kind, _} = key} when kind in [:ed25519, :mldsa44] ->
          Nif.integrity_verify(document, proof.proof, key)

        {:error, reason} ->
          {:error, {:fetch_key, reason}}

        other ->
          {:error, {:fetch_key, {:unexpected, other}}}
      end

    case outcome do
      :ok ->
        {:ok, %{verification_method: proof.verification_method, cryptosuite: proof.cryptosuite}}

      {:error, reason} ->
        first_valid(document, rest, fetch_key, [{proof.verification_method, reason} | errors])
    end
  end
end
