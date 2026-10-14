defmodule Ojak.JsonLd do
  @moduledoc """
  Reading JSON-LD the way the fediverse writes it.

  ActivityPub is JSON-LD, which means a key is not a name but an abbreviation
  for an IRI, and the `@context` says which. Two servers can describe the same
  thing with different keys (`sensitive`, `as:sensitive`, or any term aliased
  to either) and a reader that matches on spelling reads one and drops the
  other. `normalize/2` resolves what a document says and gives it back in one
  spelling, so that you match on that:

      {:ok, note} = Ojak.JsonLd.normalize(document)
      note["sensitive"]

  This is not a general JSON-LD processor. It resolves the contexts Ojak ships
  (ActivityStreams, the security vocabularies, Mastodon's, and so on) and those
  you add to a registry; it fetches nothing. A context it does not hold is not
  an error: its terms are dropped, and `normalize_with_report/2` says which.
  The work one document may cause is bounded, so that a stranger's cannot
  take unbounded time or memory.

  ## Registries

  Every function takes `registry: registry`, and uses the contexts Ojak ships
  without one. A registry holds the contexts it has processed, which nearly
  every document a server receives shares, so a long-lived one is much cheaper
  than none. Make it once, in your application's start-up, and keep it where
  every process can read it:

      {:ok, registry} = Ojak.JsonLd.registry(%{"https://example.com/ns" => context})
      :persistent_term.put({MyApp, :json_ld}, registry)
  """

  alias Ojak.{Nif, Util}

  @opaque registry :: reference()

  @doc """
  A registry: the contexts Ojak ships, and your own, as `%{iri => document}`,
  each document being what the IRI would have served (an object with an
  `@context` member).
  """
  @spec registry(%{optional(String.t()) => Nif.json()}) :: {:ok, registry()} | {:error, term()}
  def registry(contexts \\ %{}), do: Nif.jsonld_registry(contexts)

  @doc """
  The document in Ojak's own spelling: aliases and extension vocabularies
  resolved, and written with the terms Ojak's vocabulary expects.
  """
  @spec normalize(Nif.json(), keyword()) :: {:ok, Nif.json()} | {:error, term()}
  def normalize(document, opts \\ []), do: strip(normalize_with_report(document, opts))

  @doc """
  As `normalize/2`, and the IRIs of the contexts the document named that the
  registry does not hold, whose terms were dropped. A peer whose documents
  come back emptier than expected has usually started using a new extension.
  """
  @spec normalize_with_report(Nif.json(), keyword()) ::
          {:ok, Nif.json(), [String.t()]} | {:error, term()}
  def normalize_with_report(document, opts \\ []),
    do: Nif.jsonld_normalize(Keyword.get(opts, :registry), document)

  @doc "`normalize/2`, raising `Ojak.Error` if it fails."
  @spec normalize!(Nif.json(), keyword()) :: Nif.json()
  def normalize!(document, opts \\ []), do: document |> normalize(opts) |> Util.bang()

  @doc """
  Expand a document: every key becomes the IRI it stands for. The result is a
  list of node objects, the form to compare two documents in.
  """
  @spec expand(Nif.json(), keyword()) :: {:ok, Nif.json()} | {:error, term()}
  def expand(document, opts \\ []),
    do: strip(Nif.jsonld_expand(Keyword.get(opts, :registry), document))

  @doc "Compact an expanded document against a `@context` value."
  @spec compact(Nif.json(), Nif.json(), keyword()) :: {:ok, Nif.json()} | {:error, term()}
  def compact(expanded, context, opts \\ []),
    do: strip(Nif.jsonld_compact(Keyword.get(opts, :registry), expanded, context))

  defp strip({:ok, document, _unresolved}), do: {:ok, document}
  defp strip(other), do: other
end
