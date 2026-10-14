defmodule Ojak.Error do
  @moduledoc """
  What the `!` functions raise. The `:reason` is the same term the non-bang
  function returns in `{:error, reason}`, so the two can be matched alike.
  """
  defexception [:reason]

  @type t :: %__MODULE__{reason: term()}

  @impl true
  def message(%__MODULE__{reason: reason}), do: "Ojak failed: " <> describe(reason)

  defp describe(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp describe({reason, detail}) when is_atom(reason), do: "#{reason} (#{inspect(detail)})"
  defp describe(reason), do: inspect(reason)
end
