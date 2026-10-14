defmodule Ojak.Util do
  @moduledoc false

  # The time an operation is made at, in seconds since the Unix epoch. The
  # native code never reads the clock; this is the one place that does, and a
  # test can pass `now:` to say what time it is.
  def now(opts) do
    case Keyword.get(opts, :now) do
      nil -> System.os_time(:second)
      seconds when is_integer(seconds) -> seconds
      %DateTime{} = at -> DateTime.to_unix(at)
    end
  end

  def fetch!(opts, key) do
    case Keyword.fetch(opts, key) do
      {:ok, value} -> value
      :error -> raise ArgumentError, "the option #{inspect(key)} is required"
    end
  end

  def bang({:ok, value}), do: value
  def bang(:ok), do: :ok
  def bang({:error, reason}), do: raise(Ojak.Error, reason: reason)
end
