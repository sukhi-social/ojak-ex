defmodule Mix.Tasks.OjakNif.Build do
  @shortdoc "Builds the native library into priv/"
  @moduledoc """
  Builds the `ojak-nif` crate and puts the library where `Ojak.Nif` loads it
  from. `OJAK_NIF_PROFILE=debug` builds without optimisation, which is faster
  to build and far slower to run; RSA in particular.
  """
  use Mix.Task

  @impl true
  def run(_args) do
    profile = System.get_env("OJAK_NIF_PROFILE", "release")
    workspace = Path.expand("../../..", __DIR__)
    flags = if profile == "release", do: ["--release"], else: []

    {_, status} =
      System.cmd("cargo", ["build", "-p", "ojak-nif" | flags],
        cd: workspace,
        into: IO.stream(:stdio, :line)
      )

    if status != 0, do: Mix.raise("cargo build failed (#{status})")

    ext = if match?({:unix, :darwin}, :os.type()), do: "dylib", else: "so"
    built = Path.join([workspace, "target", profile, "libojak_nif.#{ext}"])
    priv = Path.join(__DIR__, "priv")
    File.mkdir_p!(priv)
    # The BEAM loads `priv/ojak_nif` and finds the `.so` whatever the platform
    # calls its libraries. Copying to a new name also avoids overwriting a
    # library a running VM has mapped.
    File.cp!(built, Path.join(priv, "ojak_nif.so"))
    :ok
  end
end

defmodule OjakNif.MixProject do
  use Mix.Project

  def project do
    [
      app: :ojak,
      version: "0.1.0",
      elixir: "~> 1.14",
      deps: [],
      aliases: [compile: ["ojak_nif.build", "compile"]],
      description: "Ojak's signatures and JSON-LD for Elixir, as a NIF"
    ]
  end

  def application, do: [extra_applications: [:logger]]
end
