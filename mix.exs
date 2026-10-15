defmodule Mix.Tasks.OjakNif.Build do
  @shortdoc "Puts the native library into priv/: a prebuilt one, or one built with cargo"
  @moduledoc """
  Puts the native library where `Ojak.Nif` loads it from (`priv/ojak_nif.so`).

  Where it comes from:

    * **As a dependency** (under `deps/`) on Linux, x86_64 or aarch64, glibc or
      musl: the library attached to the GitHub release of this version is
      downloaded, and used if its SHA-256 is the one published beside it. If the
      download fails, or the checksum is wrong, or there is no such release, it
      says so and builds with cargo instead. A library that does not match is
      never used.
    * **Anywhere else** (a clone, a `path:` dependency, another platform): built
      with cargo, which needs Rust 1.95 or newer.

  The checksum comes from the same release as the library, so it catches a
  broken download, not a release that was tampered with. If you want to know
  what the library was built from, build it yourself.

  Environment:

    * `OJAK_NIF_BUILD=1` - always build with cargo.
    * `OJAK_NIF_PREBUILT=1` - use the prebuilt library even in a clone.
    * `OJAK_NIF_BASE_URL` - fetch `libojak_nif-TARGET.so` and its `.sha256` from
      here instead of the GitHub release (a mirror, or a test).
    * `OJAK_NIF_PROFILE=debug` - build without optimisation, which is faster to
      build and far slower to run; RSA in particular.
    * `OJAK_NIF_TARGET` - a Rust target triple. Builds with `cargo build
      --target` (build scripts and procedural macros are then built without the
      flags in `RUSTFLAGS`, which a profile-guided build needs; see
      *scripts/pgo-build.sh*), and names the prebuilt library to fetch.
  """
  use Mix.Task

  @repo "https://github.com/sukhi-social/ojak-ex"
  @prebuilt_targets ~w(
    x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
    x86_64-unknown-linux-musl aarch64-unknown-linux-musl
  )
  @root __DIR__

  @impl true
  def run(_args) do
    case plan() do
      {:download, target} ->
        with {:error, reason} <- download(target) do
          Mix.shell().info(
            "ojak: no usable prebuilt library for #{target} (#{inspect(reason)}); building with cargo"
          )

          build()
        end

      :source ->
        build()
    end
  end

  defp plan do
    target = prebuilt_target()

    cond do
      System.get_env("OJAK_NIF_BUILD") == "1" ->
        :source

      target == nil ->
        :source

      System.get_env("OJAK_NIF_PREBUILT") == "1" or installed_as_dependency?() ->
        {:download, target}

      true ->
        :source
    end
  end

  # Mix compiles a dependency in `deps/NAME`. A clone, or a `path:` dependency,
  # is someone working on the code, and a prebuilt library would hide their
  # changes to the Rust.
  defp installed_as_dependency?, do: Path.basename(Path.dirname(@root)) == "deps"

  defp prebuilt_target do
    case System.get_env("OJAK_NIF_TARGET") do
      nil -> detect_target()
      target -> if target in @prebuilt_targets or System.get_env("OJAK_NIF_BASE_URL"), do: target
    end
  end

  # "x86_64-pc-linux-gnu" on Debian, "x86_64-alpine-linux-musl" on Alpine.
  defp detect_target do
    parts = :system_architecture |> :erlang.system_info() |> List.to_string() |> String.split("-")
    cpu = if hd(parts) == "arm64", do: "aarch64", else: hd(parts)
    libc = if List.last(parts) == "musl", do: "musl", else: "gnu"
    target = "#{cpu}-unknown-linux-#{libc}"
    if "linux" in parts and target in @prebuilt_targets, do: target
  end

  defp download(target) do
    version = Mix.Project.config()[:version]
    base = System.get_env("OJAK_NIF_BASE_URL") || "#{@repo}/releases/download/v#{version}"
    name = "libojak_nif-#{target}.so"
    priv = Path.join(@root, "priv")
    library_path = Path.join(priv, "ojak_nif.so")
    marker_path = Path.join(priv, "ojak_nif.prebuilt")
    stamp = "#{version} #{target}"

    # Compiling runs this every time; fetch once.
    if File.exists?(library_path) and File.read(marker_path) == {:ok, stamp} do
      :ok
    else
      with {:ok, library} <- fetch("#{base}/#{name}"),
           {:ok, listed} <- fetch("#{base}/#{name}.sha256"),
           {:ok, sum} <- check(library, listed) do
        File.mkdir_p!(priv)
        part = library_path <> ".part"
        File.write!(part, library)
        # A rename, so that a library a running VM has mapped is not overwritten.
        File.rename!(part, library_path)
        File.write!(marker_path, stamp)

        Mix.shell().info(
          "ojak: using the prebuilt library for #{target} (v#{version}, sha256 #{sum})"
        )

        :ok
      end
    end
  end

  defp check(library, listed) do
    expected = listed |> String.split() |> List.first("") |> String.downcase()
    actual = :sha256 |> :crypto.hash(library) |> Base.encode16(case: :lower)

    if expected == actual,
      do: {:ok, String.slice(actual, 0, 12)},
      else: {:error, :checksum_mismatch}
  end

  defp fetch(url) do
    ensure_otp_apps()
    {:ok, _} = Application.ensure_all_started(:inets)
    {:ok, _} = Application.ensure_all_started(:ssl)

    options = [timeout: 60_000, connect_timeout: 15_000, autoredirect: true, ssl: ssl_options()]
    request = {String.to_charlist(url), [{~c"user-agent", ~c"ojak-ex"}]}

    case :httpc.request(:get, request, options, body_format: :binary) do
      {:ok, {{_, 200, _}, _headers, body}} -> {:ok, body}
      {:ok, {{_, status, _}, _headers, _body}} -> {:error, {:http, status}}
      {:error, reason} -> {:error, reason}
    end
  rescue
    error -> {:error, Exception.message(error)}
  end

  # Mix prunes OTP applications that the project does not list from the code
  # path (since Elixir 1.15), and an earlier dependency's compile can leave it
  # that way, so `:public_key` and friends may be "not available" here even
  # though they are installed. Put them back before they are called.
  defp ensure_otp_apps do
    lib = Path.join(List.to_string(:code.root_dir()), "lib")

    for app <- ~w(crypto asn1 public_key ssl inets)a,
        match?({:error, _}, :code.lib_dir(app)),
        ebin <- Path.wildcard(Path.join([lib, "#{app}-*", "ebin"])) do
      Code.prepend_path(ebin)
    end

    :ok
  end

  # The system's certificate authorities (OTP 25 and newer), and the name the
  # certificate has to match.
  defp ssl_options do
    [
      verify: :verify_peer,
      cacerts: :public_key.cacerts_get(),
      customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
    ]
  end

  defp build do
    File.rm(Path.join([@root, "priv", "ojak_nif.prebuilt"]))

    unless System.find_executable("cargo") do
      Mix.raise("""
      ojak needs a Rust toolchain (1.95 or newer) to build its native library, and
      there is no prebuilt one for this platform or no way to fetch it.
      Prebuilt libraries exist for Linux (x86_64 and aarch64, glibc and musl).
      Install Rust from https://rustup.rs and compile again.
      """)
    end

    profile = System.get_env("OJAK_NIF_PROFILE", "release")
    flags = if profile == "release", do: ["--release"], else: []
    target = System.get_env("OJAK_NIF_TARGET")
    flags = if target, do: flags ++ ["--target", target], else: flags

    {_, status} =
      System.cmd("cargo", ["build", "-p", "ojak-nif" | flags],
        cd: @root,
        into: IO.stream(:stdio, :line)
      )

    if status != 0, do: Mix.raise("cargo build failed (#{status})")

    ext = if match?({:unix, :darwin}, :os.type()), do: "dylib", else: "so"
    built = Path.join([@root, "target"] ++ List.wrap(target) ++ [profile, "libojak_nif.#{ext}"])
    priv = Path.join(@root, "priv")
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
      version: "0.1.2",
      elixir: "~> 1.14",
      deps: [],
      aliases: [compile: ["ojak_nif.build", "compile"]],
      description: "Ojak's signatures and JSON-LD for Elixir, as a NIF"
    ]
  end

  def application, do: [extra_applications: [:logger]]
end
