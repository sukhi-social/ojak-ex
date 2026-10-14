defmodule Ojak.Request do
  @moduledoc """
  A request as it arrived, in the form the signature functions read.

  Anything that carries the four parts will do. Of the common sources:

    * a `Plug.Conn` and the body you read, with `from_conn/2`;
    * a tuple `{method, path_and_query, headers, body}`;
    * a map with `:method`, `:path` (with the query), `:headers` and `:body`.

  Header names may be in any case; values must be UTF-8.

  ## With Plug

  The signature covers the body's digest, so the *raw* body is needed, and
  `Plug.Parsers` has read it by the time a controller runs. Keep it with a
  `:body_reader`:

      defmodule MyApp.CacheBodyReader do
        def read_body(conn, opts) do
          with {:ok, body, conn} <- Plug.Conn.read_body(conn, opts) do
            {:ok, body, Plug.Conn.assign(conn, :raw_body, body)}
          end
        end
      end

      plug Plug.Parsers,
        parsers: [:json],
        json_decoder: Jason,
        body_reader: {MyApp.CacheBodyReader, :read_body, []}

  and then `Ojak.Request.from_conn(conn, conn.assigns.raw_body)`.
  """

  defstruct [:method, :path, :headers, :body]

  @type t :: %__MODULE__{
          method: String.t(),
          path: String.t(),
          headers: [{String.t(), String.t()}],
          body: binary()
        }

  @type source ::
          t()
          | {String.t(), String.t(), [{String.t(), String.t()}], binary()}
          | %{
              required(:method) => String.t(),
              required(:path) => String.t(),
              required(:headers) => [{String.t(), String.t()}],
              optional(:body) => binary()
            }

  @doc """
  The request a `Plug.Conn` is, with the raw `body` you read. `Plug.Conn` is
  not needed to compile this; anything with its fields works.
  """
  @spec from_conn(
          %{
            method: String.t(),
            request_path: String.t(),
            query_string: String.t(),
            req_headers: list()
          },
          binary()
        ) :: t()
  def from_conn(conn, body) when is_binary(body) do
    path =
      case conn.query_string do
        "" -> conn.request_path
        query -> conn.request_path <> "?" <> query
      end

    %__MODULE__{method: conn.method, path: path, headers: conn.req_headers, body: body}
  end

  @doc false
  @spec to_nif(source()) :: {:ok, Ojak.Nif.request()} | {:error, term()}
  def to_nif(%__MODULE__{} = r), do: {:ok, {r.method, r.path, r.headers, r.body}}

  def to_nif({method, path, headers, body} = tuple)
      when is_binary(method) and is_binary(path) and is_list(headers) and is_binary(body),
      do: {:ok, tuple}

  def to_nif(%{method: method, path: path, headers: headers} = map),
    do: to_nif({method, path, headers, Map.get(map, :body, "")})

  def to_nif(_), do: {:error, {:invalid_argument, "not a request; see Ojak.Request"}}
end
