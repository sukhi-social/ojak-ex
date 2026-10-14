defmodule Ojak do
  @moduledoc """
  Ojak's signatures and JSON-LD for Elixir.

  The parts of an ActivityPub server that are subtle and heavy, from the Rust
  library [Ojak](https://github.com/eunha-space/ojak). They do no I/O: you
  fetch keys and documents, queue and send, and keep the supervision tree; Ojak
  checks and makes.

  | To | Use |
  | --- | --- |
  | sign a request you send, or verify one you receive | `Ojak.HTTPSignature` |
  | sign an object, or check the proof it carries | `Ojak.Proof` |
  | check a signature Mastodon forwarded | `Ojak.LinkedDataSignature` |
  | read a document however it was spelled | `Ojak.JsonLd` |
  | make or load a key | `Ojak.Key` |
  | turn a `Plug.Conn` into a request | `Ojak.Request` |

  Every function that can fail returns `{:ok, value}` or `{:error, reason}`,
  and has a `!` twin that raises `Ojak.Error`. Where a time is needed it is
  the current time, and `now:` says otherwise, which is how to test.

  ## An inbox, in short

      def inbox(conn, params) do
        request = Ojak.Request.from_conn(conn, conn.assigns.raw_body)

        with {:ok, signed} <-
               Ojak.HTTPSignature.verify(request,
                 hosts: [MyApp.host()],
                 fetch_key: &MyApp.Remote.actor_for_key/1
               ),
             {:ok, activity} <- Ojak.JsonLd.normalize(params),
             true <- activity["actor"] == signed.owner do
          MyApp.Inbox.enqueue(activity)
          send_resp(conn, 202, "")
        else
          _ -> send_resp(conn, 401, "")
        end
      end

  Sending is yours: sign with `Ojak.HTTPSignature.sign/5` and give the
  headers to whichever HTTP client and job queue you already use.

  The functions of `Ojak.Nif` are the Rust library as it is, without these
  conveniences; they are not part of the interface, and may change.

  ## What to know

    * It has been run on Linux x86_64 with Elixir 1.14 and OTP 25, and not
      elsewhere, and not federated with a real server from Elixir.
    * Signed `GET` requests (authorized fetch) and response signatures are not
      exposed yet.
    * JSON-LD resolves only the contexts Ojak ships and those you add; terms
      from any other are dropped, and `Ojak.JsonLd.normalize_with_report/2`
      says which.
    * There is no precompiled library: building needs a Rust toolchain.
    * The licence is AGPL-3.0-only.

  The package's README lists these, and what is not yet done, in full.
  """
end
