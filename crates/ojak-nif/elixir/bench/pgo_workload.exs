# What a profile-guided build learns from: the calls a server makes, in the
# proportions a server makes them. Run by scripts/pgo-build.sh; it checks its
# own answers, so a build that has gone wrong fails here, not in production.
#
#     OJAK_PGO_ROUNDS=300 mix run --no-start bench/pgo_workload.exs

alias Ojak.{HTTPSignature, JsonLd, Key, LinkedDataSignature, Proof}

rounds = String.to_integer(System.get_env("OJAK_PGO_ROUNDS", "300"))

alice = "https://home.example/users/alice"
key_id = alice <> "#main-key"
vm = alice <> "#ed25519-key"
inbox = "https://remote.example/users/bob/inbox"

rsa = Key.generate!(:rsa)
ed = Key.generate!(:ed25519)

actor = %{
  "id" => alice,
  "publicKey" => %{"id" => key_id, "owner" => alice, "publicKeyPem" => elem(rsa.public, 1)}
}

note = %{
  "@context" => [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/security/v1",
    %{"sensitive" => "as:sensitive", "toot" => "http://joinmastodon.org/ns#"}
  ],
  "id" => "https://home.example/notes/1",
  "type" => "Note",
  "attributedTo" => alice,
  "to" => ["https://www.w3.org/ns/activitystreams#Public"],
  "cc" => [alice <> "/followers"],
  "published" => "2026-10-14T07:00:00Z",
  "sensitive" => false,
  "content" => "<p>hello, fediverse</p>",
  "contentMap" => %{"en" => "<p>hello, fediverse</p>"},
  "tag" => [%{"type" => "Hashtag", "name" => "#hello", "href" => "https://home.example/tags/hello"}]
}

activity = %{
  "@context" => "https://www.w3.org/ns/activitystreams",
  "id" => "https://home.example/activities/1",
  "type" => "Create",
  "actor" => alice,
  "object" => note["id"]
}

body = JSON.encode!(activity)

one_round = fn ->
  # Sending and receiving a delivery, in both schemes; the inbox refuses what
  # was changed on the way.
  for scheme <- [:draft_cavage, :rfc9421] do
    sent = [{"content-type", "application/activity+json"}]
    {:ok, signed} = HTTPSignature.sign("POST", inbox, body, rsa, key_id: key_id, scheme: scheme, headers: sent)
    request = {"POST", "/users/bob/inbox", [{"host", "remote.example"} | sent ++ signed], body}
    opts = [hosts: ["remote.example"], fetch_key: fn _ -> {:ok, actor} end]
    {:ok, %{owner: ^alice}} = HTTPSignature.verify(request, opts)
    {:error, _} = HTTPSignature.verify(put_elem(request, 3, body <> " "), opts)
  end

  # Signed objects, in the three forms the fediverse uses.
  signed = LinkedDataSignature.sign!(activity, rsa, key_id: key_id)
  ^key_id = LinkedDataSignature.verify!(signed, fetch_key: fn _ -> {:ok, rsa.public} end)
  {:error, _} = LinkedDataSignature.verify(Map.put(signed, "type", "Delete"), fetch_key: fn _ -> {:ok, rsa.public} end)

  proved = Proof.sign!(note, ed, verification_method: vm)
  %{cryptosuite: "eddsa-jcs-2022"} = Proof.verify!(proved, fetch_key: fn _ -> {:ok, ed.public} end)
  {:error, _} = Proof.verify(Map.put(proved, "content", "x"), fetch_key: fn _ -> {:ok, ed.public} end)

  # Reading what arrived, however it was spelled.
  {:ok, %{"content" => _}} = JsonLd.normalize(note)
  {:ok, _, _} = JsonLd.normalize_with_report(note)
  {:error, _} = JsonLd.normalize(%{"@context" => 5})
end

# A server does these on many processes at once; so does this.
one_round.()

1..System.schedulers_online()
|> Task.async_stream(
  fn _ -> for _ <- 1..div(rounds, System.schedulers_online()) |> max(1), do: one_round.() end,
  timeout: :infinity
)
|> Stream.run()

IO.puts("pgo workload: #{rounds} rounds, ok")
