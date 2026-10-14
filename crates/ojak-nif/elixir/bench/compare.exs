# A speed check that is not the PGO workload: other documents, one process,
# the median of five runs. Put the library to try in priv/ojak_nif.so, then
#
#     mix run --no-start --no-compile bench/compare.exs
alias Ojak.{HTTPSignature, JsonLd, Key, LinkedDataSignature, Proof}

alice = "https://other.example/users/carol"
key_id = alice <> "#main-key"
rsa = Key.generate!(:rsa)
ed = Key.generate!(:ed25519)
actor = %{"id" => alice, "publicKey" => %{"id" => key_id, "owner" => alice, "publicKeyPem" => elem(rsa.public, 1)}}

doc = %{
  "@context" => ["https://www.w3.org/ns/activitystreams", %{"quoteUrl" => "as:quoteUrl", "votersCount" => "http://joinmastodon.org/ns#votersCount"}],
  "id" => "https://other.example/polls/9",
  "type" => "Question",
  "attributedTo" => alice,
  "to" => ["https://www.w3.org/ns/activitystreams#Public"],
  "published" => "2026-10-14T01:02:03Z",
  "name" => "tea or coffee?",
  "oneOf" => for(n <- 1..6, do: %{"type" => "Note", "name" => "choice #{n}", "replies" => %{"type" => "Collection", "totalItems" => n}}),
  "votersCount" => 42,
  "content" => String.duplicate("<p>lorem ipsum dolor sit amet</p>", 12)
}

body = JSON.encode!(doc)
sent = [{"content-type", "application/activity+json"}]
{:ok, signed_headers} = HTTPSignature.sign("POST", "https://x.example/inbox", body, rsa, key_id: key_id, headers: sent)
request = {"POST", "/inbox", [{"host", "x.example"} | sent ++ signed_headers], body}
vopts = [hosts: ["x.example"], fetch_key: fn _ -> {:ok, actor} end]
ld = LinkedDataSignature.sign!(doc, rsa, key_id: key_id)
proof = Proof.sign!(doc, ed, verification_method: alice <> "#ed")

cases = [
  {"http sign", fn -> {:ok, _} = HTTPSignature.sign("POST", "https://x.example/inbox", body, rsa, key_id: key_id, headers: sent) end, 150},
  {"http verify", fn -> {:ok, _} = HTTPSignature.verify(request, vopts) end, 1500},
  {"ld sign", fn -> LinkedDataSignature.sign!(doc, rsa, key_id: key_id) end, 150},
  {"ld verify", fn -> ^key_id = LinkedDataSignature.verify!(ld, fetch_key: fn _ -> {:ok, rsa.public} end) end, 400},
  {"proof sign", fn -> Proof.sign!(doc, ed, verification_method: alice <> "#ed") end, 1500},
  {"proof verify", fn -> Proof.verify!(proof, fetch_key: fn _ -> {:ok, ed.public} end) end, 1500},
  {"json-ld normalize", fn -> {:ok, _} = JsonLd.normalize(doc) end, 800}
]

for {name, f, n} <- cases do
  f.()
  runs = for _ <- 1..5, do: elem(:timer.tc(fn -> for _ <- 1..n, do: f.() end), 0) / n / 1000
  median = runs |> Enum.sort() |> Enum.at(2)
  IO.puts("#{String.pad_trailing(name, 18)}#{:erlang.float_to_binary(median, decimals: 4)} ms")
end
