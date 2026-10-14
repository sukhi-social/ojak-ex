defmodule Ojak.ApiTest do
  use ExUnit.Case, async: true

  alias Ojak.{Error, HTTPSignature, JsonLd, Key, LinkedDataSignature, Proof, Request}

  @inbox "https://remote.example/users/bob/inbox"
  @alice "https://home.example/users/alice"
  @key_id @alice <> "#main-key"

  setup_all do
    %{rsa: Key.generate!(:rsa), ed: Key.generate!(:ed25519)}
  end

  # The actor document that publishes `key`, as a JSON library would give it.
  defp actor(%Key{public: {:rsa_pem, pem}}) do
    %{
      "id" => @alice,
      "publicKey" => %{"id" => @key_id, "owner" => @alice, "publicKeyPem" => pem}
    }
  end

  # What the receiving server sees of `headers` sent to the inbox.
  defp arrived(body, headers) do
    {"POST", "/users/bob/inbox", [{"host", "remote.example"} | headers], body}
  end

  describe "Ojak.Key" do
    test "does not show its secret", %{rsa: rsa, ed: ed} do
      for key <- [rsa, ed] do
        shown = inspect(key)
        assert shown =~ "Ojak.Key"
        refute shown =~ "PRIVATE"
        refute shown =~ Base.encode16(Key.export(ed))
        refute shown =~ "secret"
      end
    end

    test "an exported key comes back and signs the same way", %{rsa: rsa, ed: ed} do
      {:ok, rsa_again} = Key.from_pem(Key.export(rsa), elem(rsa.public, 1))
      {:ok, ed_again} = Key.from_seed(Key.export(ed))
      assert rsa_again.public == rsa.public
      assert ed_again.public == ed.public

      headers = HTTPSignature.sign!("POST", @inbox, "{}", rsa_again, key_id: @key_id)
      assert {:ok, _, _} = HTTPSignature.parse(arrived("{}", headers))
    end

    test "a Multikey and a did:key are made from an Ed25519 key", %{ed: ed} do
      assert {:ok, "z6Mk" <> _ = multikey} = Key.multikey(ed)
      assert {:ok, {:ed25519, key}} = Key.decode_multikey(multikey)
      assert {:ed25519, key} == ed.public
      assert {:ok, "did:key:z6Mk" <> _} = Key.did(ed)
    end

    test "an RSA key has neither", %{rsa: rsa} do
      assert {:error, {:unsupported, _}} = Key.multikey(rsa)
    end

    test "a PEM that is not one is an error" do
      assert {:error, {:key, _}} = Key.from_pem("nope")
    end
  end

  describe "Ojak.HTTPSignature" do
    test "what is signed here verifies, and says whose it is", %{rsa: rsa} do
      body = ~s({"type":"Follow","actor":"#{@alice}"})

      {:ok, headers} =
        HTTPSignature.sign("POST", @inbox, body, rsa,
          key_id: @key_id,
          headers: [{"content-type", "application/activity+json"}]
        )

      assert [{"signature", _}, {"date", _}, {"digest", _}] = headers

      request = arrived(body, [{"content-type", "application/activity+json"} | headers])

      assert {:ok, %{key_id: @key_id, owner: @alice, scheme: :draft_cavage}} =
               HTTPSignature.verify(request,
                 hosts: ["remote.example"],
                 fetch_key: fn @key_id -> {:ok, actor(rsa)} end
               )
    end

    test "the time is the current one unless said otherwise", %{rsa: rsa} do
      headers = HTTPSignature.sign!("POST", @inbox, "{}", rsa, key_id: @key_id)
      request = arrived("{}", headers)
      opts = [hosts: ["remote.example"], fetch_key: fn _ -> {:ok, actor(rsa)} end]

      assert {:ok, _} = HTTPSignature.verify(request, opts)
      far_off = DateTime.add(DateTime.utc_now(), 2 * 3600)
      assert {:error, {:stale, _}} = HTTPSignature.verify(request, [now: far_off] ++ opts)
    end

    test "the key is not fetched for a request that was never going to pass", %{rsa: rsa} do
      headers = HTTPSignature.sign!("POST", @inbox, "{}", rsa, key_id: @key_id)
      test = self()

      fetch = fn _ ->
        send(test, :fetched)
        {:ok, actor(rsa)}
      end

      request = arrived(~s({"type":"Delete"}), headers)

      assert {:error, :digest_mismatch} =
               HTTPSignature.verify(request, hosts: ["remote.example"], fetch_key: fetch)

      assert {:error, {:wrong_host, _}} =
               HTTPSignature.verify(arrived("{}", headers),
                 hosts: ["other.example"],
                 fetch_key: fetch
               )

      refute_received :fetched
    end

    test "a key the actor does not publish is not believed", %{rsa: rsa, ed: _} do
      headers = HTTPSignature.sign!("POST", @inbox, "{}", rsa, key_id: @key_id)

      stranger = put_in(actor(rsa), ["publicKey", "id"], @alice <> "#other-key")

      assert {:error, :key_not_published} =
               HTTPSignature.verify(arrived("{}", headers),
                 hosts: ["remote.example"],
                 fetch_key: fn _ -> {:ok, stranger} end
               )
    end

    test "a key that the fetch fails to find is the fetch's reason", %{rsa: rsa} do
      headers = HTTPSignature.sign!("POST", @inbox, "{}", rsa, key_id: @key_id)

      assert {:error, {:fetch_key, :gone}} =
               HTTPSignature.verify(arrived("{}", headers),
                 hosts: ["remote.example"],
                 fetch_key: fn _ -> {:error, :gone} end
               )
    end

    test "the wrong key does not verify", %{rsa: rsa} do
      other = Key.generate!(:rsa)
      headers = HTTPSignature.sign!("POST", @inbox, "{}", other, key_id: @key_id)

      assert {:error, _} =
               HTTPSignature.verify(arrived("{}", headers),
                 hosts: ["remote.example"],
                 fetch_key: fn _ -> {:ok, actor(rsa)} end
               )
    end

    test "RFC 9421 with Ed25519, and a key you already trust", %{ed: ed} do
      body = ~s({"type":"Create"})
      headers = HTTPSignature.sign!("POST", @inbox, body, ed, key_id: @alice <> "#ed")
      assert [{"signature-input", _}, {"signature", _}, {"content-digest", _}] = headers

      assert {:ok, %{scheme: :rfc9421, owner: @alice}} =
               HTTPSignature.verify(arrived(body, headers),
                 hosts: ["remote.example"],
                 fetch_key: fn _ -> {:ok, ed.public} end
               )
    end

    test "draft-cavage needs an RSA key", %{ed: ed} do
      assert {:error, {:unsupported, _}} =
               HTTPSignature.sign("POST", @inbox, "{}", ed, key_id: @key_id, scheme: :draft_cavage)
    end

    test "a Plug.Conn is a request", %{rsa: rsa} do
      url = "https://remote.example/users/bob/inbox?page=2"
      headers = HTTPSignature.sign!("POST", url, "{}", rsa, key_id: @key_id)

      conn = %{
        method: "POST",
        request_path: "/users/bob/inbox",
        query_string: "page=2",
        req_headers: [{"host", "remote.example"} | headers]
      }

      assert {:ok, %{owner: @alice}} =
               conn
               |> Request.from_conn("{}")
               |> HTTPSignature.verify(
                 hosts: ["remote.example"],
                 fetch_key: fn _ -> {:ok, actor(rsa)} end
               )
    end

    test "a request may be a map or a tuple, and nothing else", %{rsa: rsa} do
      headers = HTTPSignature.sign!("POST", @inbox, "{}", rsa, key_id: @key_id)

      as_map = %{
        method: "POST",
        path: "/users/bob/inbox",
        headers: [{"host", "remote.example"} | headers],
        body: "{}"
      }

      assert {:ok, _, %{key_id: @key_id}} = HTTPSignature.parse(as_map)
      assert {:error, {:invalid_argument, _}} = HTTPSignature.parse(:nonsense)
    end

    test "verify! raises with the reason", %{rsa: rsa} do
      headers = HTTPSignature.sign!("POST", @inbox, "{}", rsa, key_id: @key_id)

      error =
        assert_raise Error, fn ->
          HTTPSignature.verify!(arrived("{}", headers),
            hosts: ["elsewhere.example"],
            fetch_key: fn _ -> {:ok, actor(rsa)} end
          )
        end

      assert error.reason == {:wrong_host, "remote.example"}
      assert Exception.message(error) =~ "wrong_host"
    end

    test "a required option is required" do
      assert_raise ArgumentError, ~r/:hosts/, fn ->
        HTTPSignature.verify(arrived("{}", []), fetch_key: fn _ -> {:error, :x} end)
      end
    end
  end

  describe "Ojak.Proof" do
    @note %{
      "@context" => "https://www.w3.org/ns/activitystreams",
      "id" => "https://home.example/notes/1",
      "type" => "Note",
      "content" => "hello"
    }

    test "what is signed here is found and verifies", %{ed: ed} do
      vm = @alice <> "#ed25519-key"
      signed = Proof.sign!(@note, ed, verification_method: vm)

      assert %{verification_method: ^vm, cryptosuite: "eddsa-jcs-2022"} =
               Proof.verify!(signed, fetch_key: fn ^vm -> {:ok, ed.public} end)
    end

    test "an object changed afterwards does not verify", %{ed: ed} do
      vm = @alice <> "#ed25519-key"
      signed = Proof.sign!(@note, ed, verification_method: vm)
      altered = Map.put(signed, "content", "goodbye")

      assert {:error, {:no_valid_proof, [{^vm, _}]}} =
               Proof.verify(altered, fetch_key: fn _ -> {:ok, ed.public} end)
    end

    test "an object with no proof says so" do
      assert {:error, :no_proof} = Proof.verify(@note, fetch_key: fn _ -> flunk("fetched") end)
    end

    test "an RSA key does not make proofs", %{rsa: rsa} do
      assert {:error, {:unsupported, _}} = Proof.sign(@note, rsa, verification_method: "x")
    end
  end

  describe "Ojak.LinkedDataSignature" do
    test "sign, then verify, and the creator comes back", %{rsa: rsa} do
      activity = %{
        "@context" => "https://www.w3.org/ns/activitystreams",
        "id" => "https://home.example/activities/1",
        "type" => "Delete",
        "actor" => @alice,
        "object" => "https://home.example/notes/1"
      }

      signed = LinkedDataSignature.sign!(activity, rsa, key_id: @key_id)

      assert @key_id ==
               LinkedDataSignature.verify!(signed, fetch_key: fn @key_id -> {:ok, rsa.public} end)

      assert {:error, _} =
               LinkedDataSignature.verify(Map.put(signed, "type", "Create"),
                 fetch_key: fn _ -> {:ok, rsa.public} end
               )
    end

    test "an unsigned activity has no signature to check", %{rsa: rsa} do
      assert {:error, :no_signature} =
               LinkedDataSignature.verify(%{"type" => "Note"},
                 fetch_key: fn _ -> {:ok, rsa.public} end
               )
    end
  end

  describe "Ojak.JsonLd" do
    @aliased %{
      "@context" => ["https://www.w3.org/ns/activitystreams", %{"s" => "as:sensitive"}],
      "type" => "Note",
      "id" => "https://remote.example/notes/1",
      "s" => true
    }

    test "normalize resolves what the document says" do
      assert {:ok, %{"sensitive" => true}} = JsonLd.normalize(@aliased)
      assert %{"sensitive" => true} = JsonLd.normalize!(@aliased)
    end

    test "the report names the contexts that were not held" do
      document =
        Map.put(@aliased, "@context", [
          "https://www.w3.org/ns/activitystreams",
          "https://x.example/ctx"
        ])

      assert {:ok, _, ["https://x.example/ctx"]} = JsonLd.normalize_with_report(document)
      assert {:ok, _} = JsonLd.normalize(document)
    end

    test "a registry holds contexts of your own" do
      context = %{"@context" => %{"@vocab" => "https://vocab.example/"}}
      {:ok, registry} = JsonLd.registry(%{"https://x.example/ctx" => context})
      document = %{"@context" => "https://x.example/ctx", "thing" => "x"}

      assert {:ok, [%{"https://vocab.example/thing" => _}]} =
               JsonLd.expand(document, registry: registry)
    end

    test "a document too large to read is refused with a reason" do
      many = for i <- 1..20_000, do: %{"type" => "Mention", "href" => "https://x/#{i}"}
      document = %{"@context" => "https://www.w3.org/ns/activitystreams", "tag" => many}
      assert {:error, {:jsonld, _}} = JsonLd.normalize(document)
      assert_raise Error, fn -> JsonLd.normalize!(document) end
    end
  end
end
