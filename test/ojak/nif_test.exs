defmodule Ojak.NifTest do
  use ExUnit.Case, async: true

  alias Ojak.Nif

  @now 1_700_000_000
  @url "https://remote.example/users/bob/inbox"
  @key_id "https://home.example/users/alice#main-key"

  setup_all do
    {:ok, {private_pem, public_pem}} = Nif.rsa_generate_keypair()
    {:ok, key} = Nif.rsa_private_key(private_pem)
    {:ok, seed} = Nif.ed25519_generate_seed()
    {:ok, public} = Nif.ed25519_public_key(seed)
    %{key: key, public_pem: public_pem, seed: seed, public: public}
  end

  # What a receiving server sees of a request signed for `url`.
  defp received(url, body, headers) do
    uri = URI.parse(url)

    {"POST", uri.path,
     [{"Host", uri.host}, {"Content-Type", "application/activity+json"} | headers], body}
  end

  defp signed_request(key, body \\ ~s({"type":"Follow"}), now \\ @now) do
    {:ok, h} =
      Nif.sign_draft_cavage(
        "POST",
        @url,
        body,
        @key_id,
        key,
        [{"content-type", "application/activity+json"}],
        now
      )

    received(@url, body, [{"Signature", h.signature}, {"Date", h.date}, {"Digest", h.digest}])
  end

  describe "draft-cavage, in three steps" do
    test "a request signed here verifies", %{key: key, public_pem: pem} do
      request = signed_request(key)

      assert {:ok, signature, info} = Nif.signature_parse(request)
      assert %{scheme: :draft_cavage, key_id: @key_id, created: @now} = info
      assert "(request-target)" in info.covered and "digest" in info.covered

      assert :ok = Nif.signature_check(signature, request, ["remote.example"], 3600, @now)
      assert :ok = Nif.signature_verify(signature, request, {:rsa_pem, pem})
    end

    test "the key of someone else does not verify", %{key: key} do
      {:ok, {_, other_pem}} = Nif.rsa_generate_keypair()
      request = signed_request(key)
      {:ok, signature, _} = Nif.signature_parse(request)
      assert {:error, _} = Nif.signature_verify(signature, request, {:rsa_pem, other_pem})
    end

    test "a body that is not the one signed is refused before any key is fetched", %{key: key} do
      {method, path, headers, _body} = signed_request(key)
      request = {method, path, headers, ~s({"type":"Delete"})}
      {:ok, signature, _} = Nif.signature_parse(request)

      assert {:error, :digest_mismatch} =
               Nif.signature_check(signature, request, ["remote.example"], 3600, @now)
    end

    test "a request made for another host is refused", %{key: key} do
      request = signed_request(key)
      {:ok, signature, _} = Nif.signature_parse(request)

      assert {:error, {:wrong_host, "remote.example"}} =
               Nif.signature_check(signature, request, ["elsewhere.example"], 3600, @now)
    end

    test "a stale signature is refused, with how stale", %{key: key} do
      request = signed_request(key)
      {:ok, signature, _} = Nif.signature_parse(request)

      assert {:error, {:stale, -7200}} =
               Nif.signature_check(signature, request, ["remote.example"], 3600, @now + 7200)
    end

    test "a request with no signature says so" do
      assert {:error, :unsigned} = Nif.signature_parse({"POST", "/inbox", [{"host", "x"}], ""})
    end

    test "header names may be in any case", %{key: key, public_pem: pem} do
      {m, p, headers, b} = signed_request(key)
      shouted = Enum.map(headers, fn {k, v} -> {String.upcase(k), v} end)
      request = {m, p, shouted, b}
      {:ok, signature, _} = Nif.signature_parse(request)
      assert :ok = Nif.signature_verify(signature, request, {:rsa_pem, pem})
    end
  end

  describe "RFC 9421" do
    test "Ed25519 round trip", %{seed: seed, public: public} do
      body = ~s({"type":"Create"})

      {:ok, h} = Nif.sign_rfc9421("POST", @url, body, @key_id, {:ed25519, seed}, @now)
      assert h.content_digest

      request =
        received(@url, body, [
          {"Signature-Input", h.signature_input},
          {"Signature", h.signature},
          {"Content-Digest", h.content_digest}
        ])

      assert {:ok, signature, %{scheme: :rfc9421}} = Nif.signature_parse(request)
      assert :ok = Nif.signature_check(signature, request, ["remote.example"], 3600, @now)
      assert :ok = Nif.signature_verify(signature, request, {:ed25519, public})
    end

    test "RSA round trip, and a key of the wrong kind is an error, not a crash",
         %{key: key, public_pem: pem, public: public} do
      {:ok, h} = Nif.sign_rfc9421("POST", @url, "{}", @key_id, {:rsa, key}, @now)

      request =
        received(@url, "{}", [
          {"Signature-Input", h.signature_input},
          {"Signature", h.signature},
          {"Content-Digest", h.content_digest}
        ])

      {:ok, signature, _} = Nif.signature_parse(request)
      assert :ok = Nif.signature_verify(signature, request, {:rsa_pem, pem})
      assert {:error, _} = Nif.signature_verify(signature, request, {:ed25519, public})
    end
  end

  describe "digests" do
    test "match the body they describe" do
      header = Nif.content_digest("hello")
      assert Nif.content_digest_matches(header, "hello")
      refute Nif.content_digest_matches(header, "goodbye")
      refute Nif.digest_matches("not a digest", "hello")
    end
  end

  describe "published_key/2" do
    @actor %{
      "id" => "https://home.example/users/alice",
      "publicKey" => %{
        "id" => @key_id,
        "owner" => "https://home.example/users/alice",
        "publicKeyPem" => "PEM"
      }
    }

    test "finds a key the actor publishes as its own" do
      assert {:ok, {:rsa_pem, "PEM"}} = Nif.published_key(@actor, @key_id)
    end

    test "does not find a key it does not publish" do
      assert {:ok, nil} = Nif.published_key(@actor, "https://home.example/users/alice#other")
    end

    test "does not find a key whose owner is someone else" do
      stolen = put_in(@actor, ["publicKey", "owner"], "https://evil.example/users/mallory")
      assert {:ok, nil} = Nif.published_key(stolen, @key_id)
    end

    test "key_owner/1 drops the fragment" do
      assert {:ok, "https://home.example/users/alice"} = Nif.key_owner(@key_id)
    end
  end

  describe "object integrity proofs" do
    test "sign, find, verify, and notice tampering", %{seed: seed, public: public} do
      vm = "https://home.example/users/alice#ed25519-key"

      note = %{
        "@context" => "https://www.w3.org/ns/activitystreams",
        "id" => "https://home.example/notes/1",
        "type" => "Note",
        "content" => "hello"
      }

      assert {:ok, signed} = Nif.integrity_sign(note, vm, seed, @now)

      assert {:ok, [%{proof: proof, cryptosuite: "eddsa-jcs-2022", verification_method: ^vm}]} =
               Nif.integrity_proofs(signed, @now)

      assert :ok = Nif.integrity_verify(signed, proof, {:ed25519, public})

      tampered = Map.put(signed, "content", "goodbye")
      assert {:error, _} = Nif.integrity_verify(tampered, proof, {:ed25519, public})
    end

    test "an object with no proof has no proofs" do
      assert {:ok, []} = Nif.integrity_proofs(%{"type" => "Note"}, @now)
    end

    test "multikeys round trip, and make a did:key", %{public: public} do
      {:ok, multikey} = Nif.ed25519_multikey_encode(public)
      assert "z6Mk" <> _ = multikey
      assert {:ok, {:ed25519, ^public}} = Nif.multikey_decode(multikey)
      assert {:ok, "did:key:z6Mk" <> _} = Nif.did_key(public)
    end
  end

  describe "JSON-LD" do
    test "an alias is resolved to the term Ojak reads" do
      document = %{
        "@context" => ["https://www.w3.org/ns/activitystreams", %{"s" => "as:sensitive"}],
        "type" => "Note",
        "id" => "https://remote.example/notes/1",
        "s" => true
      }

      assert {:ok, normal, []} = Nif.jsonld_normalize(nil, document)
      assert normal["sensitive"] == true
      refute Map.has_key?(normal, "s")
    end

    test "a registry keeps what it processed, and gives the same answer" do
      {:ok, registry} = Nif.jsonld_registry(%{})

      document = %{
        "@context" => "https://www.w3.org/ns/activitystreams",
        "type" => "Note",
        "id" => "https://remote.example/notes/1",
        "content" => "hi"
      }

      assert {:ok, first, []} = Nif.jsonld_normalize(registry, document)
      assert {:ok, ^first, []} = Nif.jsonld_normalize(registry, document)
      assert {:ok, ^first, []} = Nif.jsonld_normalize(nil, document)
    end

    test "a context that is not held is reported, not fatal" do
      document = %{
        "@context" => ["https://www.w3.org/ns/activitystreams", "https://unknown.example/ctx"],
        "type" => "Note",
        "id" => "https://remote.example/notes/1"
      }

      assert {:ok, _, ["https://unknown.example/ctx"]} = Nif.jsonld_normalize(nil, document)
    end

    test "a registry can hold a context of the caller's" do
      ctx = %{"@context" => %{"@vocab" => "https://vocab.example/"}}
      {:ok, registry} = Nif.jsonld_registry(%{"https://unknown.example/ctx" => ctx})
      document = %{"@context" => "https://unknown.example/ctx", "thing" => "x"}

      assert {:ok, [expanded], []} = Nif.jsonld_expand(registry, document)
      assert Map.has_key?(expanded, "https://vocab.example/thing")
    end

    test "expansion, then compaction, comes back to where it began" do
      as = "https://www.w3.org/ns/activitystreams"

      document = %{
        "@context" => as,
        "type" => "Note",
        "id" => "https://remote.example/notes/1",
        "content" => "hi"
      }

      {:ok, expanded, _} = Nif.jsonld_expand(nil, document)
      {:ok, compacted, _} = Nif.jsonld_compact(nil, expanded, as)
      assert compacted["content"] == "hi"
      assert compacted["type"] == "Note"
    end

    test "a document that is too deep is refused, not a crash" do
      deep = Enum.reduce(1..200, "x", fn _, inner -> %{"a" => inner} end)
      assert {:error, {:invalid_argument, _}} = Nif.jsonld_normalize(nil, deep)
    end

    test "a term that refers to itself is an answer, not a hang" do
      document = %{"@context" => %{"a" => "b", "b" => "a"}, "a" => 1}
      assert {:error, {:jsonld, _}} = Nif.jsonld_expand(nil, document)
    end
  end

  describe "Linked Data Signatures" do
    test "sign, name the creator, verify", %{key: key, public_pem: pem} do
      note = %{
        "@context" => "https://www.w3.org/ns/activitystreams",
        "id" => "https://home.example/notes/1",
        "type" => "Note",
        "content" => "hello"
      }

      assert {:ok, signed} = Nif.linked_data_sign(nil, note, @key_id, key, @now, @now + 86_400)
      assert {:ok, @key_id} = Nif.linked_data_creator(signed)
      assert :ok = Nif.linked_data_verify(nil, signed, pem, @now)

      tampered = Map.put(signed, "content", "goodbye")
      assert {:error, _} = Nif.linked_data_verify(nil, tampered, pem, @now)
      assert {:error, _} = Nif.linked_data_verify(nil, signed, pem, @now + 200_000)
    end
  end

  describe "arguments" do
    test "a header that is not UTF-8 is an error the caller can handle" do
      request = {"POST", "/inbox", [{"signature", <<0xFF, 0xFE>>}], ""}
      assert {:error, {:invalid_argument, _}} = Nif.signature_parse(request)
    end

    test "a request of the wrong shape is reported" do
      assert {:error, {:invalid_argument, _}} = Nif.signature_parse(:not_a_request)
    end

    test "a key that is not a parsed key raises" do
      assert_raise ArgumentError, fn ->
        Nif.sign_draft_cavage("POST", @url, "", @key_id, :nope, [], @now)
      end
    end

    test "a private key that is not one is an error" do
      assert {:error, {:key, _}} = Nif.rsa_private_key("not a pem")
    end

    test "a seed of the wrong length is an error" do
      assert {:error, {:invalid_argument, _}} = Nif.ed25519_public_key(<<1, 2, 3>>)
    end
  end
end
