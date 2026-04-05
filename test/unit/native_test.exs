defmodule Cashew.NativeTest do
  use ExUnit.Case, async: true

  describe "generate_keypair/0" do
    test "returns a 32-byte private key and 33-byte compressed public key" do
      {:ok, {privkey, pubkey}} = Cashew.generate_keypair()
      assert byte_size(privkey) == 32
      assert byte_size(pubkey) == 33
    end

    test "generates different keypairs on successive calls" do
      {:ok, {privkey1, _}} = Cashew.generate_keypair()
      {:ok, {privkey2, _}} = Cashew.generate_keypair()
      assert privkey1 != privkey2
    end

    test "public key starts with 0x02 or 0x03 (compressed format)" do
      {:ok, {_, pubkey}} = Cashew.generate_keypair()
      <<prefix, _::binary>> = pubkey
      assert prefix in [0x02, 0x03]
    end
  end

  describe "pubkey_from_privkey/1" do
    test "derives the same public key as generate_keypair" do
      {:ok, {privkey, pubkey}} = Cashew.generate_keypair()
      {:ok, derived_pubkey} = Cashew.pubkey_from_privkey(privkey)
      assert pubkey == derived_pubkey
    end

    test "is deterministic" do
      {:ok, {privkey, _}} = Cashew.generate_keypair()
      {:ok, pk1} = Cashew.pubkey_from_privkey(privkey)
      {:ok, pk2} = Cashew.pubkey_from_privkey(privkey)
      assert pk1 == pk2
    end

    test "rejects invalid private key (wrong size)" do
      assert {:error, _} = Cashew.pubkey_from_privkey(<<0::8*16>>)
    end

    test "rejects zero private key" do
      assert {:error, _} = Cashew.pubkey_from_privkey(<<0::8*32>>)
    end

    test "rejects private key larger than curve order" do
      # secp256k1 order n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
      # Use all 0xFF bytes which exceeds the order
      assert {:error, _} = Cashew.pubkey_from_privkey(:binary.copy(<<0xFF>>, 32))
    end
  end

  describe "hash_to_curve/1" do
    test "returns a 33-byte compressed point" do
      {:ok, point} = Cashew.hash_to_curve("test message")
      assert byte_size(point) == 33
    end

    test "output starts with 0x02 or 0x03 (compressed format)" do
      {:ok, point} = Cashew.hash_to_curve("test message")
      <<prefix, _::binary>> = point
      assert prefix in [0x02, 0x03]
    end

    test "is deterministic" do
      {:ok, point1} = Cashew.hash_to_curve("same input")
      {:ok, point2} = Cashew.hash_to_curve("same input")
      assert point1 == point2
    end

    test "different inputs produce different points" do
      {:ok, point1} = Cashew.hash_to_curve("input_a")
      {:ok, point2} = Cashew.hash_to_curve("input_b")
      assert point1 != point2
    end

    test "handles empty binary" do
      {:ok, point} = Cashew.hash_to_curve("")
      assert byte_size(point) == 33
    end

    test "handles large binary" do
      {:ok, point} = Cashew.hash_to_curve(:binary.copy(<<0xAB>>, 10_000))
      assert byte_size(point) == 33
    end
  end

  describe "step1_alice/2" do
    test "returns a blinded message and blinding factor with random r" do
      {:ok, {b_prime, r}} = Cashew.step1_alice("secret", nil)
      assert byte_size(b_prime) == 33
      assert byte_size(r) == 32
    end

    test "returns different blinding factors on successive calls" do
      {:ok, {_, r1}} = Cashew.step1_alice("secret", nil)
      {:ok, {_, r2}} = Cashew.step1_alice("secret", nil)
      assert r1 != r2
    end

    test "uses provided blinding factor when given" do
      {:ok, {_, _}} = Cashew.generate_keypair()
      # Use a known valid private key as blinding factor
      {:ok, {r, _}} = Cashew.generate_keypair()
      {:ok, {_, returned_r}} = Cashew.step1_alice("secret", r)
      assert returned_r == r
    end

    test "is deterministic with same blinding factor" do
      {:ok, {r, _}} = Cashew.generate_keypair()
      {:ok, {b1, _}} = Cashew.step1_alice("secret", r)
      {:ok, {b2, _}} = Cashew.step1_alice("secret", r)
      assert b1 == b2
    end

    test "rejects wrong-size blinding factor" do
      assert {:error, _} = Cashew.step1_alice("secret", <<0::8*16>>)
    end

    test "rejects zero blinding factor" do
      assert {:error, _} = Cashew.step1_alice("secret", <<0::8*32>>)
    end
  end

  describe "step2_bob/2" do
    test "signs a blinded message" do
      {:ok, {privkey, _}} = Cashew.generate_keypair()
      {:ok, {b_prime, _}} = Cashew.step1_alice("secret", nil)
      {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)
      assert byte_size(c_prime) == 33
    end

    test "is deterministic" do
      {:ok, {privkey, _}} = Cashew.generate_keypair()
      {:ok, {r, _}} = Cashew.generate_keypair()
      {:ok, {b_prime, _}} = Cashew.step1_alice("secret", r)
      {:ok, c1} = Cashew.step2_bob(privkey, b_prime)
      {:ok, c2} = Cashew.step2_bob(privkey, b_prime)
      assert c1 == c2
    end

    test "rejects invalid private key" do
      {:ok, {b_prime, _}} = Cashew.step1_alice("secret", nil)
      assert {:error, _} = Cashew.step2_bob(<<0::8*32>>, b_prime)
    end

    test "rejects invalid blinded point" do
      {:ok, {privkey, _}} = Cashew.generate_keypair()
      assert {:error, _} = Cashew.step2_bob(privkey, <<0::8*33>>)
    end
  end

  describe "step3_alice/3" do
    test "unblinds the signature" do
      {:ok, {privkey, pubkey}} = Cashew.generate_keypair()
      {:ok, {b_prime, r}} = Cashew.step1_alice("secret", nil)
      {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)
      {:ok, c} = Cashew.step3_alice(c_prime, r, pubkey)
      assert byte_size(c) == 33
    end

    test "rejects invalid c_prime" do
      {:ok, {_, _}} = Cashew.generate_keypair()
      {:ok, {_, r}} = Cashew.step1_alice("secret", nil)
      {:ok, {_, pubkey}} = Cashew.generate_keypair()
      assert {:error, _} = Cashew.step3_alice(<<0::8*33>>, r, pubkey)
    end

    test "rejects zero blinding factor" do
      {:ok, {privkey, pubkey}} = Cashew.generate_keypair()
      {:ok, {b_prime, _}} = Cashew.step1_alice("secret", nil)
      {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)
      assert {:error, _} = Cashew.step3_alice(c_prime, <<0::8*32>>, pubkey)
    end

    test "rejects invalid mint pubkey" do
      {:ok, {privkey, _}} = Cashew.generate_keypair()
      {:ok, {b_prime, r}} = Cashew.step1_alice("secret", nil)
      {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)
      assert {:error, _} = Cashew.step3_alice(c_prime, r, <<0::8*33>>)
    end
  end

  describe "verify/3" do
    test "valid BDHKE roundtrip verifies successfully" do
      {:ok, {privkey, pubkey}} = Cashew.generate_keypair()
      secret = "test_secret"

      {:ok, {b_prime, r}} = Cashew.step1_alice(secret, nil)
      {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)
      {:ok, c} = Cashew.step3_alice(c_prime, r, pubkey)

      assert :ok = Cashew.verify(privkey, secret, c)
    end

    test "wrong secret fails verification" do
      {:ok, {privkey, pubkey}} = Cashew.generate_keypair()

      {:ok, {b_prime, r}} = Cashew.step1_alice("real_secret", nil)
      {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)
      {:ok, c} = Cashew.step3_alice(c_prime, r, pubkey)

      assert {:error, :invalid_signature} = Cashew.verify(privkey, "wrong_secret", c)
    end

    test "wrong key fails verification" do
      {:ok, {privkey, pubkey}} = Cashew.generate_keypair()
      {:ok, {other_privkey, _}} = Cashew.generate_keypair()
      secret = "test_secret"

      {:ok, {b_prime, r}} = Cashew.step1_alice(secret, nil)
      {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)
      {:ok, c} = Cashew.step3_alice(c_prime, r, pubkey)

      assert {:error, :invalid_signature} = Cashew.verify(other_privkey, secret, c)
    end

    test "rejects invalid private key" do
      assert {:error, _} = Cashew.verify(<<0::8*32>>, "secret", <<2, 0::8*32>>)
    end

    test "rejects invalid signature format" do
      {:ok, {privkey, _}} = Cashew.generate_keypair()
      assert {:error, _} = Cashew.verify(privkey, "secret", <<0::8*33>>)
    end
  end

  describe "schnorr_sign/2" do
    test "produces a 64-byte signature and 32-byte x-only pubkey" do
      {:ok, {privkey, _}} = Cashew.generate_keypair()
      msg_hash = :crypto.hash(:sha256, "test message")
      {:ok, {sig, xonly}} = Cashew.schnorr_sign(privkey, msg_hash)
      assert byte_size(sig) == 64
      assert byte_size(xonly) == 32
    end

    test "rejects zero private key" do
      msg_hash = :crypto.hash(:sha256, "test message")
      assert {:error, _} = Cashew.schnorr_sign(<<0::8*32>>, msg_hash)
    end

    test "rejects wrong-size private key" do
      msg_hash = :crypto.hash(:sha256, "test message")
      assert {:error, _} = Cashew.schnorr_sign(<<0::8*16>>, msg_hash)
    end

    test "rejects wrong-size message hash" do
      {:ok, {privkey, _}} = Cashew.generate_keypair()
      assert {:error, _} = Cashew.schnorr_sign(privkey, <<0::8*16>>)
    end
  end

  describe "schnorr_verify/3" do
    test "valid signature verifies successfully" do
      {:ok, {privkey, _}} = Cashew.generate_keypair()
      msg_hash = :crypto.hash(:sha256, "test message")
      {:ok, {sig, xonly}} = Cashew.schnorr_sign(privkey, msg_hash)
      assert :ok = Cashew.schnorr_verify(xonly, msg_hash, sig)
    end

    test "rejects wrong signature" do
      {:ok, {privkey, _}} = Cashew.generate_keypair()
      msg_hash = :crypto.hash(:sha256, "test message")
      {:ok, {_, xonly}} = Cashew.schnorr_sign(privkey, msg_hash)
      wrong_sig = :binary.copy(<<0>>, 64)
      assert {:error, _} = Cashew.schnorr_verify(xonly, msg_hash, wrong_sig)
    end

    test "rejects wrong-size public key" do
      assert {:error, _} = Cashew.schnorr_verify(<<0::8*16>>, <<0::8*32>>, <<0::8*64>>)
    end

    test "rejects wrong-size message hash" do
      assert {:error, _} = Cashew.schnorr_verify(<<0::8*32>>, <<0::8*16>>, <<0::8*64>>)
    end

    test "rejects wrong-size signature" do
      assert {:error, _} = Cashew.schnorr_verify(<<0::8*32>>, <<0::8*32>>, <<0::8*32>>)
    end
  end
end
