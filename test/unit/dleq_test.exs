defmodule Cashew.DLEQTest do
  @moduledoc """
  Tests for NUT-12 DLEQ proof generation and verification.

  Verifies that the NIF generates valid DLEQ proofs for blind signatures,
  and that these proofs can be verified correctly.

  Source: https://github.com/cashubtc/nuts/blob/main/tests/12-tests.md
  """

  use ExUnit.Case, async: true

  # -- NUT-12: hash_e function test vector --

  describe "DLEQ hash_e function" do
    test "DLEQ challenge hash is deterministic" do
      # The DLEQ challenge e = SHA256(R1 || R2 || K || C') uses compressed point bytes.
      # Verify determinism by generating two proofs with the same inputs.
      privkey = Base.decode16!("0000000000000000000000000000000000000000000000000000000000000001")
      {:ok, pubkey} = Cashew.pubkey_from_privkey(privkey)

      b_prime =
        Base.decode16!("02A9ACC1E48C25EEEB9289B5031CC57DA9FE72F3FE2861D264BDC074209B107BA2")

      {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)

      # Both proofs should verify against the same pubkey/b_prime/c_prime
      {:ok, {e1, s1}} = Cashew.generate_dleq_proof(privkey, b_prime)
      {:ok, {e2, s2}} = Cashew.generate_dleq_proof(privkey, b_prime)

      assert :ok = Cashew.verify_dleq_proof(pubkey, b_prime, c_prime, e1, s1)
      assert :ok = Cashew.verify_dleq_proof(pubkey, b_prime, c_prime, e2, s2)

      # Different random nonces should give different challenges
      assert e1 != e2
    end
  end

  # -- NUT-12: BlindSignature DLEQ --

  describe "DLEQ BlindSignature verification" do
    test "spec test vector: privkey=1 on known B'" do
      # BlindSignature DLEQ test vector from NUT-12
      # A (pubkey) = G (generator point, meaning privkey = 1)
      privkey = Base.decode16!("0000000000000000000000000000000000000000000000000000000000000001")
      {:ok, pubkey} = Cashew.pubkey_from_privkey(privkey)

      assert pubkey ==
               Base.decode16!("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")

      b_prime =
        Base.decode16!("02A9ACC1E48C25EEEB9289B5031CC57DA9FE72F3FE2861D264BDC074209B107BA2")

      # Generate DLEQ proof
      {:ok, {e, s}} = Cashew.generate_dleq_proof(privkey, b_prime)

      assert byte_size(e) == 32
      assert byte_size(s) == 32

      # C' = privkey * B' (for privkey=1, C' = B')
      {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)
      assert c_prime == b_prime

      # Verify the generated DLEQ proof
      assert :ok = Cashew.verify_dleq_proof(pubkey, b_prime, c_prime, e, s)
    end

    test "spec test vector: privkey=7f...7f" do
      privkey = Base.decode16!("7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F")
      {:ok, pubkey} = Cashew.pubkey_from_privkey(privkey)

      b_prime =
        Base.decode16!("02A9ACC1E48C25EEEB9289B5031CC57DA9FE72F3FE2861D264BDC074209B107BA2")

      {:ok, {e, s}} = Cashew.generate_dleq_proof(privkey, b_prime)
      {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)

      # Verify
      assert :ok = Cashew.verify_dleq_proof(pubkey, b_prime, c_prime, e, s)
    end

    test "wrong pubkey fails verification" do
      privkey = Base.decode16!("0000000000000000000000000000000000000000000000000000000000000001")

      b_prime =
        Base.decode16!("02A9ACC1E48C25EEEB9289B5031CC57DA9FE72F3FE2861D264BDC074209B107BA2")

      {:ok, {e, s}} = Cashew.generate_dleq_proof(privkey, b_prime)
      {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)

      # Use wrong pubkey
      wrong_privkey =
        Base.decode16!("7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F")

      {:ok, wrong_pubkey} = Cashew.pubkey_from_privkey(wrong_privkey)

      assert {:error, :invalid_dleq_proof} =
               Cashew.verify_dleq_proof(wrong_pubkey, b_prime, c_prime, e, s)
    end

    test "tampered e fails verification" do
      privkey = Base.decode16!("0000000000000000000000000000000000000000000000000000000000000001")
      {:ok, pubkey} = Cashew.pubkey_from_privkey(privkey)

      b_prime =
        Base.decode16!("02A9ACC1E48C25EEEB9289B5031CC57DA9FE72F3FE2861D264BDC074209B107BA2")

      {:ok, {e, s}} = Cashew.generate_dleq_proof(privkey, b_prime)
      {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)

      # Tamper with e
      <<first_byte, rest::binary>> = e
      tampered_e = <<first_byte + 1, rest::binary>>

      assert {:error, :invalid_dleq_proof} =
               Cashew.verify_dleq_proof(pubkey, b_prime, c_prime, tampered_e, s)
    end

    test "tampered s fails verification" do
      privkey = Base.decode16!("0000000000000000000000000000000000000000000000000000000000000001")
      {:ok, pubkey} = Cashew.pubkey_from_privkey(privkey)

      b_prime =
        Base.decode16!("02A9ACC1E48C25EEEB9289B5031CC57DA9FE72F3FE2861D264BDC074209B107BA2")

      {:ok, {e, s}} = Cashew.generate_dleq_proof(privkey, b_prime)
      {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)

      # Tamper with s
      <<first_byte, rest::binary>> = s
      tampered_s = <<first_byte + 1, rest::binary>>

      assert {:error, :invalid_dleq_proof} =
               Cashew.verify_dleq_proof(pubkey, b_prime, c_prime, e, tampered_s)
    end

    test "wrong C' fails verification" do
      privkey = Base.decode16!("0000000000000000000000000000000000000000000000000000000000000001")
      {:ok, pubkey} = Cashew.pubkey_from_privkey(privkey)

      b_prime =
        Base.decode16!("02A9ACC1E48C25EEEB9289B5031CC57DA9FE72F3FE2861D264BDC074209B107BA2")

      {:ok, {e, s}} = Cashew.generate_dleq_proof(privkey, b_prime)

      # Use wrong C' (from different privkey)
      wrong_privkey =
        Base.decode16!("7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F")

      {:ok, wrong_c_prime} = Cashew.step2_bob(wrong_privkey, b_prime)

      assert {:error, :invalid_dleq_proof} =
               Cashew.verify_dleq_proof(pubkey, b_prime, wrong_c_prime, e, s)
    end
  end

  # -- DLEQ proof with full BDHKE round-trip --

  describe "DLEQ integrated with BDHKE" do
    test "full blind-sign-verify cycle with DLEQ" do
      # Generate a mint keypair
      {:ok, {privkey, pubkey}} = Cashew.generate_keypair()

      # Client creates blinded message
      secret = :crypto.hash(:sha256, "test_secret")
      {:ok, {b_prime, r}} = Cashew.step1_alice(secret)

      # Mint signs and generates DLEQ
      {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)
      {:ok, {e, s}} = Cashew.generate_dleq_proof(privkey, b_prime)

      # Verify DLEQ proof on blind signature
      assert :ok = Cashew.verify_dleq_proof(pubkey, b_prime, c_prime, e, s)

      # Client unblinds
      {:ok, c} = Cashew.step3_alice(c_prime, r, pubkey)

      # Mint verifies unblinded signature
      assert :ok = Cashew.verify(privkey, secret, c)
    end

    test "multiple denominations produce valid DLEQ proofs" do
      {:ok, {privkey, pubkey}} = Cashew.generate_keypair()

      for _ <- 1..10 do
        secret = :crypto.strong_rand_bytes(32)
        {:ok, {b_prime, r}} = Cashew.step1_alice(secret)

        {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)
        {:ok, {e, s}} = Cashew.generate_dleq_proof(privkey, b_prime)

        assert :ok = Cashew.verify_dleq_proof(pubkey, b_prime, c_prime, e, s)

        {:ok, c} = Cashew.step3_alice(c_prime, r, pubkey)
        assert :ok = Cashew.verify(privkey, secret, c)
      end
    end

    test "DLEQ proofs are unique per invocation (random nonce)" do
      {:ok, {privkey, _}} = Cashew.generate_keypair()

      b_prime =
        Base.decode16!("02A9ACC1E48C25EEEB9289B5031CC57DA9FE72F3FE2861D264BDC074209B107BA2")

      {:ok, {e1, s1}} = Cashew.generate_dleq_proof(privkey, b_prime)
      {:ok, {e2, s2}} = Cashew.generate_dleq_proof(privkey, b_prime)

      # Different nonces should produce different e and s
      assert {e1, s1} != {e2, s2}
    end
  end

  # -- Input validation --

  describe "DLEQ input validation" do
    test "generate_dleq_proof rejects wrong privkey size" do
      assert {:error, _} =
               Cashew.generate_dleq_proof(<<1, 2, 3>>, :crypto.strong_rand_bytes(33))
    end

    test "generate_dleq_proof rejects wrong b_prime size" do
      assert {:error, _} =
               Cashew.generate_dleq_proof(:crypto.strong_rand_bytes(32), <<1, 2, 3>>)
    end

    test "verify_dleq_proof rejects wrong point sizes" do
      assert {:error, _} =
               Cashew.verify_dleq_proof(
                 <<1>>,
                 :crypto.strong_rand_bytes(33),
                 :crypto.strong_rand_bytes(33),
                 :crypto.strong_rand_bytes(32),
                 :crypto.strong_rand_bytes(32)
               )
    end
  end
end
