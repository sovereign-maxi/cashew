defmodule Cashew.PropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  @moduletag timeout: 120_000

  describe "BDHKE roundtrip" do
    property "blind -> sign -> unblind -> verify succeeds for arbitrary secrets" do
      {:ok, {privkey, pubkey}} = Cashew.generate_keypair()

      check all(
              secret <- binary(min_length: 0, max_length: 1000),
              max_runs: 1000
            ) do
        {:ok, {b_prime, r}} = Cashew.step1_alice(secret)
        {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)
        {:ok, c} = Cashew.step3_alice(c_prime, r, pubkey)
        assert :ok = Cashew.verify(privkey, secret, c)
      end
    end

    property "roundtrip works with fresh keypairs each time" do
      check all(
              secret <- binary(min_length: 1, max_length: 256),
              max_runs: 1000
            ) do
        {:ok, {privkey, pubkey}} = Cashew.generate_keypair()
        {:ok, {b_prime, r}} = Cashew.step1_alice(secret)
        {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)
        {:ok, c} = Cashew.step3_alice(c_prime, r, pubkey)
        assert :ok = Cashew.verify(privkey, secret, c)
      end
    end
  end

  describe "denomination isolation" do
    property "signature under key A does not verify under key B" do
      check all(
              secret <- binary(min_length: 1, max_length: 256),
              max_runs: 1000
            ) do
        {:ok, {privkey_a, pubkey_a}} = Cashew.generate_keypair()
        {:ok, {privkey_b, _}} = Cashew.generate_keypair()

        {:ok, {b_prime, r}} = Cashew.step1_alice(secret)
        {:ok, c_prime} = Cashew.step2_bob(privkey_a, b_prime)
        {:ok, c} = Cashew.step3_alice(c_prime, r, pubkey_a)

        # Must verify with the signing key
        assert :ok = Cashew.verify(privkey_a, secret, c)

        # Must fail with a different key
        assert {:error, :invalid_signature} = Cashew.verify(privkey_b, secret, c)
      end
    end
  end

  describe "invalid signature rejection" do
    property "modified signatures are always rejected" do
      {:ok, {privkey, pubkey}} = Cashew.generate_keypair()

      check all(
              secret <- binary(min_length: 1, max_length: 256),
              other_secret <- binary(min_length: 1, max_length: 256),
              max_runs: 1000
            ) do
        {:ok, {b_prime, r}} = Cashew.step1_alice(secret)
        {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)
        {:ok, c} = Cashew.step3_alice(c_prime, r, pubkey)

        if other_secret != secret do
          assert {:error, :invalid_signature} = Cashew.verify(privkey, other_secret, c)
        end
      end
    end
  end

  describe "hash_to_curve determinism" do
    property "same input always yields same output" do
      check all(
              input <- binary(min_length: 0, max_length: 1000),
              max_runs: 1000
            ) do
        {:ok, point1} = Cashew.hash_to_curve(input)
        {:ok, point2} = Cashew.hash_to_curve(input)
        assert point1 == point2
        assert byte_size(point1) == 33
      end
    end

    property "different inputs produce different points" do
      check all(
              a <- binary(min_length: 1, max_length: 256),
              b <- binary(min_length: 1, max_length: 256),
              a != b,
              max_runs: 1000
            ) do
        {:ok, point_a} = Cashew.hash_to_curve(a)
        {:ok, point_b} = Cashew.hash_to_curve(b)
        assert point_a != point_b
      end
    end
  end

  describe "key generation" do
    property "all generated keys are valid (pubkey derivation roundtrips)" do
      check all(
              _ <- constant(nil),
              max_runs: 1000
            ) do
        {:ok, {privkey, pubkey}} = Cashew.generate_keypair()

        assert byte_size(privkey) == 32
        assert byte_size(pubkey) == 33

        {:ok, derived_pubkey} = Cashew.pubkey_from_privkey(privkey)
        assert derived_pubkey == pubkey
      end
    end

    property "different keys produce different signatures for same secret" do
      secret = "fixed_test_secret"

      check all(
              _ <- constant(nil),
              max_runs: 1000
            ) do
        {:ok, {privkey_a, pubkey_a}} = Cashew.generate_keypair()
        {:ok, {privkey_b, pubkey_b}} = Cashew.generate_keypair()

        {:ok, {b_prime_a, r_a}} = Cashew.step1_alice(secret)
        {:ok, c_prime_a} = Cashew.step2_bob(privkey_a, b_prime_a)
        {:ok, c_a} = Cashew.step3_alice(c_prime_a, r_a, pubkey_a)

        {:ok, {b_prime_b, r_b}} = Cashew.step1_alice(secret)
        {:ok, c_prime_b} = Cashew.step2_bob(privkey_b, b_prime_b)
        {:ok, c_b} = Cashew.step3_alice(c_prime_b, r_b, pubkey_b)

        # Different keys should produce different unblinded signatures
        assert c_a != c_b
      end
    end
  end
end
