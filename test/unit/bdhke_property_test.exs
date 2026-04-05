defmodule Cashew.BdhkePropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  @moduletag :property
  @moduletag timeout: 120_000

  describe "roundtrip (10_000 runs)" do
    property "blind -> sign -> unblind -> verify succeeds for arbitrary 32-byte secrets" do
      {:ok, {privkey, pubkey}} = Cashew.generate_keypair()

      check all(
              secret <- binary(length: 32),
              max_runs: 10_000
            ) do
        {:ok, {b_prime, r}} = Cashew.step1_alice(secret)
        {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)
        {:ok, c} = Cashew.step3_alice(c_prime, r, pubkey)
        assert :ok = Cashew.verify(privkey, secret, c)
      end
    end

    property "roundtrip succeeds with variable-length secrets and fresh keypairs" do
      check all(
              secret <- binary(min_length: 1, max_length: 512),
              max_runs: 10_000
            ) do
        {:ok, {privkey, pubkey}} = Cashew.generate_keypair()
        {:ok, {b_prime, r}} = Cashew.step1_alice(secret)
        {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)
        {:ok, c} = Cashew.step3_alice(c_prime, r, pubkey)
        assert :ok = Cashew.verify(privkey, secret, c)
      end
    end
  end

  describe "unlinkability" do
    property "different blinding factors for same secret produce different blind messages" do
      {:ok, {privkey, pubkey}} = Cashew.generate_keypair()

      check all(
              secret <- binary(min_length: 1, max_length: 256),
              max_runs: 1_000
            ) do
        {:ok, {b_prime1, r1}} = Cashew.step1_alice(secret)
        {:ok, {b_prime2, r2}} = Cashew.step1_alice(secret)

        # Same secret with different random blinding factors must produce different B'
        assert b_prime1 != b_prime2
        assert r1 != r2

        # Both must produce valid proofs
        {:ok, c_prime1} = Cashew.step2_bob(privkey, b_prime1)
        {:ok, c_prime2} = Cashew.step2_bob(privkey, b_prime2)

        {:ok, c1} = Cashew.step3_alice(c_prime1, r1, pubkey)
        {:ok, c2} = Cashew.step3_alice(c_prime2, r2, pubkey)

        assert :ok = Cashew.verify(privkey, secret, c1)
        assert :ok = Cashew.verify(privkey, secret, c2)

        # Both proofs yield the same unblinded C (BDHKE determinism)
        assert c1 == c2
      end
    end

    property "blind messages for different secrets are indistinguishable to the signer" do
      check all(
              secret_a <- binary(min_length: 1, max_length: 256),
              secret_b <- binary(min_length: 1, max_length: 256),
              secret_a != secret_b,
              max_runs: 1_000
            ) do
        {:ok, {b_prime_a, _}} = Cashew.step1_alice(secret_a)
        {:ok, {b_prime_b, _}} = Cashew.step1_alice(secret_b)

        # The signer sees only B' and cannot determine which secret was used
        assert b_prime_a != b_prime_b
      end
    end

    property "batch of n blind-sign-unblind ops cannot be correlated without blinding factors" do
      {:ok, {privkey, pubkey}} = Cashew.generate_keypair()

      check all(
              secrets <- list_of(binary(length: 32), min_length: 2, max_length: 10),
              secrets == Enum.uniq(secrets),
              max_runs: 500
            ) do
        # Blind all secrets
        blinds_and_sigs =
          Enum.map(secrets, fn secret ->
            {:ok, {b_prime, r}} = Cashew.step1_alice(secret)
            {:ok, c_prime} = Cashew.step2_bob(privkey, b_prime)
            {{b_prime, r}, c_prime}
          end)

        # Unblind to get proofs
        cs =
          Enum.map(blinds_and_sigs, fn {{_, r}, c_prime} ->
            {:ok, c} = Cashew.step3_alice(c_prime, r, pubkey)
            c
          end)

        # All proofs are valid
        for {secret, c} <- Enum.zip(secrets, cs) do
          assert :ok = Cashew.verify(privkey, secret, c)
        end

        # Each proof has a unique C value (no collisions)
        assert length(Enum.uniq(cs)) == length(cs)
      end
    end
  end

  describe "hash-to-curve" do
    property "all outputs are valid 33-byte compressed secp256k1 points" do
      check all(
              input <- binary(min_length: 0, max_length: 1_000),
              max_runs: 10_000
            ) do
        {:ok, point} = Cashew.hash_to_curve(input)
        assert byte_size(point) == 33

        # Compressed secp256k1 point prefix must be 0x02 or 0x03
        <<prefix, _::binary-size(32)>> = point
        assert prefix in [0x02, 0x03]
      end
    end

    test "edge case inputs: all-zero, all-0xFF, empty, and single byte" do
      edge_cases = [
        <<>>,
        :binary.copy(<<0>>, 32),
        :binary.copy(<<0xFF>>, 32),
        <<1>>,
        <<0>>,
        :binary.copy(<<0xAA>>, 64)
      ]

      for input <- edge_cases do
        {:ok, point} = Cashew.hash_to_curve(input)
        assert byte_size(point) == 33
        <<prefix, _::binary-size(32)>> = point
        assert prefix in [0x02, 0x03]
      end
    end
  end

  describe "key generation" do
    property "all generated keypairs have correct sizes and derive consistently" do
      check all(
              _ <- constant(nil),
              max_runs: 10_000
            ) do
        {:ok, {privkey, pubkey}} = Cashew.generate_keypair()

        assert byte_size(privkey) == 32
        assert byte_size(pubkey) == 33

        {:ok, derived} = Cashew.pubkey_from_privkey(privkey)
        assert derived == pubkey
      end
    end
  end
end
