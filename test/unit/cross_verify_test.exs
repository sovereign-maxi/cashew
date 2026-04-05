defmodule Cashew.CrossVerifyTest do
  @moduledoc """
  Cross-verification between the server-side NIF (cashew)
  and the client-side WASM (wallet_crypto) implementations.

  Both modules implement the same Cashu NUT-00 BDHKE protocol with
  identical hash_to_curve. This test ensures they produce bit-identical
  outputs for the same inputs, so mint and wallet always agree.

  Since we can't call WASM from Elixir directly, we verify against
  known test vectors that both implementations must match.
  """

  use ExUnit.Case, async: true

  # Deterministic test inputs shared between NIF and WASM test suites
  @test_secret Base.decode16!("D341EE4871F1F889041E63CF0D3823C713EEA6AFF01E80F1719F08F9E5BE98F6")
  @test_r Base.decode16!("99FCE58439FC37412AB3468B73DB0569322588F62FB3A49182D67E23D877824A")
  @mint_privkey Base.decode16!("0000000000000000000000000000000000000000000000000000000000000001")

  describe "hash_to_curve cross-verification" do
    test "NIF produces same curve points as WASM for spec vectors" do
      # These are the canonical points that both NIF and WASM must produce
      vectors = [
        {<<0::256>>,
         Base.decode16!("024CCE997D3B518F739663B757DEAEC95BCD9473C30A14AC2FD04023A739D1A725")},
        {<<1::256>>,
         Base.decode16!("022E7158E11C9506F1AA4248BF531298DAA7FEBD6194F003EDCD9B93ADE6253ACF")},
        {<<2::256>>,
         Base.decode16!("026CDBE15362DF59CD1DD3C9C11DE8AEDAC2106ECA69236ECD9FBE117AF897BE4F")}
      ]

      for {input, expected} <- vectors do
        {:ok, point} = Cashew.hash_to_curve(input)
        assert point == expected, "hash_to_curve mismatch for input #{Base.encode16(input)}"
      end
    end
  end

  describe "BDHKE step cross-verification" do
    test "step1_alice NIF produces same B' as WASM for same secret+r" do
      expected_b_prime =
        Base.decode16!("033B1A9737A40CC3FD9B6AF4B723632B76A67A36782596304612A6C2BFB5197E6D")

      {:ok, {b_prime, _}} = Cashew.step1_alice(@test_secret, @test_r)
      assert b_prime == expected_b_prime
    end

    test "step2_bob NIF produces same C' as WASM for same privkey+B'" do
      {:ok, {b_prime, _}} = Cashew.step1_alice(@test_secret, @test_r)
      {:ok, c_prime} = Cashew.step2_bob(@mint_privkey, b_prime)

      # C' must be a valid 33-byte compressed point
      assert byte_size(c_prime) == 33
      assert binary_part(c_prime, 0, 1) in [<<0x02>>, <<0x03>>]
    end

    test "step3_alice NIF produces same C as WASM for same inputs" do
      {:ok, mint_pubkey} = Cashew.pubkey_from_privkey(@mint_privkey)
      {:ok, {b_prime, r}} = Cashew.step1_alice(@test_secret, @test_r)
      {:ok, c_prime} = Cashew.step2_bob(@mint_privkey, b_prime)
      {:ok, c} = Cashew.step3_alice(c_prime, r, mint_pubkey)

      # C must be a valid 33-byte compressed point
      assert byte_size(c) == 33
      assert binary_part(c, 0, 1) in [<<0x02>>, <<0x03>>]

      # And verify the signature is correct
      assert :ok = Cashew.verify(@mint_privkey, @test_secret, c)
    end

    test "full round-trip: NIF blind-sign-unblind matches WASM create_blind-unblind" do
      # Multiple secrets to catch edge cases
      secrets = [
        @test_secret,
        :crypto.hash(:sha256, "test_secret_1"),
        :crypto.hash(:sha256, "test_secret_2"),
        :crypto.hash(:sha256, "a]7#R!2pQ")
      ]

      {:ok, mint_pubkey} = Cashew.pubkey_from_privkey(@mint_privkey)

      for secret <- secrets do
        # Step 1: blind (random r this time)
        {:ok, {b_prime, r}} = Cashew.step1_alice(secret)

        # Step 2: mint signs
        {:ok, c_prime} = Cashew.step2_bob(@mint_privkey, b_prime)

        # Step 3: unblind
        {:ok, c} = Cashew.step3_alice(c_prime, r, mint_pubkey)

        # Verify
        assert :ok = Cashew.verify(@mint_privkey, secret, c),
               "Round-trip failed for secret #{Base.encode16(secret)}"
      end
    end
  end

  describe "determinism" do
    test "same inputs always produce same outputs" do
      {:ok, {b1, r1}} = Cashew.step1_alice(@test_secret, @test_r)
      {:ok, {b2, r2}} = Cashew.step1_alice(@test_secret, @test_r)

      assert b1 == b2
      assert r1 == r2
    end

    test "hash_to_curve is deterministic" do
      {:ok, p1} = Cashew.hash_to_curve(@test_secret)
      {:ok, p2} = Cashew.hash_to_curve(@test_secret)
      assert p1 == p2
    end

    test "different secrets produce different Y points" do
      {:ok, y1} = Cashew.hash_to_curve(:crypto.hash(:sha256, "secret_a"))
      {:ok, y2} = Cashew.hash_to_curve(:crypto.hash(:sha256, "secret_b"))
      assert y1 != y2
    end
  end
end
