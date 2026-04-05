defmodule Cashew.SpecVectorsTest do
  @moduledoc """
  Cashu NUT-00 specification test vectors.

  These vectors are taken directly from the Cashu protocol specification
  to ensure our hash_to_curve and BDHKE implementations produce identical
  outputs to standard Cashu wallets (Nutshell, Minibits, eNuts).

  Source: https://github.com/cashubtc/nuts/blob/main/tests/00-tests.md
  """

  use ExUnit.Case, async: true

  # -- NUT-00: hash_to_curve spec test vectors --

  describe "hash_to_curve spec vectors" do
    test "vector 1: all zeros" do
      message = Base.decode16!("0000000000000000000000000000000000000000000000000000000000000000")

      expected =
        Base.decode16!("024CCE997D3B518F739663B757DEAEC95BCD9473C30A14AC2FD04023A739D1A725")

      {:ok, point} = Cashew.hash_to_curve(message)
      assert point == expected
    end

    test "vector 2: ...0001" do
      message = Base.decode16!("0000000000000000000000000000000000000000000000000000000000000001")

      expected =
        Base.decode16!("022E7158E11C9506F1AA4248BF531298DAA7FEBD6194F003EDCD9B93ADE6253ACF")

      {:ok, point} = Cashew.hash_to_curve(message)
      assert point == expected
    end

    test "vector 3: ...0002" do
      message = Base.decode16!("0000000000000000000000000000000000000000000000000000000000000002")

      expected =
        Base.decode16!("026CDBE15362DF59CD1DD3C9C11DE8AEDAC2106ECA69236ECD9FBE117AF897BE4F")

      {:ok, point} = Cashew.hash_to_curve(message)
      assert point == expected
    end
  end

  # -- NUT-00: BDHKE blinded messages (step1_alice) --

  describe "BDHKE blinded messages spec vectors" do
    test "vector 1: step1_alice produces expected B'" do
      secret = Base.decode16!("D341EE4871F1F889041E63CF0D3823C713EEA6AFF01E80F1719F08F9E5BE98F6")
      r = Base.decode16!("99FCE58439FC37412AB3468B73DB0569322588F62FB3A49182D67E23D877824A")

      expected_b_prime =
        Base.decode16!("033B1A9737A40CC3FD9B6AF4B723632B76A67A36782596304612A6C2BFB5197E6D")

      {:ok, {b_prime, returned_r}} = Cashew.step1_alice(secret, r)
      assert b_prime == expected_b_prime
      assert returned_r == r
    end

    test "vector 2: step1_alice produces expected B'" do
      secret = Base.decode16!("F1AAF16C2239746F369572C0784D9DD3D032D952C2D992175873FB58FAE31A60")
      r = Base.decode16!("F78476EA7CC9ADE20F9E05E58A804CF19533F03EA805ECE5FEE88C8E2874BA50")

      expected_b_prime =
        Base.decode16!("029BDF2D716EE366EDDF599BA252786C1033F47E230248A4612A5670AB931F1763")

      {:ok, {b_prime, returned_r}} = Cashew.step1_alice(secret, r)
      assert b_prime == expected_b_prime
      assert returned_r == r
    end
  end

  # -- NUT-00: BDHKE blinded signatures (step2_bob) --

  describe "BDHKE blinded signatures spec vectors" do
    test "vector 1: mint key 1 signs B'" do
      mint_privkey =
        Base.decode16!("0000000000000000000000000000000000000000000000000000000000000001")

      b_prime =
        Base.decode16!("02A9ACC1E48C25EEEB9289B5031CC57DA9FE72F3FE2861D264BDC074209B107BA2")

      expected_c_prime =
        Base.decode16!("02A9ACC1E48C25EEEB9289B5031CC57DA9FE72F3FE2861D264BDC074209B107BA2")

      {:ok, c_prime} = Cashew.step2_bob(mint_privkey, b_prime)
      assert c_prime == expected_c_prime
    end

    test "vector 2: mint key 7f...7f signs B'" do
      mint_privkey =
        Base.decode16!("7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F")

      b_prime =
        Base.decode16!("02A9ACC1E48C25EEEB9289B5031CC57DA9FE72F3FE2861D264BDC074209B107BA2")

      expected_c_prime =
        Base.decode16!("0398BC70CE8184D27BA89834D19F5199C84443C31131E48D3C1214DB24247D005D")

      {:ok, c_prime} = Cashew.step2_bob(mint_privkey, b_prime)
      assert c_prime == expected_c_prime
    end
  end

  # -- Full BDHKE round-trip with deterministic blinding factor --

  describe "BDHKE round-trip" do
    test "full blind-sign-unblind-verify cycle with spec vector inputs" do
      # Use vector 1 blinding factor and secret
      secret = Base.decode16!("D341EE4871F1F889041E63CF0D3823C713EEA6AFF01E80F1719F08F9E5BE98F6")
      r = Base.decode16!("99FCE58439FC37412AB3468B73DB0569322588F62FB3A49182D67E23D877824A")

      # Generate a known mint keypair (privkey = 1)
      mint_privkey =
        Base.decode16!("0000000000000000000000000000000000000000000000000000000000000001")

      {:ok, mint_pubkey} = Cashew.pubkey_from_privkey(mint_privkey)

      # Step 1: Alice blinds
      {:ok, {b_prime, ^r}} = Cashew.step1_alice(secret, r)

      # Step 2: Bob signs
      {:ok, c_prime} = Cashew.step2_bob(mint_privkey, b_prime)

      # Step 3: Alice unblinds
      {:ok, c} = Cashew.step3_alice(c_prime, r, mint_pubkey)

      # Verify: mint can verify the unblinded signature
      assert :ok = Cashew.verify(mint_privkey, secret, c)
    end

    test "full cycle with different mint key (7f...7f)" do
      secret = Base.decode16!("D341EE4871F1F889041E63CF0D3823C713EEA6AFF01E80F1719F08F9E5BE98F6")
      r = Base.decode16!("99FCE58439FC37412AB3468B73DB0569322588F62FB3A49182D67E23D877824A")

      mint_privkey =
        Base.decode16!("7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F")

      {:ok, mint_pubkey} = Cashew.pubkey_from_privkey(mint_privkey)

      {:ok, {b_prime, ^r}} = Cashew.step1_alice(secret, r)
      {:ok, c_prime} = Cashew.step2_bob(mint_privkey, b_prime)
      {:ok, c} = Cashew.step3_alice(c_prime, r, mint_pubkey)

      assert :ok = Cashew.verify(mint_privkey, secret, c)
    end

    test "wrong mint key fails verification" do
      secret = Base.decode16!("D341EE4871F1F889041E63CF0D3823C713EEA6AFF01E80F1719F08F9E5BE98F6")
      r = Base.decode16!("99FCE58439FC37412AB3468B73DB0569322588F62FB3A49182D67E23D877824A")

      # Sign with key 1
      mint_privkey =
        Base.decode16!("0000000000000000000000000000000000000000000000000000000000000001")

      {:ok, mint_pubkey} = Cashew.pubkey_from_privkey(mint_privkey)

      {:ok, {b_prime, ^r}} = Cashew.step1_alice(secret, r)
      {:ok, c_prime} = Cashew.step2_bob(mint_privkey, b_prime)
      {:ok, c} = Cashew.step3_alice(c_prime, r, mint_pubkey)

      # Verify with different key fails
      wrong_privkey =
        Base.decode16!("7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F7F")

      assert {:error, :invalid_signature} = Cashew.verify(wrong_privkey, secret, c)
    end
  end
end
