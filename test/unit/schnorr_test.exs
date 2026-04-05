defmodule Cashew.SchnorrTest do
  use ExUnit.Case, async: true

  describe "schnorr_sign/2 + schnorr_verify/3 roundtrip" do
    test "valid signature verifies" do
      {:ok, {privkey, pubkey}} = Cashew.generate_keypair()
      <<_::8, xonly::binary-32>> = pubkey
      msg = :crypto.hash(:sha256, "test message")

      {:ok, {sig, returned_xonly}} = Cashew.schnorr_sign(privkey, msg)
      assert byte_size(sig) == 64
      assert returned_xonly == xonly
      assert :ok = Cashew.schnorr_verify(xonly, msg, sig)
    end

    test "wrong message fails verification" do
      {:ok, {privkey, pubkey}} = Cashew.generate_keypair()
      <<_::8, xonly::binary-32>> = pubkey
      msg = :crypto.hash(:sha256, "msg1")
      wrong = :crypto.hash(:sha256, "msg2")

      {:ok, {sig, _}} = Cashew.schnorr_sign(privkey, msg)
      assert {:error, :invalid_signature} = Cashew.schnorr_verify(xonly, wrong, sig)
    end

    test "wrong key fails verification" do
      {:ok, {privkey, _}} = Cashew.generate_keypair()
      {:ok, {_, other_pubkey}} = Cashew.generate_keypair()
      <<_::8, other_xonly::binary-32>> = other_pubkey
      msg = :crypto.hash(:sha256, "test")

      {:ok, {sig, _}} = Cashew.schnorr_sign(privkey, msg)
      assert {:error, :invalid_signature} = Cashew.schnorr_verify(other_xonly, msg, sig)
    end

    test "rejects invalid input sizes" do
      # privkey too short
      assert {:error, _} = Cashew.schnorr_sign(<<0::128>>, <<0::256>>)
      # msg too short
      assert {:error, _} = Cashew.schnorr_sign(<<0::256>>, <<0::128>>)
      # xonly too short
      assert {:error, _} = Cashew.schnorr_verify(<<0::128>>, <<0::256>>, <<0::512>>)
    end
  end
end
