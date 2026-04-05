defmodule Cashew.HashToCurveTest do
  use ExUnit.Case, async: true

  describe "hash_to_curve/1" do
    test "returns a valid 33-byte compressed point" do
      {:ok, point} = Cashew.hash_to_curve("test_secret")
      assert byte_size(point) == 33
      <<prefix, _::binary>> = point
      assert prefix in [0x02, 0x03]
    end

    test "is deterministic for same input" do
      {:ok, p1} = Cashew.hash_to_curve("deterministic_input")
      {:ok, p2} = Cashew.hash_to_curve("deterministic_input")
      assert p1 == p2
    end

    test "different inputs produce different points" do
      {:ok, p1} = Cashew.hash_to_curve("input_alpha")
      {:ok, p2} = Cashew.hash_to_curve("input_beta")
      assert p1 != p2
    end

    test "handles empty binary" do
      {:ok, point} = Cashew.hash_to_curve("")
      assert byte_size(point) == 33
    end

    test "handles binary with null bytes" do
      {:ok, point} = Cashew.hash_to_curve(<<0, 0, 0, 0>>)
      assert byte_size(point) == 33
    end

    test "handles large input" do
      {:ok, point} = Cashew.hash_to_curve(:binary.copy(<<0xFF>>, 1_000))
      assert byte_size(point) == 33
    end

    test "result differs from SHA256 of input" do
      input = "not_sha256"
      {:ok, point} = Cashew.hash_to_curve(input)
      sha = :crypto.hash(:sha256, input)
      # The point is 33 bytes (with prefix), sha is 32 bytes — structurally different
      assert point != <<0x02>> <> sha
      assert point != <<0x03>> <> sha
    end
  end
end
