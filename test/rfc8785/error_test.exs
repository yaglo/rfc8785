defmodule RFC8785.ErrorTest do
  use ExUnit.Case, async: true

  # Every reason documented on the two exception structs must be reachable,
  # and no failure may leave :reason nil — callers branch on it, so an
  # unreachable or missing reason is a broken contract.

  defp encode_cases do
    [
      {:integer_unrepresentable, fn -> RFC8785.encode(%{"n" => 9_007_199_254_740_993}) end},
      {:duplicate_name, fn -> RFC8785.encode(%{:a => 1, "a" => 2}) end},
      {:invalid_key, fn -> RFC8785.encode(%{1 => 2}) end},
      {:invalid_string, fn -> RFC8785.encode(<<0xFF>>) end},
      {:unsupported_term, fn -> RFC8785.encode(~D[2026-01-01]) end},
      {:improper_list, fn -> RFC8785.encode([1 | 2]) end}
    ]
  end

  defp decode_cases do
    [
      {:syntax, fn -> RFC8785.canonicalize("@") end},
      {:unexpected_end, fn -> RFC8785.canonicalize("{") end},
      {:trailing_data, fn -> RFC8785.canonicalize("[1] x") end},
      {:number_out_of_range, fn -> RFC8785.canonicalize("1e400") end},
      {:unpaired_surrogate, fn -> RFC8785.canonicalize(~S("\uDC00")) end},
      {:noncharacter, fn -> RFC8785.canonicalize(~S({"x":"﷐"})) end},
      {:duplicate_name, fn -> RFC8785.canonicalize(~S({"a":1,"a":2})) end},
      {:negative_zero, fn -> RFC8785.canonicalize("-0") end}
    ]
  end

  test "every documented EncodeError reason is reachable" do
    for {reason, fun} <- encode_cases() do
      assert {:error, %RFC8785.EncodeError{reason: ^reason}} = fun.(),
             "expected reason #{inspect(reason)}"
    end
  end

  test "every documented DecodeError reason is reachable" do
    for {reason, fun} <- decode_cases() do
      assert {:error, %RFC8785.DecodeError{reason: ^reason}} = fun.(),
             "expected reason #{inspect(reason)}"
    end
  end

  test "no failure leaves reason nil or message empty" do
    for {_reason, fun} <- encode_cases() ++ decode_cases() do
      assert {:error, error} = fun.()
      refute is_nil(error.reason)
      assert is_binary(error.message) and error.message != ""
    end
  end

  test "reasons stay inside the documented unions" do
    encode_reasons = Enum.map(encode_cases(), &elem(&1, 0))
    decode_reasons = Enum.map(decode_cases(), &elem(&1, 0))

    for {_reason, fun} <- encode_cases() do
      {:error, error} = fun.()
      assert error.reason in encode_reasons
    end

    for {_reason, fun} <- decode_cases() do
      {:error, error} = fun.()
      assert error.reason in decode_reasons
    end
  end

  test "raising variants carry the same reason as the tuple variants" do
    error = assert_raise RFC8785.EncodeError, fn -> RFC8785.encode!({:nope}) end
    assert error.reason == :unsupported_term

    error = assert_raise RFC8785.DecodeError, fn -> RFC8785.canonicalize!("-0") end
    assert error.reason == :negative_zero
  end
end
