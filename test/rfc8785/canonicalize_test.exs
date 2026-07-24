defmodule RFC8785.CanonicalizeTest do
  use ExUnit.Case, async: true

  describe "canonicalize!/1" do
    test "decodes, sorts, and re-encodes JSON text" do
      assert RFC8785.canonicalize!(~S({"b": 2, "a": [1E30, 4.50, "x"]})) ==
               ~S({"a":[1e+30,4.5,"x"],"b":2})
    end

    test "null decodes to the JSON literal, not an atom string" do
      assert RFC8785.canonicalize!(~S({"a": null})) == ~S({"a":null})
      assert RFC8785.canonicalize!("null") == "null"
    end

    test "surrounding whitespace is accepted" do
      assert RFC8785.canonicalize!("  [1, 2]\r\n\t ") == "[1,2]"
    end

    test "scalar documents canonicalize" do
      assert RFC8785.canonicalize!("2E-3") == "0.002"
      assert RFC8785.canonicalize!("0.100000000000000005") == "0.1"
      assert RFC8785.canonicalize!(~S("a\tb")) == ~S("a\tb")
      assert RFC8785.canonicalize!("true") == "true"
    end

    test "digit-preserving large number tokens survive as integers" do
      assert RFC8785.canonicalize!("428654966685883400000") == "428654966685883400000"

      assert RFC8785.canonicalize!("-428654966685883400000") ==
               "-428654966685883400000"
    end

    test "digit-altering integer tokens raise EncodeError" do
      error =
        assert_raise RFC8785.EncodeError, fn ->
          RFC8785.canonicalize!(~S({"n": 9007199254740993}))
        end

      assert error.message =~ "$.n"
    end

    test "negative-zero tokens and negative underflow raise DecodeError" do
      for bad <- [
            "-0",
            "-0e0",
            "-0E+999999",
            "-0.0",
            "-0.000e+10",
            "-1e-400",
            "-0.0000000000000000000000000000000000000000000000000000000000000000001e-999"
          ] do
        error = assert_raise RFC8785.DecodeError, fn -> RFC8785.canonicalize!(bad) end
        assert error.message =~ "negative zero"
        assert error.message =~ "$"
      end
    end

    test "negative-zero rejection reports nested array and object paths" do
      for {json, path} <- [
            {~S({"amount":-0}), "$.amount"},
            {~S({"amount":-0e0}), "$.amount"},
            {~S({"outer":[1,-0.0]}), "$.outer[1]"},
            {~S({"outer":{"amount":-1e-400}}), "$.outer.amount"}
          ] do
        error = assert_raise RFC8785.DecodeError, fn -> RFC8785.canonicalize!(json) end
        assert error.message =~ path
      end
    end

    test "positive zero and positive underflow remain accepted" do
      for good <- ["0", "0.0", "0e0", "1e-400"] do
        assert RFC8785.canonicalize!(good) == "0"
      end
    end

    test "negative-zero-looking text inside strings is not treated as a number" do
      assert RFC8785.canonicalize!(~S(["-0","escaped quote: \"-0e0\""])) ==
               ~S(["-0","escaped quote: \"-0e0\""])
    end

    test "attacker-sized integer tokens are rejected with bounded path errors" do
      digits = :binary.copy("9", 100_000)
      json = ~S({"payload":[) <> digits <> "]}"

      error = assert_raise RFC8785.EncodeError, fn -> RFC8785.canonicalize!(json) end
      assert error.message =~ "$.payload[0]"
      assert error.message =~ "at least 1e21"
      assert byte_size(error.message) < 500
    end

    test "duplicate object names raise DecodeError instead of dropping pairs" do
      error =
        assert_raise RFC8785.DecodeError, fn ->
          RFC8785.canonicalize!(~S({"a": 1, "b": 2, "a": 3}))
        end

      assert error.message =~ "duplicate object name"
      assert error.message =~ "I-JSON"
    end

    test "duplicate names in nested objects are also detected" do
      assert_raise RFC8785.DecodeError, fn ->
        RFC8785.canonicalize!(~S([{"x": {"k": 1, "k": 2}}]))
      end
    end

    test "escaped and literal spellings of the same name are duplicates" do
      # "\u0061" and "a" decode to the same name; detection happens after
      # unescaping, as I-JSON requires.
      assert_raise RFC8785.DecodeError, fn ->
        RFC8785.canonicalize!(~S({"\u0061": 1, "a": 2}))
      end
    end

    test "number literals outside the double range raise DecodeError" do
      for bad <- ["1e400", "-1e400", "1e999999"] do
        error = assert_raise RFC8785.DecodeError, fn -> RFC8785.canonicalize!(bad) end
        assert error.message =~ "IEEE-754 double range"
      end
    end

    test "errors for attacker-sized invalid number tokens are bounded" do
      for bad <- [
            "1e" <> :binary.copy("9", 100_000),
            :binary.copy("9", 100_000) <> ".0"
          ] do
        error = assert_raise RFC8785.DecodeError, fn -> RFC8785.canonicalize!(bad) end
        assert error.message =~ "10000"
        assert error.message =~ "bytes total"
        assert byte_size(error.message) < 500
      end
    end

    test "unpaired surrogate escapes raise DecodeError" do
      # A lone low surrogate and a high-high pair fail as escape sequences;
      # a lone trailing high surrogate fails when its pair lookahead runs
      # past the end of the input.
      for bad <- [~S("\uDC00"), ~S("\uD800\uD800"), ~S("\uD800")] do
        assert_raise RFC8785.DecodeError, fn -> RFC8785.canonicalize!(bad) end
      end
    end

    test "non-hex escape digits are reported as invalid escapes, not surrogates" do
      error = assert_raise RFC8785.DecodeError, fn -> RFC8785.canonicalize!(~S("\uZZZZ")) end
      assert error.message =~ "invalid \\u escape"
      refute error.message =~ "surrogate"

      error = assert_raise RFC8785.DecodeError, fn -> RFC8785.canonicalize!(~S("\uDC00")) end
      assert error.message =~ "unpaired surrogate"
    end

    test "invalid bytes are reported with zero-padded hex" do
      error =
        assert_raise RFC8785.DecodeError, fn ->
          RFC8785.canonicalize!(<<?", 0xFF, ?">>)
        end

      assert error.message =~ "0xff"

      error =
        assert_raise RFC8785.DecodeError, fn ->
          RFC8785.canonicalize!(<<?", 0x01, ?">>)
        end

      assert error.message =~ "0x01"
    end

    test "empty input raises DecodeError" do
      assert_raise RFC8785.DecodeError, fn -> RFC8785.canonicalize!("") end
      assert_raise RFC8785.DecodeError, fn -> RFC8785.canonicalize!("   ") end
    end

    test "a byte-order mark is rejected, per RFC 8259" do
      assert_raise RFC8785.DecodeError, fn ->
        RFC8785.canonicalize!(<<0xEF, 0xBB, 0xBF>> <> "{}")
      end
    end

    test "syntax errors raise DecodeError" do
      for bad <- ["{", "[1,", ~S({"a" 1}), "01", "+1", "nul", ~S("unterminated)] do
        assert_raise RFC8785.DecodeError, fn -> RFC8785.canonicalize!(bad) end
      end
    end

    test "trailing non-whitespace data raises DecodeError" do
      error =
        assert_raise RFC8785.DecodeError, fn ->
          RFC8785.canonicalize!(~S([1] [2]))
        end

      assert error.message =~ "after the JSON document"
    end
  end

  describe "canonicalize/1" do
    test "wraps success and both error kinds" do
      assert RFC8785.canonicalize(~S({"a": 1})) == {:ok, ~S({"a":1})}
      assert {:error, %RFC8785.DecodeError{}} = RFC8785.canonicalize("{")
      assert {:error, %RFC8785.DecodeError{}} = RFC8785.canonicalize("-0")
      assert {:error, %RFC8785.EncodeError{}} = RFC8785.canonicalize("9007199254740993")

      assert {:error, %RFC8785.EncodeError{}} =
               RFC8785.canonicalize("1000000000000000000000")
    end
  end

  describe "decode!/1" do
    test "null decodes to nil, which re-encodes as the null literal" do
      assert RFC8785.decode!(~S({"a": null})) == %{"a" => nil}
      assert RFC8785.decode!(~S({"a": null})) |> RFC8785.encode!() == ~S({"a":null})
    end

    test "duplicate object names raise DecodeError" do
      assert_raise RFC8785.DecodeError, fn ->
        RFC8785.decode!(~S({"a": 1, "a": 2}))
      end
    end

    test "negative zero and noncharacters raise DecodeError during decoding" do
      error =
        assert_raise RFC8785.DecodeError, fn ->
          RFC8785.decode!(~S({"amount":-0}))
        end

      assert error.message =~ "$.amount"

      noncharacter = <<0xFFFF::utf8>>

      error =
        assert_raise RFC8785.DecodeError, fn ->
          RFC8785.decode!(~S({"name":") <> noncharacter <> ~S("}))
        end

      assert error.message =~ "$.name"
    end

    test "trailing non-whitespace data raises DecodeError" do
      assert_raise RFC8785.DecodeError, fn -> RFC8785.decode!("[1] x") end
    end

    test "decode then encode agrees with canonicalize" do
      text = ~S({"z": [1E30, null], "a": {"k": "v"}})
      assert RFC8785.decode!(text) |> RFC8785.encode!() == RFC8785.canonicalize!(text)
    end

    test "public decoding retains the integer term mapping for long plain tokens" do
      token = :binary.copy("9", 1_000)
      decoded = RFC8785.decode!(token)

      assert is_integer(decoded)
      assert :erlang.integer_to_binary(decoded) == token
    end

    test "successful decoding does not bypass term-side encoding checks" do
      decoded = RFC8785.decode!("9007199254740993")

      assert decoded == 9_007_199_254_740_993
      assert {:error, %RFC8785.EncodeError{}} = RFC8785.encode(decoded)
      assert {:error, %RFC8785.EncodeError{}} = RFC8785.canonicalize("9007199254740993")
    end

    test "strip-proof workflow produces correct canonical bytes" do
      secured = ~S({"claim": {"name": null}, "proof": {"type": "DataIntegrityProof"}})

      unsecured =
        secured
        |> RFC8785.decode!()
        |> Map.delete("proof")
        |> RFC8785.encode!()

      assert unsecured == ~S({"claim":{"name":null}})
    end
  end

  describe "decode/1" do
    test "wraps success and decode errors" do
      assert RFC8785.decode(~S({"a": null})) == {:ok, %{"a" => nil}}
      assert {:error, %RFC8785.DecodeError{}} = RFC8785.decode("{")
      assert {:error, %RFC8785.DecodeError{}} = RFC8785.decode("-0e0")
      assert {:error, %RFC8785.DecodeError{}} = RFC8785.decode(~S({"a": 1, "a": 2}))
    end
  end

  describe "encode_to_iodata/1" do
    test "wraps success and encode errors" do
      assert {:ok, iodata} = RFC8785.encode_to_iodata(%{"a" => 1})
      assert IO.iodata_to_binary(iodata) == ~S({"a":1})
      assert {:error, %RFC8785.EncodeError{}} = RFC8785.encode_to_iodata({:tuple})
    end
  end
end
