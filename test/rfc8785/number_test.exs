defmodule RFC8785.NumberTest do
  use ExUnit.Case, async: true

  # RFC 8785, Appendix B: Number Serialization Samples. Each entry is the
  # big-endian hex of an IEEE-754 double and its required serialization.
  # The NaN and Infinity rows of the appendix are absent because Erlang
  # floats cannot represent them; see the dedicated test below.
  @appendix_b [
    {"0000000000000000", "0"},
    {"8000000000000000", "0"},
    {"0000000000000001", "5e-324"},
    {"8000000000000001", "-5e-324"},
    {"7fefffffffffffff", "1.7976931348623157e+308"},
    {"ffefffffffffffff", "-1.7976931348623157e+308"},
    {"4340000000000000", "9007199254740992"},
    {"c340000000000000", "-9007199254740992"},
    {"4430000000000000", "295147905179352830000"},
    {"44b52d02c7e14af5", "9.999999999999997e+22"},
    {"44b52d02c7e14af6", "1e+23"},
    {"44b52d02c7e14af7", "1.0000000000000001e+23"},
    {"444b1ae4d6e2ef4e", "999999999999999700000"},
    {"444b1ae4d6e2ef4f", "999999999999999900000"},
    {"444b1ae4d6e2ef50", "1e+21"},
    {"3eb0c6f7a0b5ed8c", "9.999999999999997e-7"},
    {"3eb0c6f7a0b5ed8d", "0.000001"},
    {"41b3de4355555553", "333333333.3333332"},
    {"41b3de4355555554", "333333333.33333325"},
    {"41b3de4355555555", "333333333.3333333"},
    {"41b3de4355555556", "333333333.3333334"},
    {"41b3de4355555557", "333333333.33333343"},
    {"becbf647612f3696", "-0.0000033333333333333333"},
    {"43143ff3c1cb0959", "1424953923781206.2"}
  ]

  test "RFC 8785 Appendix B number serialization samples" do
    for {hex, expected} <- @appendix_b do
      <<value::float-64>> = Base.decode16!(hex, case: :lower)

      assert RFC8785.encode!(value) == expected,
             "0x#{hex} must serialize as #{expected}"
    end
  end

  test "NaN and Infinity are unrepresentable as Erlang floats" do
    # RFC 8785, Section 3.2.2.3, requires an error for NaN and Infinity.
    # Erlang's float type cannot hold either value, so such input cannot
    # reach the encoder in the first place: decoding their IEEE-754 bit
    # patterns as a float fails.
    for hex <- ["7fffffffffffffff", "7ff0000000000000", "fff0000000000000"] do
      assert_raise MatchError, fn ->
        <<_value::float-64>> = Base.decode16!(hex, case: :lower)
      end
    end
  end

  # Verified against Node.js JSON.stringify (ECMAScript NumberToString).
  # These pin the plain/exponential notation boundaries (n = 21 above,
  # n = -6 below) and the ECMA-262 formatting rules 6-10.
  @es6_boundaries [
    {123.45, "123.45"},
    {0.5, "0.5"},
    {3.141592653589793, "3.141592653589793"},
    {1.0e15, "1000000000000000"},
    {1.0e16, "10000000000000000"},
    {1.0e17, "100000000000000000"},
    {1.0e20, "100000000000000000000"},
    {1.0e21, "1e+21"},
    {1.0e22, "1e+22"},
    {5.0e21, "5e+21"},
    {1.5e21, "1.5e+21"},
    {123_456_780_000_000.0, "123456780000000"},
    {4.5e15, "4500000000000000"},
    {4.5e16, "45000000000000000"},
    {1_424_953_923_781_206.2, "1424953923781206.2"},
    {0.001, "0.001"},
    {1.0e-4, "0.0001"},
    {1.0e-5, "0.00001"},
    {1.0e-6, "0.000001"},
    {1.0e-7, "1e-7"},
    {1.7e-5, "0.000017"},
    {2.5e-7, "2.5e-7"},
    {2.5e-6, "0.0000025"},
    {-123.45, "-123.45"},
    {-1.0e21, "-1e+21"},
    {-1.0e-7, "-1e-7"},
    {1.0, "1"},
    {-1.0, "-1"},
    {100.0, "100"},
    {10.1, "10.1"}
  ]

  test "ECMAScript notation boundaries" do
    for {value, expected} <- @es6_boundaries do
      assert RFC8785.encode!(value) == expected,
             "#{inspect(value)} must serialize as #{expected}"
    end
  end

  test "negative zero serializes as 0" do
    <<minus_zero::float-64>> = Base.decode16!("8000000000000000", case: :lower)
    assert RFC8785.encode!(minus_zero) == "0"
  end

  describe "integers" do
    test "within ±2^53 serialize as exact digits" do
      assert RFC8785.encode!(0) == "0"
      assert RFC8785.encode!(42) == "42"
      assert RFC8785.encode!(-42) == "-42"
      assert RFC8785.encode!(9_007_199_254_740_992) == "9007199254740992"
      assert RFC8785.encode!(-9_007_199_254_740_992) == "-9007199254740992"
    end

    test "beyond ±2^53, digit-preserving integers are accepted" do
      # Each value is the canonical ES6 serialization of some IEEE-754
      # double (the three 21-digit ones appear in RFC 8785 Appendix B;
      # 72057594037927940 is the canonical form of 2^56), so each can arise
      # from parsing canonical output and must re-canonicalize unchanged.
      for int <- [
            72_057_594_037_927_940,
            295_147_905_179_352_830_000,
            999_999_999_999_999_700_000,
            999_999_999_999_999_900_000,
            -999_999_999_999_999_700_000
          ] do
        assert RFC8785.encode!(int) == Integer.to_string(int)
      end
    end

    test "bignum conversion is correctly rounded (BEAM `1.0 * int` is not)" do
      # Each value is canonical output of some double, but BEAM's own
      # bignum-to-float conversion returns the second-nearest double for it,
      # so an implementation built on `1.0 * int` rejects all of them.
      for int <- [
            428_654_966_685_883_400_000,
            -428_654_966_685_883_400_000,
            38_409_289_721_754_710_000,
            34_784_104_853_086_640_000,
            385_269_108_828_434_300_000,
            96_874_578_115_970_900_000,
            26_465_126_867_694_860_000,
            252_558_769_001_389_900_000
          ] do
        assert RFC8785.encode!(int) == Integer.to_string(int)
      end
    end

    test "digit-altering large integers are rejected" do
      for int <- [
            9_007_199_254_740_993,
            -9_007_199_254_740_993,
            10_000_000_000_000_000_000_000,
            18_446_744_073_709_551_616
          ] do
        error = assert_raise RFC8785.EncodeError, fn -> RFC8785.encode!(int) end
        assert error.message =~ "±2^53"
      end
    end

    test "integers beyond the IEEE-754 double range are rejected" do
      huge = Integer.pow(10, 400)

      for int <- [huge, -huge] do
        error = assert_raise RFC8785.EncodeError, fn -> RFC8785.encode!(int) end
        assert error.message =~ "double range"
      end
    end

    test "attacker-sized term integers are rejected before building enormous errors" do
      huge = Integer.pow(10, 100_000)

      error =
        assert_raise RFC8785.EncodeError, fn ->
          RFC8785.encode!(%{"payload" => [huge]})
        end

      assert error.message =~ "$.payload[0]"
      assert error.message =~ "double range"
      assert byte_size(error.message) < 500
    end

    test "canonical integer output always re-canonicalizes (idempotence)" do
      # Round-trip every non-negative integral serialization in Appendix B:
      # parse the digits back as an integer and re-encode.
      for {_hex, expected} <- @appendix_b,
          not String.contains?(expected, ["e", ".", "-"]) do
        int = String.to_integer(expected)
        assert RFC8785.encode!(int) == expected
      end
    end

    test "rejection error reports the path" do
      error =
        assert_raise RFC8785.EncodeError, fn ->
          RFC8785.encode!(%{"amounts" => [1, 9_007_199_254_740_993]})
        end

      assert error.message =~ "$.amounts[1]"
    end

    test "integer and equivalent float serialize identically" do
      assert RFC8785.encode!(100) == RFC8785.encode!(100.0)
      assert RFC8785.encode!(9_007_199_254_740_992) == RFC8785.encode!(9_007_199_254_740_992.0)
    end
  end
end
