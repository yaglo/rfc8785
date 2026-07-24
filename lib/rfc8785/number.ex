defmodule RFC8785.Number do
  @moduledoc false

  # Number serialization per RFC 8785, Section 3.2.2.3: JSON numbers MUST be
  # serialized exactly as ECMAScript's `Number::toString` (ECMA-262,
  # "NumberToString", section 7.1.12.1 in the 2019 edition referenced by the
  # RFC) serializes IEEE-754 double precision values.
  #
  # Strategy:
  #
  #   1. Obtain the shortest round-tripping decimal digits for the float from
  #      Erlang's Ryu implementation (`:erlang.float_to_binary(f, [:short])`,
  #      OTP >= 25). Ryu computes exactly the digits required by NumberToString
  #      step 5 (including the round-to-even tie rule from Note 2).
  #   2. Parse that output with a *total* parser into `{digits, n}`, where
  #      `digits` is the significant digits `s` as a string (no leading or
  #      trailing zeros, `k = byte_size(digits)`) and `n` is the base-10
  #      position of the decimal point, so that the value equals
  #      `s * 10^(n - k)`. This step is independent of whether Erlang chose
  #      plain or scientific notation, so no assumption about Erlang's
  #      (undocumented) notation-selection heuristics is needed.
  #   3. Format `{digits, n}` following NumberToString steps 6-10 literally,
  #      one function clause per rule.

  import Bitwise

  alias RFC8785.EncodeError

  # 2^53. Every integer with |i| <= 2^53 is exactly representable as an
  # IEEE-754 double, and NumberToString renders it as its plain decimal
  # digits (k <= 16 implies n <= 21, rule 6), so emitting the integer's
  # digits directly is byte-identical to converting through a float.
  @two_pow_53 9_007_199_254_740_992

  # No integer whose magnitude is at least 1e21 can preserve its plain decimal
  # digits through an IEEE-754 double: finite values at that magnitude use
  # ECMAScript exponential notation, and still larger values overflow the
  # double range. Check this before Integer.to_string/1; converting an
  # attacker-controlled, million-digit bignum to decimal is needlessly
  # expensive and would also create an enormous exception message.
  @one_e21 1_000_000_000_000_000_000_000

  @doc """
  Serializes an integer.

  Integers within `±2^53` serialize as their exact digits. A larger
  integer is accepted when the canonical form of its nearest IEEE-754
  double reproduces the same digits; integers parsed from canonical JCS
  output always pass this check. Anything else raises
  `RFC8785.EncodeError`: serialization would alter the digits, or the
  value is outside the double range.
  """
  @spec encode_integer(integer(), EncodeError.path()) :: binary()
  # :erlang.is_integer/3 rather than `abs(int) <= @two_pow_53`: abs/1
  # allocates a sign-flipped copy of the whole bignum before the comparison
  # rejects it, which an oversized token turns into work proportional to its
  # size. The guard BIF allocates nothing (measured 62x on a million-digit
  # negative integer). It must be written fully qualified to be guard-safe.
  def encode_integer(int, _path)
      when :erlang.is_integer(int, -@two_pow_53, @two_pow_53),
      do: Integer.to_string(int)

  def encode_integer(int, path) when is_integer(int),
    do: encode_large_integer(int, path)

  defp encode_large_integer(int, path) do
    if int <= -@one_e21 or int >= @one_e21 do
      raise EncodeError,
        reason: :integer_unrepresentable,
        message:
          "cannot canonicalize integer at #{EncodeError.format_path(path)}: " <>
            "its magnitude is at least 1e21. Finite IEEE-754 doubles at this " <>
            "magnitude use exponential notation, while still larger values " <>
            "are outside the double range, so none can preserve the integer's " <>
            "plain decimal digits (interoperable integers stay within ±2^53). " <>
            "Encode it as a string."
    end

    digits = Integer.to_string(int)

    case nearest_double(int) do
      float when is_float(float) ->
        canonical = encode_float(float)

        if canonical == digits do
          digits
        else
          raise EncodeError,
            reason: :integer_unrepresentable,
            message:
              "cannot canonicalize integer #{digits} at " <>
                "#{EncodeError.format_path(path)}: RFC 8785 represents numbers " <>
                "as IEEE-754 doubles, and the canonical form of this value's " <>
                "nearest double is #{canonical}, which does not preserve the " <>
                "integer's decimal digits (interoperable integers stay within " <>
                "±2^53). Convert the value to a float to accept that form, or " <>
                "encode it as a string."
        end

      :overflow ->
        raise EncodeError,
          reason: :integer_unrepresentable,
          message:
            "cannot canonicalize integer #{digits} at " <>
              "#{EncodeError.format_path(path)}: the value is outside the " <>
              "IEEE-754 double range. Encode it as a string."
    end
  end

  # Correctly rounded integer-to-double conversion, round half to even.
  #
  # BEAM's own conversion (`:erlang.float/1`, mixed-type arithmetic such as
  # `1.0 * int`) is not correctly rounded for integers wider than 64 bits:
  # for example `1.0 * 428654966685883400000` yields the second-nearest
  # double. Using it here would falsely reject integers that are the exact
  # decimal form of a double. The conversion is therefore done directly:
  # take the top 53 bits of the magnitude, round on the remainder, and
  # assemble the IEEE-754 encoding.
  #
  # Only called with |int| > 2^53, so the magnitude always has more than
  # 53 significant bits.
  defp nearest_double(int) when int < 0 do
    case nearest_double(-int) do
      :overflow -> :overflow
      float -> -float
    end
  end

  defp nearest_double(int) do
    width = bit_width(int)
    shift = width - 53
    mantissa = int >>> shift
    remainder = int - (mantissa <<< shift)
    half = 1 <<< (shift - 1)

    mantissa =
      cond do
        remainder > half -> mantissa + 1
        remainder < half -> mantissa
        (mantissa &&& 1) == 1 -> mantissa + 1
        true -> mantissa
      end

    # Rounding up can carry into a 54th bit (mantissa == 2^53).
    {mantissa, shift} =
      if mantissa == 1 <<< 53 do
        {mantissa >>> 1, shift + 1}
      else
        {mantissa, shift}
      end

    # Value is mantissa * 2^shift with mantissa in [2^52, 2^53), that is
    # 1.fraction * 2^exponent with exponent = shift + 52.
    exponent = shift + 52

    if exponent > 1023 do
      :overflow
    else
      <<float::float-64>> = <<0::1, exponent + 1023::11, mantissa - (1 <<< 52)::52>>
      float
    end
  end

  defp bit_width(int) do
    bytes = :binary.encode_unsigned(int)
    <<first, _::binary>> = bytes
    bit_size(bytes) - 8 + significant_bits(first)
  end

  defp significant_bits(byte) when byte >= 128, do: 8
  defp significant_bits(byte) when byte >= 64, do: 7
  defp significant_bits(byte) when byte >= 32, do: 6
  defp significant_bits(byte) when byte >= 16, do: 5
  defp significant_bits(byte) when byte >= 8, do: 4
  defp significant_bits(byte) when byte >= 4, do: 3
  defp significant_bits(byte) when byte >= 2, do: 2
  defp significant_bits(_byte), do: 1

  @doc """
  Serializes a float exactly as ECMAScript `Number::toString` would.

  Erlang floats cannot hold `NaN` or `Infinity`, so the RFC's requirement to
  reject those values is enforced by the type system itself.
  """
  @spec encode_float(float()) :: binary()
  def encode_float(float) when is_float(float) do
    cond do
      # NumberToString rule 2: +0 and -0 both serialize as "0".
      float == 0.0 -> "0"
      # Rule 3: negative values are "-" followed by the positive serialization.
      float < 0 -> "-" <> encode_positive(-float)
      true -> encode_positive(float)
    end
  end

  defp encode_positive(float) do
    {digits, n} =
      float
      |> :erlang.float_to_binary([:short])
      |> parse()

    format(digits, byte_size(digits), n)
  end

  # -- Step 2: total parser for Erlang's decimal output ----------------------
  #
  # Accepts any string of the shape [digits].[digits][(e|E)[+|-]digits] and
  # returns {significant_digits, n}. Handles every notation Erlang emits
  # ("4.0", "123.45", "0.001", "1.0e15", "1.2345678e14", "5.0e-324") as well
  # as shapes it currently never emits (no fraction, "E", explicit "+").

  defp parse(string) do
    {mantissa, exp} =
      case :binary.split(string, ["e", "E"]) do
        [mantissa] -> {mantissa, 0}
        [mantissa, exp] -> {mantissa, parse_exponent(exp)}
      end

    {int_part, frac_part} =
      case :binary.split(mantissa, ".") do
        [int_part] -> {int_part, ""}
        [int_part, frac_part] -> {int_part, frac_part}
      end

    digits_and_point(int_part, frac_part, exp)
  end

  defp parse_exponent("+" <> exp), do: String.to_integer(exp)
  defp parse_exponent(exp), do: String.to_integer(exp)

  defp digits_and_point(int_part, frac_part, exp) do
    stripped_int = String.trim_leading(int_part, "0")

    {all_digits, point} =
      if stripped_int == "" do
        # Value < 1: significant digits start inside the fraction. Each
        # leading fractional zero moves the decimal point one further left.
        stripped_frac = String.trim_leading(frac_part, "0")
        leading_zeros = byte_size(frac_part) - byte_size(stripped_frac)
        {stripped_frac, -leading_zeros}
      else
        {stripped_int <> frac_part, byte_size(stripped_int)}
      end

    {String.trim_trailing(all_digits, "0"), point + exp}
  end

  # -- Step 3: ECMA-262 NumberToString steps 6-10 ----------------------------
  #
  # Given s (the digit string), k = byte_size(s), and n such that the value
  # is s * 10^(n - k):

  # Rule 6: k <= n <= 21 — an integer; digits followed by n - k zeros.
  defp format(digits, k, n) when k <= n and n <= 21 do
    digits <> String.duplicate("0", n - k)
  end

  # Rule 7: 0 < n <= 21 (and k > n) — decimal point after the first n digits.
  defp format(digits, k, n) when 0 < n and n <= 21 do
    binary_part(digits, 0, n) <> "." <> binary_part(digits, n, k - n)
  end

  # Rule 8: -6 < n <= 0 — "0." then -n zeros, then the digits.
  defp format(digits, _k, n) when -6 < n and n <= 0 do
    "0." <> String.duplicate("0", -n) <> digits
  end

  # Rule 9: single digit, exponential notation.
  defp format(digits, 1, n) do
    digits <> exponent(n - 1)
  end

  # Rule 10: d.dddde±X exponential notation.
  defp format(<<first, rest::binary>>, _k, n) do
    <<first, ?., rest::binary, exponent(n - 1)::binary>>
  end

  # In rules 9 and 10, n - 1 is never zero: n = 1 is always covered by
  # rule 6 (k = 1) or rule 7 (k > 1).
  defp exponent(exp) when exp > 0, do: "e+" <> Integer.to_string(exp)
  defp exponent(exp), do: "e" <> Integer.to_string(exp)
end
