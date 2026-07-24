defmodule RFC8785.PropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Bitwise

  @two_pow_53 9_007_199_254_740_992

  # String generator biased toward the escaping range. string(:utf8) alone
  # almost never produces C0 controls, quotes, or backslashes, which lets
  # escaping properties pass without exercising the escaper.
  defp json_string do
    escapey =
      [integer(0x00..0x1F), constant(?"), constant(?\\), integer(0x20..0x7E)]
      |> one_of()
      |> list_of(max_length: 12)
      |> map(&List.to_string/1)

    unicode =
      string(:utf8)
      |> filter(&i_json_string?/1)

    one_of([unicode, escapey])
  end

  # Float generator covering both notation-boundary regions: the small
  # magnitudes around 1e-7..1e-3 (plain/exponential switch at n = -6) and
  # the large integral region up to the n = 21 switch.
  defp json_float do
    one_of([
      float(),
      float(min: -1.0e-3, max: 1.0e-3),
      float(min: 9.0e15, max: 1.0e21),
      float(min: -1.0e21, max: -9.0e15)
    ])
  end

  defp json_term do
    scalar =
      one_of([
        constant(nil),
        boolean(),
        integer(-@two_pow_53..@two_pow_53),
        json_float(),
        json_string()
      ])

    tree(scalar, fn child ->
      one_of([
        list_of(child, max_length: 8),
        map_of(json_string(), child, max_length: 8)
      ])
    end)
  end

  property "canonical output parses back to an equivalent term" do
    check all(term <- json_term(), max_runs: 300) do
      json = RFC8785.encode!(term)
      assert equivalent?(term, json_decode!(json))
    end
  end

  property "canonicalization is idempotent" do
    check all(term <- json_term(), max_runs: 300) do
      json = RFC8785.encode!(term)
      assert RFC8785.encode!(json_decode!(json)) == json
    end
  end

  property "output is always valid UTF-8" do
    check all(term <- json_term(), max_runs: 300) do
      assert String.valid?(RFC8785.encode!(term))
    end
  end

  property "output has no whitespace outside strings and only lowercase hex escapes" do
    check all(term <- json_term(), max_runs: 300) do
      assert_lexically_canonical(RFC8785.encode!(term))
    end
  end

  property "encode/1 on arbitrary binaries either succeeds or returns EncodeError" do
    # encode/1 rescues only RFC8785.EncodeError, so any other exception
    # (e.g. a leaked UnicodeConversionError) escapes and fails this test.
    check all(bytes <- binary(max_length: 64), max_runs: 500) do
      case RFC8785.encode(bytes) do
        {:ok, json} -> assert String.valid?(json)
        {:error, error} -> assert %RFC8785.EncodeError{} = error
      end
    end
  end

  property "canonicalize/1 on arbitrary binaries returns ok, DecodeError, or EncodeError" do
    # canonicalize/1 rescues only [DecodeError, EncodeError]; anything else
    # :json raises (or a MatchError from Decoder's pattern) escapes and
    # fails this test. Half the samples are mutated near-JSON so the parser
    # gets past the first byte.
    near_json =
      map({member_of(["{", "[1,", ~S({"a":1}), "1e", ~S("\ud8)]), binary(max_length: 8)}, fn
        {prefix, noise} -> prefix <> noise
      end)

    check all(input <- one_of([binary(max_length: 64), near_json]), max_runs: 500) do
      case RFC8785.canonicalize(input) do
        {:ok, json} -> assert String.valid?(json)
        {:error, %RFC8785.DecodeError{}} -> :ok
        {:error, %RFC8785.EncodeError{}} -> :ok
      end
    end
  end

  property "object names sort by an independently computed UTF-16 code-unit order" do
    check all(keys <- uniq_list_of(json_string(), max_length: 12), max_runs: 300) do
      map = keys |> Enum.with_index() |> Map.new()

      expected =
        "{" <>
          Enum.map_join(Enum.sort_by(keys, &utf16_code_units/1), ",", fn key ->
            RFC8785.encode!(key) <> ":" <> Integer.to_string(Map.fetch!(map, key))
          end) <> "}"

      assert RFC8785.encode!(map) == expected
    end
  end

  property "integral canonical output re-canonicalizes after integer decode" do
    # Regression for the bignum-conversion defect: floats in (2^53, 1e21)
    # often canonicalize to integral digit strings that JSON decoders parse
    # as integers wider than 64 bits; re-encoding those must reproduce the
    # same bytes.
    check all(
            float <-
              one_of([
                float(min: 9.0e15, max: 1.0e21),
                float(min: -1.0e21, max: -9.0e15)
              ]),
            max_runs: 500
          ) do
      json = RFC8785.encode!(float)

      unless String.contains?(json, [".", "e"]) do
        assert RFC8785.encode!(String.to_integer(json)) == json
      end
    end
  end

  property "large-integer acceptance agrees with a correctly rounded strtod oracle" do
    # Cross-validates the hand-rolled nearest-double conversion against the
    # platform's decimal parser (:erlang.binary_to_float, which is correctly
    # rounded): an integer is accepted exactly when the canonical form of
    # its nearest double reproduces its digits.
    check all(
            magnitude <-
              integer((@two_pow_53 + 1)..10_000_000_000_000_000_000_000_000),
            sign <- member_of([1, -1]),
            max_runs: 500
          ) do
      int = sign * magnitude
      digits = Integer.to_string(int)

      oracle_accepts =
        try do
          RFC8785.encode!(:erlang.binary_to_float(digits <> ".0")) == digits
        rescue
          ArgumentError -> false
        end

      case RFC8785.encode(int) do
        {:ok, json} ->
          assert oracle_accepts
          assert json == digits

        {:error, %RFC8785.EncodeError{}} ->
          refute oracle_accepts
      end
    end
  end

  # Decodes with OTP's :json using only the null-to-nil mapping, keeping
  # the parser independent of RFC8785.Decoder's custom object handling.
  # Canonical output never has trailing bytes.
  defp json_decode!(json) do
    {value, :ok, ""} = :json.decode(json, :ok, %{null: nil})
    value
  end

  # Numeric equivalence is defined by the canonical form itself: 100.0 and
  # 100 are the same JSON value, as are a float and the bignum parsed from
  # its integral canonical output. Comparing via 1.0 * int would reintroduce
  # BEAM's incorrectly rounded bignum conversion into the test.
  defp equivalent?(a, b) when is_number(a) and is_number(b) do
    RFC8785.encode!(a) == RFC8785.encode!(b)
  end

  defp equivalent?(a, b) when is_list(a) and is_list(b) do
    length(a) == length(b) and
      Enum.zip(a, b) |> Enum.all?(fn {x, y} -> equivalent?(x, y) end)
  end

  defp equivalent?(a, b) when is_map(a) and is_map(b) do
    Map.keys(a) |> Enum.sort() == Map.keys(b) |> Enum.sort() and
      Enum.all?(a, fn {k, v} -> equivalent?(v, Map.fetch!(b, k)) end)
  end

  defp equivalent?(a, b), do: a === b

  defp i_json_string?(string) do
    string
    |> String.to_charlist()
    |> Enum.all?(fn cp ->
      cp not in 0xFDD0..0xFDEF and
        (cp &&& 0xFFFF) not in [0xFFFE, 0xFFFF]
    end)
  end

  # Independent UTF-16 oracle: expand codepoints to code units with the
  # surrogate-pair formula and rely on Erlang's lexicographic list
  # comparison. The implementation under test uses UTF-16BE binaries
  # instead, so agreement is meaningful.
  defp utf16_code_units(string) do
    string
    |> String.to_charlist()
    |> Enum.flat_map(fn cp ->
      if cp < 0x10000 do
        [cp]
      else
        n = cp - 0x10000
        [0xD800 + (n >>> 10), 0xDC00 + (n &&& 0x3FF)]
      end
    end)
  end

  # Lexical scan of canonical output: a two-state machine over bytes.
  # Outside strings no whitespace may appear; inside strings \u escapes
  # must use lowercase hex.
  defp assert_lexically_canonical(json), do: scan(json, false)

  defp scan(<<>>, false), do: :ok

  defp scan(<<?", rest::binary>>, false), do: scan(rest, true)

  defp scan(<<byte, rest::binary>>, false) do
    refute byte in [?\s, ?\t, ?\n, ?\r], "whitespace outside a string literal"
    scan(rest, false)
  end

  defp scan(<<?\\, ?u, hex::binary-size(4), rest::binary>>, true) do
    for <<digit <- hex>> do
      assert digit in ?0..?9 or digit in ?a..?f,
             "uppercase or invalid hex digit in \\u escape: #{<<digit>>}"
    end

    scan(rest, true)
  end

  defp scan(<<?\\, _escaped, rest::binary>>, true), do: scan(rest, true)
  defp scan(<<?", rest::binary>>, true), do: scan(rest, false)
  defp scan(<<_byte, rest::binary>>, true), do: scan(rest, true)
end
