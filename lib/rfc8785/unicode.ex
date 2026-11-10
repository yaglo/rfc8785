defmodule RFC8785.Unicode do
  @moduledoc false

  # RFC 7493, Section 2.1, excludes both surrogate code points and Unicode
  # noncharacters from I-JSON strings. Surrogates cannot occur in valid UTF-8,
  # so a single pass can enforce the complete scalar-value requirement.

  @type validation ::
          :ok
          | {:invalid_utf8, byte_offset :: non_neg_integer()}
          | {:noncharacter, codepoint :: non_neg_integer(), byte_offset :: non_neg_integer()}

  @spec validate(binary()) :: validation()
  def validate(string) when is_binary(string), do: validate(string, 0)

  @typedoc """
  `:bmp` when every code point is at most U+FFFF, `:supplementary` when at
  least one lies above it (a four-byte UTF-8 sequence, a surrogate pair in
  UTF-16).
  """
  @type plane :: :bmp | :supplementary

  @doc """
  Validates like `validate/1` and, in the same pass, reports whether the
  string contains a code point above U+FFFF.
  """
  @spec validate_and_classify(binary()) ::
          {:ok, plane()}
          | {:invalid_utf8, byte_offset :: non_neg_integer()}
          | {:noncharacter, codepoint :: non_neg_integer(), byte_offset :: non_neg_integer()}
  def validate_and_classify(string) when is_binary(string), do: classify(string, 0, :bmp)

  @spec format_codepoint(non_neg_integer()) :: String.t()
  def format_codepoint(codepoint) do
    hex =
      codepoint
      |> Integer.to_string(16)
      |> String.upcase()
      |> String.pad_leading(4, "0")

    "U+" <> hex
  end

  defp validate(<<>>, _offset), do: :ok

  defp validate(<<codepoint::utf8, rest::binary>> = whole, offset) do
    if noncharacter?(codepoint) do
      {:noncharacter, codepoint, offset}
    else
      width = byte_size(whole) - byte_size(rest)
      validate(rest, offset + width)
    end
  end

  defp validate(_invalid, offset), do: {:invalid_utf8, offset}

  defp classify(<<>>, _offset, plane), do: {:ok, plane}

  defp classify(<<codepoint::utf8, rest::binary>> = whole, offset, plane) do
    if noncharacter?(codepoint) do
      {:noncharacter, codepoint, offset}
    else
      plane = if codepoint > 0xFFFF, do: :supplementary, else: plane
      classify(rest, offset + byte_size(whole) - byte_size(rest), plane)
    end
  end

  defp classify(_invalid, offset, _plane), do: {:invalid_utf8, offset}

  # The permanently reserved range U+FDD0..U+FDEF plus the final two code
  # points of every Unicode plane, U+?FFFE and U+?FFFF (17 planes).
  defp noncharacter?(codepoint) when codepoint in 0xFDD0..0xFDEF, do: true
  defp noncharacter?(codepoint) when rem(codepoint, 0x10000) in [0xFFFE, 0xFFFF], do: true
  defp noncharacter?(_codepoint), do: false
end
