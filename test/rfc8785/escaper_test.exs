defmodule RFC8785.EscaperTest do
  use ExUnit.Case, async: true

  alias RFC8785.StringEncoder

  # The escaper advances seven bytes at a time when none of them needs
  # escaping (see StringEncoder). That fast path must agree with a
  # byte-at-a-time reference over every window that straddles an escaping
  # boundary — the values around 0x20, the quote and backslash, 0x7F, and
  # UTF-8 lead bytes — at every offset within the seven-byte window.

  @boundary_bytes [
    0x00,
    0x01,
    0x08,
    0x0A,
    0x1F,
    0x20,
    0x21,
    0x22,
    0x23,
    0x5B,
    0x5C,
    0x5D,
    0x7E,
    0x7F
  ]

  defp reference_escape(string) do
    escaped =
      string
      |> :binary.bin_to_list()
      |> Enum.map_join(fn
        0x08 -> "\\b"
        0x09 -> "\\t"
        0x0A -> "\\n"
        0x0C -> "\\f"
        0x0D -> "\\r"
        ?" -> "\\\""
        ?\\ -> "\\\\"
        byte when byte < 0x20 -> "\\u00" <> hex2(byte)
        byte -> <<byte>>
      end)

    "\"" <> escaped <> "\""
  end

  defp hex2(byte) do
    byte |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(2, "0")
  end

  test "the seven-byte fast path agrees with a byte-at-a-time reference" do
    plain = ~c"abcdefghij"

    windows =
      for a <- @boundary_bytes,
          b <- @boundary_bytes,
          offset <- 0..8 do
        prefix = Enum.take(plain, offset)
        List.to_string(prefix) <> <<a, b>> <> "xyz" <> <<a>>
      end

    mismatches =
      for window <- windows,
          String.valid?(window),
          reduce: [] do
        acc ->
          actual = window |> StringEncoder.encode([]) |> IO.iodata_to_binary()
          if actual == reference_escape(window), do: acc, else: [window | acc]
      end

    assert mismatches == []
  end

  test "runs of exactly seven plain bytes escape correctly at every boundary" do
    # Seven is the fast-path window; six and eight exercise the transition
    # into and out of it.
    for length <- 0..20 do
      plain = String.duplicate("a", length)

      for suffix <- [~S("), "\\", <<0x00>>, <<0x1F>>, "é", ""] do
        string = plain <> suffix
        actual = string |> StringEncoder.encode([]) |> IO.iodata_to_binary()

        expected =
          if String.valid?(suffix) and suffix not in [<<0x00>>, <<0x1F>>] and
               suffix in [~S("), "\\", "é", ""] do
            reference_escape_utf8(string)
          else
            reference_escape(string)
          end

        assert actual == expected, "length #{length}, suffix #{inspect(suffix)}"
      end
    end
  end

  # Non-ASCII passes through unescaped, so the reference must not treat its
  # bytes individually.
  defp reference_escape_utf8(string) do
    escaped =
      string
      |> String.to_charlist()
      |> Enum.map_join(fn
        0x08 -> "\\b"
        0x09 -> "\\t"
        0x0A -> "\\n"
        0x0C -> "\\f"
        0x0D -> "\\r"
        ?" -> "\\\""
        ?\\ -> "\\\\"
        codepoint when codepoint < 0x20 -> "\\u00" <> hex2(codepoint)
        codepoint -> <<codepoint::utf8>>
      end)

    "\"" <> escaped <> "\""
  end
end
