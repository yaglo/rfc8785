defmodule RFC8785.StringEncoder do
  @moduledoc false

  # String serialization per RFC 8785, Section 3.2.2.2:
  #
  #   * U+0008, U+0009, U+000A, U+000C, U+000D serialize as \b \t \n \f \r
  #   * other characters in U+0000..U+001F serialize as lowercase \u00hh
  #   * U+0022 (") and U+005C (\) serialize as \" and \\
  #   * every remaining I-JSON character — including U+007F and non-ASCII —
  #     is emitted as-is, UTF-8 encoded
  #
  # A validation pass rejects malformed UTF-8 and the 66 Unicode
  # noncharacters excluded by I-JSON. The escaper then slices runs that need
  # no escaping out of the source with binary_part/3 rather than copying
  # them byte-by-byte.

  import Bitwise, only: [band: 2, bxor: 2]

  alias RFC8785.{EncodeError, Unicode}

  @doc """
  Serializes a string as a quoted JSON string literal, returned as iodata.
  Raises `RFC8785.EncodeError` if the binary is not an I-JSON string.
  """
  @spec encode(binary(), EncodeError.path()) :: iolist()
  def encode(string, path) when is_binary(string) do
    validate!(string, path, "string")
    [?", escape(string, string, 0, 0, [], path), ?"]
  end

  @doc """
  Returns the key by which an object name is sorted: its UTF-16 big-endian
  encoding. RFC 8785, Section 3.2.3, requires object names to be sorted by
  their UTF-16 code units; bytewise comparison of UTF-16BE binaries is
  exactly that comparison. Raises `RFC8785.EncodeError` if `name` is not an
  I-JSON string.
  """
  @spec sort_key(binary(), EncodeError.path()) :: binary()
  def sort_key(name, path) do
    validate!(name, path, "object name")

    case :unicode.characters_to_binary(name, :utf8, {:utf16, :big}) do
      key when is_binary(key) ->
        key

      _error_or_incomplete ->
        raise EncodeError,
          reason: :invalid_string,
          message:
            "object name is not valid UTF-8: #{inspect(name)} " <>
              "at #{EncodeError.format_path(path)}"
    end
  end

  defp validate!(string, path, kind) do
    case Unicode.validate(string) do
      :ok ->
        :ok

      {:invalid_utf8, offset} ->
        raise EncodeError,
          reason: :invalid_string,
          message:
            "#{kind} is not valid UTF-8 (invalid byte at offset #{offset}) " <>
              "at #{EncodeError.format_path(path)}"

      {:noncharacter, codepoint, offset} ->
        raise EncodeError,
          reason: :invalid_string,
          message:
            "#{kind} contains Unicode noncharacter " <>
              "#{Unicode.format_codepoint(codepoint)} at byte offset #{offset} " <>
              "at #{EncodeError.format_path(path)}; I-JSON excludes noncharacters"
    end
  end

  # escape(rest, source, run_start, run_length, acc, path)
  #
  # `run_start`/`run_length` delimit the current run of bytes in `source`
  # that can be copied through verbatim. Bytes 0x00-0x7F are always consumed
  # by one of the first three clauses, so the utf8 clause only ever sees
  # lead bytes >= 0x80. The preceding validation pass guarantees that the
  # Erlang utf8 segment matches.

  defp escape(<<>>, source, start, len, acc, _path) do
    flush_run(source, start, len, acc)
  end

  # Advances seven bytes at once when none of them needs escaping, testing
  # all seven in parallel inside one integer. OTP's own :json escaper uses
  # the same technique (stdlib swar_ascii.hrl). Each test clears the high
  # bit of every acceptable byte, so "no high bits set anywhere" means "no
  # byte in this window needs escaping":
  #
  #   1. word &&& 0x80..  is zero            every byte is ASCII (< 0x80)
  #   2. (word + 0x60..) &&& 0x80..          every byte is >= 0x20: adding
  #      is all ones                         0x60 carries into the high bit
  #                                          exactly when the byte is >=
  #                                          0x20, and by (1) no carry
  #                                          crosses a byte boundary
  #   3. ((word ^^^ 0x22..) - 0x01..)        no byte is `"`: the XOR turns a
  #      &&& 0x80.. is zero                  match into 0x00, which borrows
  #                                          on subtract, setting its high bit
  #   4. the same test against 0x5C..        no byte is `\`
  #
  # Every test is conservative: anything unusual leaves a high bit set and
  # falls through to the byte-at-a-time clauses below, so the fast path can
  # only skip bytes that provably need no escaping.
  defp escape(<<word::56, rest::binary>>, source, start, len, acc, path)
       when band(word, 0x80808080808080) === 0 and
              band(word + 0x60606060606060, 0x80808080808080) === 0x80808080808080 and
              band(bxor(word, 0x22222222222222) - 0x01010101010101, 0x80808080808080) === 0 and
              band(bxor(word, 0x5C5C5C5C5C5C5C) - 0x01010101010101, 0x80808080808080) === 0 do
    escape(rest, source, start, len + 7, acc, path)
  end

  defp escape(<<byte, rest::binary>>, source, start, len, acc, path)
       when byte >= 0x20 and byte <= 0x7F and byte != ?" and byte != ?\\ do
    escape(rest, source, start, len + 1, acc, path)
  end

  defp escape(<<byte, rest::binary>>, source, start, len, acc, path)
       when byte < 0x20 or byte == ?" or byte == ?\\ do
    acc = [flush_run(source, start, len, acc), escape_byte(byte)]
    escape(rest, source, start + len + 1, 0, acc, path)
  end

  defp escape(<<_cp::utf8, rest::binary>> = whole, source, start, len, acc, path) do
    char_size = byte_size(whole) - byte_size(rest)
    escape(rest, source, start, len + char_size, acc, path)
  end

  defp escape(_invalid, _source, start, len, _acc, path) do
    raise EncodeError,
      reason: :invalid_string,
      message:
        "string is not valid UTF-8 (invalid byte at offset #{start + len}) " <>
          "at #{EncodeError.format_path(path)}"
  end

  defp flush_run(_source, _start, 0, acc), do: acc
  defp flush_run(source, start, len, acc), do: [acc, binary_part(source, start, len)]

  defp escape_byte(0x08), do: "\\b"
  defp escape_byte(0x09), do: "\\t"
  defp escape_byte(0x0A), do: "\\n"
  defp escape_byte(0x0C), do: "\\f"
  defp escape_byte(0x0D), do: "\\r"
  defp escape_byte(?"), do: "\\\""
  defp escape_byte(?\\), do: "\\\\"

  defp escape_byte(byte) when byte < 0x20 do
    <<"\\u00", Base.encode16(<<byte>>, case: :lower)::binary>>
  end
end
