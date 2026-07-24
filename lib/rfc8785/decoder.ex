defmodule RFC8785.Decoder do
  @moduledoc false

  # JSON text decoding for RFC8785.canonicalize!/1, built on JSON.decode/3
  # (Elixir 1.18+). The callbacks and post-decode validation enforce the
  # parts of the RFC 8785 input contract that JSON.decode!/1 does not:
  #
  #   * null decodes as nil rather than the atom :null
  #   * duplicate object names raise RFC8785.DecodeError; the default
  #     decoder keeps the first pair and drops the rest silently, which a
  #     canonicalizer under signatures must not do
  #   * Unicode noncharacters are rejected from names and string values
  #   * number tokens that decode to IEEE-754 negative zero are rejected
  #   * oversized plain integer tokens are represented lazily during
  #     canonicalization, so rejecting them never converts attacker-sized
  #     bignums back to decimal
  #   * bytes after the document raise unless they are RFC 8259 whitespace

  alias RFC8785.{DecodeError, EncodeError, Unicode}

  defmodule NegativeZero do
    @moduledoc false
    defstruct []
  end

  defmodule OversizeInteger do
    @moduledoc false
    @enforce_keys [:token]
    defstruct [:token]
  end

  @spec decode!(binary()) :: term()
  def decode!(json) when is_binary(json) do
    decode!(json, :materialize_oversize_integers)
  end

  @doc false
  @spec decode_for_canonicalization!(binary()) :: term()
  def decode_for_canonicalization!(json) when is_binary(json) do
    decode!(json, :preserve_oversize_integer_tokens)
  end

  defp decode!(json, oversize_mode) do
    {json, insertions} = expose_normalized_negative_zero_signs(json)

    case JSON.decode(json, :ok, decoders()) do
      {value, :ok, rest} ->
        case skip_whitespace(rest) do
          <<>> ->
            validate_and_transform!(value, [], oversize_mode)

          trailing ->
            raise DecodeError,
              reason: :trailing_data,
              message:
                "unexpected data after the JSON document: " <>
                  inspect(binary_slice(trailing, 0, 16))
        end

      {:error, reason} ->
        {kind, message} = format_error(reason, insertions)
        raise DecodeError, reason: kind, message: message
    end
  end

  defp decoders do
    [
      null: nil,
      float: &decode_float/1,
      integer: &decode_integer/1,
      object_start: fn _acc -> %{} end,
      object_push: fn key, value, object ->
        if is_map_key(object, key) do
          raise DecodeError,
            reason: :duplicate_name,
            message:
              "duplicate object name #{inspect(key)}: RFC 8785 requires I-JSON " <>
                "input, in which object names are unique"
        end

        Map.put(object, key, value)
      end,
      object_finish: fn object, acc -> {object, acc} end
    ]
  end

  defp decode_float(token) do
    float = :erlang.binary_to_float(token)

    case <<float::float-64>> do
      <<1::1, 0::63>> -> %NegativeZero{}
      _other -> float
    end
  end

  # A plain integer with more than 21 magnitude digits is necessarily at
  # least 1e21, where ECMAScript serializes numbers exponentially. Preserve
  # the token instead of constructing a bignum during canonicalization. The
  # public decode API still materializes it below, retaining its established
  # JSON-to-Elixir mapping.
  defp decode_integer(<<"-", digits::binary>> = token) do
    if byte_size(digits) > 21 do
      %OversizeInteger{token: token}
    else
      :erlang.binary_to_integer(token)
    end
  end

  defp decode_integer(token) when byte_size(token) > 21,
    do: %OversizeInteger{token: token}

  defp decode_integer(token), do: :erlang.binary_to_integer(token)

  defp validate_and_transform!(%NegativeZero{}, path, _oversize_mode) do
    raise DecodeError,
      reason: :negative_zero,
      message:
        "number at #{EncodeError.format_path(path)} decodes to IEEE-754 negative zero; " <>
          "RFC 8785 erratum 7920 recommends rejecting negative zero during parsing"
  end

  defp validate_and_transform!(
         %OversizeInteger{} = integer,
         _path,
         :preserve_oversize_integer_tokens
       ),
       do: integer

  defp validate_and_transform!(
         %OversizeInteger{token: token},
         _path,
         :materialize_oversize_integers
       ),
       do: :erlang.binary_to_integer(token)

  defp validate_and_transform!(string, path, _oversize_mode) when is_binary(string) do
    case Unicode.validate(string) do
      :ok ->
        string

      {:noncharacter, codepoint, offset} ->
        raise DecodeError,
          reason: :noncharacter,
          message:
            "string at #{EncodeError.format_path(path)} contains Unicode noncharacter " <>
              "#{Unicode.format_codepoint(codepoint)} at byte offset #{offset}; " <>
              "I-JSON excludes noncharacters"

      # OTP's parser validates UTF-8 before invoking its string callback.
      # Retain a defensive branch in case that contract ever changes.
      {:invalid_utf8, offset} ->
        raise DecodeError,
          reason: :syntax,
          message:
            "string at #{EncodeError.format_path(path)} is not valid UTF-8 " <>
              "(invalid byte at offset #{offset})"
    end
  end

  defp validate_and_transform!(list, path, oversize_mode) when is_list(list) do
    Enum.with_index(list, fn value, index ->
      validate_and_transform!(value, [index | path], oversize_mode)
    end)
  end

  defp validate_and_transform!(map, path, oversize_mode) when is_map(map) do
    Map.new(map, fn {key, value} ->
      key_path = [key | path]
      validate_and_transform!(key, key_path, oversize_mode)
      {key, validate_and_transform!(value, key_path, oversize_mode)}
    end)
  end

  defp validate_and_transform!(value, _path, _oversize_mode), do: value

  # OTP normalizes the integer token "-0" to "0" before
  # invoking the integer callback, and similarly turns "-0e0" into
  # "0.0e0" before invoking the float callback. Insert a fractional part into
  # precisely those value tokens so the float callback sees the sign. This
  # funnels every negative-zero spelling through the same sentinel and lets
  # the post-decode walk report its exact JSONPath. Fractional negative zero
  # and non-zero values that underflow retain their sign without rewriting.
  defp expose_normalized_negative_zero_signs(json) do
    case find_negative_zero_insertions(json, 0, true, []) do
      [] -> {json, []}
      reversed -> {insert_fractional_zeroes(json, Enum.reverse(reversed), 0, []), reversed}
    end
  end

  defp find_negative_zero_insertions(<<>>, _offset, _can_start_value, acc), do: acc

  defp find_negative_zero_insertions(
         <<byte, rest::binary>>,
         offset,
         can_start_value,
         acc
       )
       when byte in [?\s, ?\t, ?\n, ?\r] do
    find_negative_zero_insertions(rest, offset + 1, can_start_value, acc)
  end

  defp find_negative_zero_insertions(<<?", rest::binary>>, offset, _can_start_value, acc),
    do: find_after_string(rest, offset + 1, acc)

  defp find_negative_zero_insertions(<<"-0", rest::binary>>, offset, true, acc) do
    acc =
      if needs_fractional_zero?(rest) do
        [offset + 2 | acc]
      else
        acc
      end

    find_negative_zero_insertions(rest, offset + 2, false, acc)
  end

  defp find_negative_zero_insertions(<<byte, rest::binary>>, offset, _can_start_value, acc) do
    can_start_value = byte in [?[, ?{, ?,, ?:]
    find_negative_zero_insertions(rest, offset + 1, can_start_value, acc)
  end

  defp find_after_string(<<>>, _offset, acc), do: acc

  defp find_after_string(<<?\\, _escaped, rest::binary>>, offset, acc),
    do: find_after_string(rest, offset + 2, acc)

  defp find_after_string(<<?", rest::binary>>, offset, acc),
    do: find_negative_zero_insertions(rest, offset + 1, false, acc)

  defp find_after_string(<<_byte, rest::binary>>, offset, acc),
    do: find_after_string(rest, offset + 1, acc)

  defp needs_fractional_zero?(<<>>), do: true

  defp needs_fractional_zero?(<<byte, _rest::binary>>)
       when byte in [?\s, ?\t, ?\n, ?\r, ?,, ?], ?}, ?e, ?E],
       do: true

  defp needs_fractional_zero?(_rest), do: false

  defp insert_fractional_zeroes(json, [], start, acc) do
    IO.iodata_to_binary([acc, binary_part(json, start, byte_size(json) - start)])
  end

  defp insert_fractional_zeroes(json, [offset | rest], start, acc) do
    part = binary_part(json, start, offset - start)
    insert_fractional_zeroes(json, rest, offset, [acc, part, ".0"])
  end

  defp skip_whitespace(<<byte, rest::binary>>) when byte in [?\s, ?\t, ?\n, ?\r],
    do: skip_whitespace(rest)

  defp skip_whitespace(rest), do: rest

  # `JSON.decode_error_reason/0` is exhaustive, so no catch-all clause is
  # needed here; dialyzer flags this function if the type ever widens.
  #
  # JSON reports :unexpected_end both for truncated documents and for escape
  # sequences cut short near the end of the input, such as a lone "\uD800"
  # whose low-surrogate lookahead runs past the binary.
  @spec format_error(JSON.decode_error_reason(), [pos_integer()]) ::
          {DecodeError.reason(), String.t()}
  defp format_error({:unexpected_end, offset}, insertions),
    do:
      {:unexpected_end,
       "unexpected end of input at byte offset #{source_offset(offset, insertions)}: " <>
         "truncated JSON or incomplete escape sequence"}

  defp format_error({:invalid_byte, offset, byte}, insertions),
    do:
      {:syntax,
       "invalid byte 0x#{hex2(byte)} at byte offset " <>
         "#{source_offset(offset, insertions)} in JSON input"}

  # The parser normalizes a number token before float conversion, so on
  # overflow the reported sequence ("1.0e400") differs from the input text
  # ("1e400"); the message must not present it as a literal quote of the
  # input. A \u token with valid hex digits can only fail as a surrogate
  # problem; one with invalid digits is a plain bad escape.
  defp format_error({:unexpected_sequence, offset, bytes}, insertions) do
    sequence = "#{describe_sequence(bytes)} at byte offset #{source_offset(offset, insertions)}"

    cond do
      bytes =~ ~r/\A-?\d+(\.\d+)?([eE][+-]?\d+)?\z/ ->
        {:number_out_of_range, "number token #{sequence} is outside the IEEE-754 double range"}

      bytes =~ ~r/\A(\\u[0-9a-fA-F]{4})+\z/ ->
        {:unpaired_surrogate, "unpaired surrogate in escape sequence #{sequence}"}

      String.contains?(bytes, "\\u") ->
        {:syntax, "invalid \\u escape sequence #{sequence}"}

      true ->
        {:syntax, "cannot decode sequence #{sequence}"}
    end
  end

  # JSON.decode/3 reports offsets into the rewritten text, so subtract the
  # two bytes each preceding ".0" insertion added.
  defp source_offset(offset, []), do: offset

  defp source_offset(offset, insertions) do
    shift =
      insertions
      |> Enum.reverse()
      |> Enum.reduce_while(0, fn insertion, shift ->
        if insertion + shift + 2 <= offset, do: {:cont, shift + 2}, else: {:halt, shift}
      end)

    offset - shift
  end

  @error_sequence_preview_bytes 80

  defp describe_sequence(bytes) when byte_size(bytes) <= @error_sequence_preview_bytes,
    do: inspect(bytes)

  defp describe_sequence(bytes) do
    prefix = binary_part(bytes, 0, @error_sequence_preview_bytes)
    "#{inspect(prefix)}... (#{byte_size(bytes)} bytes total)"
  end

  defp hex2(byte), do: Base.encode16(<<byte>>, case: :lower)
end
