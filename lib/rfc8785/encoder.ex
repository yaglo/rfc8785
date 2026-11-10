defmodule RFC8785.Encoder do
  @moduledoc false

  # Canonical serialization per RFC 8785, Section 3.2. Emits iodata; no
  # whitespace is ever produced (Section 3.2.1). The `path` argument is the
  # reversed location of the current value inside the input term, used only
  # for error messages.

  alias RFC8785.Decoder.OversizeInteger
  alias RFC8785.{EncodeError, Number, StringEncoder}

  @spec encode(term(), EncodeError.path()) :: iodata()
  def encode(value, path)

  def encode(nil, _path), do: "null"
  def encode(true, _path), do: "true"
  def encode(false, _path), do: "false"

  def encode(value, path) when is_integer(value), do: Number.encode_integer(value, path)
  def encode(value, _path) when is_float(value), do: Number.encode_float(value)
  def encode(value, path) when is_binary(value), do: StringEncoder.encode(value, path)

  # Decoder keeps attacker-sized plain integer tokens lazy while
  # canonicalizing. No token with more than 21 magnitude digits can preserve
  # its plain form: finite doubles at that magnitude use exponential notation,
  # and still larger values overflow. Reject it without ever constructing or
  # decimalizing a bignum.
  def encode(%OversizeInteger{}, path) do
    raise EncodeError,
      reason: :integer_unrepresentable,
      message:
        "cannot canonicalize integer token at #{EncodeError.format_path(path)}: " <>
          "its magnitude is at least 1e21. Finite IEEE-754 doubles at this " <>
          "magnitude use exponential notation, while still larger values " <>
          "are outside the double range, so none can preserve the token's " <>
          "plain decimal digits (interoperable integers stay within ±2^53). " <>
          "Encode it as a string."
  end

  # Bare atoms other than nil/true/false (matched above) encode as their
  # name string. In particular, :null encodes as "null", unlike OTP's
  # :json encoder; this deliberate mapping is documented in RFC8785's
  # public API.
  def encode(value, path) when is_atom(value),
    do: StringEncoder.encode(Atom.to_string(value), path)

  def encode(value, path) when is_list(value), do: [?[, elements(value, 0, path), ?]]

  def encode(value, path) when is_struct(value) do
    raise EncodeError,
      reason: :unsupported_term,
      message:
        "cannot encode struct #{inspect(value.__struct__)} " <>
          "at #{EncodeError.format_path(path)}. RFC 8785 canonicalization is " <>
          "defined only for plain JSON data; convert the struct to a plain map " <>
          "(and its values to JSON types) before encoding."
  end

  def encode(value, path) when is_map(value), do: encode_object(value, path)

  def encode(value, path) do
    raise EncodeError,
      reason: :unsupported_term,
      message:
        "cannot encode #{inspect(value)} at #{EncodeError.format_path(path)}: " <>
          "not a JSON-representable term"
  end

  # -- Arrays ----------------------------------------------------------------

  defp elements([], _index, _path), do: []

  defp elements([head | tail], index, path) do
    encoded = encode(head, [index | path])

    case tail do
      [] ->
        [encoded]

      tail when is_list(tail) ->
        [encoded, ?, | elements(tail, index + 1, path)]

      _improper ->
        raise EncodeError,
          reason: :improper_list,
          message: "cannot encode improper list at #{EncodeError.format_path(path)}"
    end
  end

  # -- Objects ---------------------------------------------------------------
  #
  # RFC 8785, Section 3.2.3: object names sort by their UTF-16 code units.
  # Each name is validated exactly once. When every name in the object lies
  # within the BMP, UTF-16 code-unit order equals bytewise order of the
  # UTF-8 binaries, so the names are sorted as they are; only an object with
  # a name above U+FFFF pays for UTF-16BE sort keys (see
  # StringEncoder.utf16_sort_key/1). RFC 8785 requires I-JSON (RFC 7493)
  # input, in which object names are unique, so duplicates produced by key
  # coercion (an atom key and a string key with the same name) are rejected.

  defp encode_object(map, path) do
    {entries, plane} =
      map
      |> Map.to_list()
      |> Enum.map_reduce(:bmp, fn {key, value}, plane ->
        name = coerce_name(key, path)

        case StringEncoder.validate_name!(name, [name | path]) do
          :bmp -> {{name, value}, plane}
          :supplementary -> {{name, value}, :supplementary}
        end
      end)

    entries = sort_entries(entries, plane)
    assert_unique_names(entries, path)

    inner =
      entries
      |> Enum.map(fn {name, value} ->
        [StringEncoder.encode_validated(name, path), ?: | encode(value, [name | path])]
      end)
      |> Enum.intersperse(?,)

    [?{, inner, ?}]
  end

  defp sort_entries(entries, :bmp), do: List.keysort(entries, 0)

  defp sort_entries(entries, :supplementary) do
    entries
    |> Enum.map(fn {name, value} -> {StringEncoder.utf16_sort_key(name), name, value} end)
    |> List.keysort(0)
    |> Enum.map(fn {_sort_key, name, value} -> {name, value} end)
  end

  defp coerce_name(key, _path) when is_binary(key), do: key
  defp coerce_name(key, _path) when is_atom(key), do: Atom.to_string(key)

  defp coerce_name(key, path) do
    raise EncodeError,
      reason: :invalid_key,
      message:
        "invalid object key #{inspect(key)} at #{EncodeError.format_path(path)}: " <>
          "only strings and atoms may be used as object names"
  end

  defp assert_unique_names([{name, _value} | rest], path) do
    check_adjacent(rest, name, path)
  end

  defp assert_unique_names([], _path), do: :ok

  defp check_adjacent([], _previous, _path), do: :ok

  defp check_adjacent([{name, _value} | rest], previous, path) do
    if name == previous do
      raise EncodeError,
        reason: :duplicate_name,
        message:
          "duplicate object name #{inspect(name)} after key coercion " <>
            "at #{EncodeError.format_path(path)}: RFC 8785 requires I-JSON input, " <>
            "in which object names are unique"
    end

    check_adjacent(rest, name, path)
  end
end
