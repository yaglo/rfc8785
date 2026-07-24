defmodule RFC8785.EncodeError do
  @moduledoc """
  Raised when a term cannot be canonicalized per RFC 8785.

  The message includes a JSONPath-style location (for example `$.foo[3].bar`)
  pointing at the offending value inside the input term.

  `:reason` is a stable atom, so callers can branch on the cause without
  parsing prose; `:message` explains it and names the location.

      case RFC8785.encode(term) do
        {:ok, json} -> json
        {:error, %RFC8785.EncodeError{reason: :integer_unrepresentable}} -> retry_as_string(term)
        {:error, error} -> {:rejected, error.message}
      end
  """

  defexception [:reason, :message]

  @typedoc """
  Why the term was rejected:

    * `:integer_unrepresentable` — an integer beyond `±2^53` whose decimal
      digits are not preserved by serialization through its nearest
      IEEE-754 double, or which is outside the double range entirely
    * `:duplicate_name` — a duplicate object name, as in
      `%{:a => 1, "a" => 2}` after the atom key is converted to a string
    * `:invalid_key` — an object key that is neither a string nor an atom
    * `:invalid_string` — a binary that is not valid UTF-8 or contains a
      Unicode noncharacter
    * `:unsupported_term` — a struct, tuple, or any other term with no JSON
      representation
    * `:improper_list`
  """
  @type reason ::
          :integer_unrepresentable
          | :duplicate_name
          | :invalid_key
          | :invalid_string
          | :unsupported_term
          | :improper_list

  @type t :: %__MODULE__{reason: reason(), message: String.t()}

  # Location of a value inside the input term, innermost segment first.
  # Integer segments are array indexes; binary segments are object names.
  # Shared by the encoder modules' specs; not part of the public API.
  @typedoc false
  @type path :: [non_neg_integer() | String.t()]

  @doc false
  @spec format_path(path()) :: String.t()
  def format_path(reversed_path) do
    reversed_path
    |> Enum.reverse()
    |> Enum.map_join(fn
      index when is_integer(index) -> "[#{index}]"
      name when is_binary(name) -> format_name(name)
    end)
    |> then(&("$" <> &1))
  end

  # \A/\z anchors, not ^/$: $ also matches before a trailing newline, which
  # would render a name like "tail\n" as an identifier and embed a raw
  # control character in the exception message.
  defp format_name(name) do
    if name =~ ~r/\A[A-Za-z_][A-Za-z0-9_]*\z/ do
      "." <> name
    else
      "[" <> inspect(name) <> "]"
    end
  end
end
