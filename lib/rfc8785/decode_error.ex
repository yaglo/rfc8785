defmodule RFC8785.DecodeError do
  @moduledoc """
  Raised by `RFC8785.canonicalize!/1` and `RFC8785.decode!/1` when a JSON
  text is invalid or unsafe to use as JCS input.

  Reasons a text is rejected:

    * a syntax error or invalid byte, reported by OTP's `:json` parser
    * truncated input
    * data after the end of the document, other than whitespace
    * a fraction- or exponent-form number outside the IEEE-754 double
      range, such as `1e400`
    * an unpaired surrogate in a `\\u` escape sequence
    * a Unicode noncharacter in a string or object name
    * a duplicate object name, which RFC 8785 forbids via its I-JSON
      (RFC 7493) input requirement and which `:json.decode/1` alone would
      silently drop
    * a number token that decodes to IEEE-754 negative zero, rejected
      following RFC 8785 erratum 7920

  `:reason` is a stable atom, so callers can branch on the cause without
  parsing prose; `:message` explains it.
  """

  defexception [:reason, :message]

  @typedoc """
  Why the text was rejected:

    * `:syntax` — a syntax error or invalid byte
    * `:unexpected_end` — truncated input, or an escape cut short
    * `:trailing_data` — non-whitespace after the document
    * `:number_out_of_range` — a number literal outside the IEEE-754 double
      range, such as `1e400`
    * `:unpaired_surrogate` — an unpaired surrogate in a `\\u` escape
    * `:noncharacter` — a Unicode noncharacter, which I-JSON excludes
    * `:duplicate_name` — a duplicate object name, which I-JSON forbids
    * `:negative_zero` — a number token decoding to IEEE-754 negative zero,
      rejected per RFC 8785 erratum 7920
  """
  @type reason ::
          :syntax
          | :unexpected_end
          | :trailing_data
          | :number_out_of_range
          | :unpaired_surrogate
          | :noncharacter
          | :duplicate_name
          | :negative_zero

  @type t :: %__MODULE__{reason: reason(), message: String.t()}
end
