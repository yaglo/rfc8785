defmodule RFC8785 do
  @moduledoc """
  A pure Elixir implementation of [RFC 8785: JSON Canonicalization Scheme
  (JCS)](https://www.rfc-editor.org/rfc/rfc8785).

  JCS assigns every I-JSON-compatible value a single canonical byte
  representation, so logically equivalent valid inputs hash and sign
  identically. Schemes that sign JSON by value depend on this property,
  among them the JCS cryptosuites of W3C Data Integrity
  (`eddsa-jcs-2022`, `ecdsa-jcs-2019`).

      iex> RFC8785.encode!(%{"b" => 100.0, "a" => "hello\\tworld"})
      ~S({"a":"hello\\tworld","b":100})

      iex> RFC8785.encode!(%{"numbers" => [1.0e21, 1.0e-7, 0.000001]})
      ~S({"numbers":[1e+21,1e-7,0.000001]})

  ## Canonical form

  Output follows RFC 8785, Section 3.2:

    * Numbers serialize exactly as ECMAScript's `Number::toString`
      (Section 3.2.2.3). The shortest round-tripping digits come from
      Erlang/OTP's Ryu implementation; the ECMA-262 `NumberToString` rules
      determine the notation.
    * Strings use the escapes `\\b`, `\\t`, `\\n`, `\\f`, `\\r`, lowercase
      `\\u00hh` for the remaining C0 controls, `\\"`, and `\\\\`
      (Section 3.2.2.2). All other permitted code points, including U+007F
      and non-ASCII, appear unescaped in UTF-8. Unicode noncharacters are
      rejected as required by I-JSON.
    * Object names sort by UTF-16 code units (Section 3.2.3), which orders
      names containing surrogate pairs correctly.
    * The output contains no whitespace (Section 3.2.1).

  ## Input mapping

  | Elixir term                  | JSON                                    |
  | ---------------------------- | --------------------------------------- |
  | `nil` / `true` / `false`     | `null` / `true` / `false`               |
  | integer                      | number (see below)                      |
  | float                        | number (ECMAScript shortest form)       |
  | binary (valid I-JSON string) | string                                  |
  | other atom                   | string (`Atom.to_string/1`)             |
  | list                         | array                                   |
  | map (string or atom keys)    | object, names sorted per the RFC        |

  ### Atoms

  Atoms other than `nil`, `true`, and `false` encode as their name string.
  Note the consequence for `:null`: OTP's `:json.decode/1` yields that atom
  for JSON `null` by default, and it encodes here as the string `"null"` —
  not the `null` literal. Decode with `decode!/1` (or any decoder that maps
  `null` to `nil`) before re-encoding.

  ### Integers

  RFC 8785 represents every number as an IEEE-754 double. Integers within
  `±2^53` serialize as their exact digits, which is identical to their
  serialization through a double. A larger integer is accepted only when
  the canonical form of its nearest double reproduces the integer's
  decimal digits. Integers parsed from canonical JCS output always satisfy
  this, so decoding a canonical document and re-canonicalizing it
  reproduces the same bytes. An integer that fails the check, such as
  `9007199254740993` (nearest double: `9007199254740992`), raises
  `RFC8785.EncodeError`; convert it to a float first if the altered digits
  are acceptable, or encode it as a string to keep them.

  ### Rejected input

  Structs, tuples, non-UTF-8 binaries, strings containing Unicode
  noncharacters, map keys that are neither strings nor atoms, improper
  lists, and maps whose keys collide after atom-to-string coercion raise
  `RFC8785.EncodeError`. The error message names the offending value's
  location in JSONPath style, such as `$.credential.amounts[3]`.

  `NaN` and `Infinity` need no handling: Erlang floats cannot represent
  them.

  ## JSON text input

  `canonicalize!/1` accepts a JSON text instead of Elixir terms, as when
  verifying a hash or signature over a received document. It decodes with
  OTP's `:json` parser and enforces I-JSON on the way in: duplicate object
  names and Unicode noncharacters raise `RFC8785.DecodeError` rather than
  being silently accepted or altered. Number tokens that decode to
  IEEE-754 negative zero are also rejected, following RFC 8785 erratum
  7920. A programmatically supplied `-0.0` float still encodes as `0`, as
  required by ECMAScript `Number::toString`.

  Number tokens with a fraction or exponent are decoded to IEEE-754
  doubles, as required by RFC 8785. Canonicalization preserves their
  numeric double value rather than their original spelling or every
  decimal digit.

      iex> RFC8785.canonicalize!(~S({"b": 2.50, "a": "\\u20ac"}))
      ~S({"a":"€","b":2.5})

  When the document must be modified between parsing and canonicalizing —
  the W3C Data Integrity JCS cryptosuites, for instance, remove the `proof`
  member before hashing the rest — decode with `decode!/1`, which applies
  the same parser-side strictness, and re-encode the modified terms:

      iex> doc = RFC8785.decode!(~S({"claim": null, "proof": {"v": "..."}}))
      iex> doc |> Map.delete("proof") |> RFC8785.encode!()
      ~S({"claim":null})

  A parser is a safe substitute here only if its term mapping and
  validation preserve the same data. OTP's `:json.decode/1`, for example,
  yields the atom `:null` for JSON `null`, which `encode!/1` then encodes
  as the *string* `"null"`; it also silently keeps the first of two
  duplicate object names. Successful decoding does not guarantee that the
  resulting term can be encoded: `encode!/1` still applies term-side checks
  such as the digit-preserving integer rule.

  ## Resource limits

  When canonicalizing JSON text, an integer token with more than 21
  magnitude digits is rejected before constructing a bignum, because it
  cannot preserve those integer digits in canonical JCS output.
  `decode!/1` remains a general decoding API and does materialize such
  tokens as arbitrary-precision integers.

  The library does not impose an overall document byte, nesting-depth, or
  member-count limit. Callers handling untrusted documents must enforce
  application-appropriate input limits, as advised by RFC 8785, Section 5.

  ## Requirements

  Erlang/OTP 29 or later, checked at compile time, and Elixir 1.20.2 or
  later.
  """

  otp_release = :erlang.system_info(:otp_release) |> List.to_integer()

  if otp_release < 29 do
    raise "rfc8785 requires Erlang/OTP 29 or later (found OTP #{otp_release})"
  end

  alias RFC8785.{DecodeError, Decoder, EncodeError, Encoder}

  @doc """
  Canonicalizes `term`, returning `{:ok, json}` or `{:error, error}`.

      iex> RFC8785.encode(%{"a" => 1})
      {:ok, ~S({"a":1})}

      iex> {:error, %RFC8785.EncodeError{reason: :unsupported_term}} =
      ...>   RFC8785.encode({:not, :json})
      iex> {:error, error} = RFC8785.encode(%{"n" => 9_007_199_254_740_993})
      iex> error.reason
      :integer_unrepresentable
  """
  @spec encode(term()) :: {:ok, String.t()} | {:error, EncodeError.t()}
  def encode(term) do
    {:ok, encode!(term)}
  rescue
    error in EncodeError -> {:error, error}
  end

  @doc """
  Canonicalizes `term`, returning the canonical JSON as a UTF-8 binary.
  Raises `RFC8785.EncodeError` if the term has no canonical representation.

      iex> RFC8785.encode!(%{"€" => "Euro", "1" => "One", "😂" => "Smiley"})
      ~S({"1":"One","€":"Euro","😂":"Smiley"})
  """
  @spec encode!(term()) :: String.t()
  def encode!(term) do
    term
    |> encode_to_iodata!()
    |> IO.iodata_to_binary()
  end

  @doc """
  Canonicalizes `term` as iodata rather than a binary.

  The bytes are identical to those of `encode!/1`. Consumers that accept
  iodata, such as `:crypto.hash/2`, `IO.binwrite/2`, and sockets, can take
  this result directly without the intermediate binary ever being built.

      iex> RFC8785.encode_to_iodata!([1, 2]) |> IO.iodata_to_binary()
      "[1,2]"
  """
  @spec encode_to_iodata!(term()) :: iodata()
  def encode_to_iodata!(term) do
    Encoder.encode(term, [])
  end

  @doc """
  Canonicalizes `term` as iodata, returning `{:ok, iodata}` or
  `{:error, error}`.

      iex> {:ok, iodata} = RFC8785.encode_to_iodata([1, 2])
      iex> IO.iodata_to_binary(iodata)
      "[1,2]"
  """
  @spec encode_to_iodata(term()) :: {:ok, iodata()} | {:error, EncodeError.t()}
  def encode_to_iodata(term) do
    {:ok, encode_to_iodata!(term)}
  rescue
    error in EncodeError -> {:error, error}
  end

  @doc """
  Canonicalizes a JSON text, returning the canonical JSON as a UTF-8
  binary.

  Decodes `json` with OTP's `:json` parser and re-encodes it canonically.
  Raises `RFC8785.DecodeError` for invalid or unsafe JCS input, including
  duplicate object names, Unicode noncharacters, and number tokens that
  decode to IEEE-754 negative zero. Raises `RFC8785.EncodeError` if a
  decoded value has no canonical representation, such as an integer token
  whose decimal digits cannot be preserved through the required IEEE-754
  double.

      iex> RFC8785.canonicalize!(~S({"b": 2, "a": 1}))
      ~S({"a":1,"b":2})

      iex> RFC8785.canonicalize!("[1E30, 4.50, null]")
      "[1e+30,4.5,null]"
  """
  @spec canonicalize!(String.t()) :: String.t()
  def canonicalize!(json) when is_binary(json) do
    json
    |> Decoder.decode_for_canonicalization!()
    |> encode!()
  end

  @doc """
  Canonicalizes a JSON text, returning `{:ok, json}` or `{:error, error}`.

      iex> RFC8785.canonicalize(~S({"a": 1}))
      {:ok, ~S({"a":1})}

      iex> {:error, %RFC8785.DecodeError{}} = RFC8785.canonicalize("{")
      iex> {:error, %RFC8785.DecodeError{}} = RFC8785.canonicalize(~S({"a": 1, "a": 2}))
      iex> {:error, %RFC8785.EncodeError{}} = RFC8785.canonicalize("9007199254740993")
      iex> match?({:ok, _}, RFC8785.canonicalize("9007199254740992"))
      true
  """
  @spec canonicalize(String.t()) ::
          {:ok, String.t()} | {:error, DecodeError.t() | EncodeError.t()}
  def canonicalize(json) when is_binary(json) do
    {:ok, canonicalize!(json)}
  rescue
    error in [DecodeError, EncodeError] -> {:error, error}
  end

  @doc """
  Decodes a JSON text into Elixir terms under the same parser-side
  validation as `canonicalize!/1`: `null` becomes `nil`; duplicate object
  names, Unicode noncharacters, and number tokens that decode to negative
  zero raise `RFC8785.DecodeError`; and so does non-whitespace data after
  the document.

  Use this rather than a general-purpose JSON parser whenever the decoded
  terms will be re-encoded with `encode!/1` — for example, removing a
  `proof` member before canonicalizing the rest. A parser used instead
  must preserve a compatible term mapping and reject the same invalid
  input. OTP's `:json.decode/1`, for example, yields the atom `:null`,
  which `encode!/1` encodes as the string `"null"`; it also silently keeps
  the first of two duplicate object names.

  A successful decode does not promise that the returned term can be
  canonicalized. `encode!/1` applies additional term-side checks; for
  example, `decode!/1` materializes a plain `9007199254740993` token as an
  integer, while `encode!/1` rejects that integer because conversion
  through its nearest IEEE-754 double would alter the digits.

      iex> RFC8785.decode!(~S({"a": null, "n": 2.50}))
      %{"a" => nil, "n" => 2.5}
  """
  @spec decode!(String.t()) :: term()
  def decode!(json) when is_binary(json) do
    Decoder.decode!(json)
  end

  @doc """
  Decodes a JSON text into Elixir terms, returning `{:ok, term}` or
  `{:error, error}`.

      iex> RFC8785.decode(~S({"a": null}))
      {:ok, %{"a" => nil}}

      iex> {:error, %RFC8785.DecodeError{}} = RFC8785.decode(~S({"a": 1, "a": 2}))
      iex> {:error, %RFC8785.DecodeError{}} = RFC8785.decode("{")
      iex> match?({:ok, _}, RFC8785.decode("[1]"))
      true
  """
  @spec decode(String.t()) :: {:ok, term()} | {:error, DecodeError.t()}
  def decode(json) when is_binary(json) do
    {:ok, decode!(json)}
  rescue
    error in DecodeError -> {:error, error}
  end
end
