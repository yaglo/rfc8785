# RFC8785

An implementation of [RFC 8785: JSON Canonicalization Scheme
(JCS)](https://www.rfc-editor.org/rfc/rfc8785) in pure Elixir.

JCS defines a canonical byte representation for I-JSON-compatible values:
logically equivalent valid inputs serialize to identical bytes. Canonical
bytes are what protocols hash and sign. Schemes that sign JSON by value
build on JCS, among them the JCS cryptosuites of W3C Data Integrity
(`eddsa-jcs-2022`, `ecdsa-jcs-2019`).

```elixir
# Elixir terms in, canonical bytes out.
RFC8785.encode!(%{"b" => 100.0, "aa" => 200, "a" => "hello\tworld"})
#=> ~S({"a":"hello\tworld","aa":200,"b":100})

# Or JSON text in, canonical bytes out.
RFC8785.canonicalize!(~S({"b": 2.50, "a": 1E30}))
#=> ~S({"a":1e+30,"b":2.5})

# Hashing takes the iodata form directly, with no intermediate binary.
document = %{"amount" => 100, "currency" => "GBP"}
:crypto.hash(:sha256, RFC8785.encode_to_iodata!(document))
```

The library has no runtime dependencies and requires Erlang/OTP 29 and
Elixir 1.20.2 or later.

## Installation

Add `rfc8785` to your dependencies:

```elixir
def deps do
  [
    {:rfc8785, "~> 1.0"}
  ]
end
```

## API

  * `RFC8785.encode!/1` canonicalizes Elixir terms into a UTF-8 binary and
    raises `RFC8785.EncodeError` on input with no canonical representation.
  * `RFC8785.encode/1` returns `{:ok, json}` or `{:error, error}`.
  * `RFC8785.encode_to_iodata!/1` returns iodata suitable for passing
    directly to `:crypto.hash/2`, a socket, or a file;
    `RFC8785.encode_to_iodata/1` wraps that iodata in `{:ok, iodata}` (or
    returns `{:error, error}`).
  * `RFC8785.canonicalize!/1` and `RFC8785.canonicalize/1` accept a JSON
    text, as when verifying a signature over a received document. Decoding
    uses OTP's `:json` parser and enforces I-JSON: duplicate object names
    and Unicode noncharacters raise `RFC8785.DecodeError` rather than
    being silently accepted or altered. Number tokens that decode to
    IEEE-754 negative zero are also rejected, following RFC 8785 erratum
    7920.
  * `RFC8785.decode!/1` and `RFC8785.decode/1` decode a JSON text into
    Elixir terms under the same parser-side strictness, for workflows that
    modify the document between parsing and canonicalizing — removing a
    `proof` member before hashing, for instance. A parser is a safe
    substitute on this path only if its term mapping and validation
    preserve the same data: OTP's `:json.decode/1`, for example, yields
    the atom `:null` for JSON `null`, which re-encodes here as the string
    `"null"`; it also silently keeps the first of two duplicate object
    names. Successful decoding does not guarantee that the resulting term
    can be encoded: `encode!/1` still applies term-side checks such as the
    digit-preserving integer rule.

Every failure is an `RFC8785.EncodeError` or `RFC8785.DecodeError` carrying
a stable `:reason` atom and an explanatory `:message` that names the
offending value's location. Callers can branch on the reason without
parsing prose:

```elixir
text = ~S({"a": 1, "a": 2})

case RFC8785.canonicalize(text) do
  {:ok, json} -> json
  {:error, %RFC8785.DecodeError{reason: :duplicate_name}} -> :client_error
  {:error, error} -> {:rejected, error.message}
end
#=> :client_error
```

## Conformance

  * **Numbers** (RFC 8785 §3.2.2.3) serialize exactly as ECMAScript's
    `Number::toString`. The shortest round-tripping digits come from OTP's
    Ryu implementation; formatting follows the ECMA-262 `NumberToString`
    rules, implemented one clause per rule. Erlang's choice between plain
    and scientific notation is not relied on: its output is first reparsed
    into digits and a decimal exponent.
  * **Strings** (§3.2.2.2) use `\b`, `\t`, `\n`, `\f`, `\r`, lowercase
    `\u00hh` for the remaining C0 controls, and `\"` and `\\`. All other
    permitted code points, including U+007F and non-ASCII, are emitted
    unescaped in UTF-8. Unicode noncharacters are rejected as required by
    I-JSON.
  * **Object names** (§3.2.3) sort by UTF-16 code units. Names containing
    surrogate pairs order correctly. Duplicate names, which can arise in
    Elixir when an atom key and a string key coerce to the same name, are
    rejected: RFC 8785 requires I-JSON (RFC 7493) input, and I-JSON object
    names are unique.
  * **Whitespace** is never emitted (§3.2.1). Output is always valid UTF-8
    (§3.2.4).

## Input validation

Elixir term input must fit the documented JSON mapping and I-JSON
constraints. A term outside that domain is rejected with an
`RFC8785.EncodeError` naming the offending value's location, such as
`$.payload.amounts[3]`.

Integers within ±2^53 are exact. A larger integer is accepted only when
serializing its nearest IEEE-754 double reproduces the same decimal digits.
Every integer parsed from canonical JCS output has this property, so
decoding a canonical document and re-canonicalizing it always round-trips.
An integer such as `9007199254740993`, whose nearest double serializes as
`9007199254740992`, is rejected; convert such a value to a float if the
altered digits are acceptable, or encode it as a string to keep them.

For JSON text input, number tokens with a fraction or exponent are decoded
to IEEE-754 doubles, as required by RFC 8785. Canonicalization therefore
preserves their numeric double value, not their original spelling or every
decimal digit; for example, `0.100000000000000005` canonicalizes to `0.1`.

Structs, tuples, non-UTF-8 binaries, strings containing Unicode
noncharacters, map keys that are neither strings nor atoms, and improper
lists are also rejected. JSON text number tokens that decode to IEEE-754
negative zero — including negative values that underflow to zero — are
rejected. A programmatically supplied `-0.0` float still follows
ECMAScript `Number::toString` and encodes as `0`. `NaN` and `Infinity`
cannot occur: Erlang floats cannot represent them.

When canonicalizing JSON text, an integer token with more than 21
magnitude digits is rejected before constructing a bignum. If its value
is representable as a finite double, ECMAScript serializes that magnitude
in exponent notation; otherwise it is outside the IEEE-754 range. In
either case, the token's plain integer digits cannot be canonical output.
`decode!/1` remains a general decoding API and does materialize such
tokens as arbitrary-precision integers.

The library does not impose an overall document byte, nesting-depth, or
member-count limit. Callers handling untrusted documents must enforce
application-appropriate input limits, as advised by RFC 8785 §5.

## Verification

The test suite verifies conformance against:

  * the number serialization samples of RFC 8785 Appendix B;
  * the object-sorting example of §3.2.3, byte for byte;
  * the `es6testfile100m` number corpus of
    [cyberphone/json-canonicalization](https://github.com/cyberphone/json-canonicalization),
    generated locally with the published deterministic algorithm and
    checked against the published prefix checksums as it streams;
  * canonicalization test data from cyberphone/json-canonicalization and
    the W3C JSON-LD 1.1 test suite;
  * property-based tests covering round-tripping, idempotence, sort-order
    agreement with an independent UTF-16 comparator, output validity, and
    error totality;
  * differential fuzzing against Node.js, whose `JSON.stringify` implements
    the ECMAScript serialization that RFC 8785 normatively references.

The corpus and differential tests require `node` in `PATH` and are
excluded by default. The corpus test runs its first 100,000 values unless
told otherwise; this source tree has passed the full 100-million-value run
with zero mismatches.

```sh
mix test --include differential --include es6_corpus
RFC8785_FUZZ_N=1000000 mix test --include differential
RFC8785_ES6_CORPUS_N=100000000 mix test --include es6_corpus
```

## Acknowledgements

The `arrays`, `french`, `structures`, `unicode`, `values`, and `weird`
test fixtures are verbatim copies from Anders Rundgren's
[json-canonicalization](https://github.com/cyberphone/json-canonicalization)
test data, whose number-corpus generator the corpus test also derives
from. The `tjs09`–`tjs13` fixtures come from the
[W3C JSON-LD 1.1 test suite](https://w3c.github.io/json-ld-api/tests/) and
`latin1` from Peter Zingg's [jcs](https://github.com/pzingg/jcs) package,
which first brought both into Elixir.

## License

The published library code is Apache-2.0; see `LICENSE`. Test data and test
tooling bundled in the source repository retain the third-party terms and
attributions listed in `NOTICE`; those test files are not included in the
Hex package.
