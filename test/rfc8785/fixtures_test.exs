defmodule RFC8785.FixturesTest do
  use ExUnit.Case, async: true

  # Canonicalization pairs: each input document, decoded and canonicalized,
  # must match its expected output file byte for byte.
  #
  # Provenance:
  #
  #   * arrays, french, structures, unicode, values, weird — the testdata
  #     directory of cyberphone/json-canonicalization, fetched verbatim
  #   * tjs09..tjs13 — JSON-literal canonicalization cases from the W3C
  #     JSON-LD 1.1 test suite, via the pzingg/jcs project
  #   * latin1 — escaped U+0080..U+00FF unescaped into raw UTF-8, from the
  #     pzingg/jcs project
  #
  # Never edit fixture files in place: unicode.json holds unnormalized
  # Unicode that editors may silently normalize.

  @fixtures_dir Path.expand("../fixtures", __DIR__)

  input_files =
    @fixtures_dir
    |> Path.join("input")
    |> File.ls!()
    |> Enum.sort()

  for file_name <- input_files do
    test "fixture #{file_name}" do
      input = File.read!(Path.join(@fixtures_dir, "input/#{unquote(file_name)}"))
      expected = File.read!(Path.join(@fixtures_dir, "output/#{unquote(file_name)}"))

      assert RFC8785.canonicalize!(input) == expected
    end
  end
end
