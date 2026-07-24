defmodule RFC8785Test do
  use ExUnit.Case, async: true
  doctest RFC8785

  describe "encode/1" do
    test "returns {:ok, json} on success" do
      assert RFC8785.encode(%{"a" => 1}) == {:ok, ~S({"a":1})}
    end

    test "returns {:error, %EncodeError{}} on failure" do
      assert {:error, %RFC8785.EncodeError{message: message}} = RFC8785.encode({:a, :tuple})
      assert message =~ "cannot encode"
    end
  end

  describe "encode!/1 scalars" do
    test "literals" do
      assert RFC8785.encode!(nil) == "null"
      assert RFC8785.encode!(true) == "true"
      assert RFC8785.encode!(false) == "false"
    end

    test "strings" do
      assert RFC8785.encode!("") == ~S("")
      assert RFC8785.encode!("hello") == ~S("hello")
      assert RFC8785.encode!("西葛西駅") == ~S("西葛西駅")
    end

    test "bare atoms encode as their name string" do
      assert RFC8785.encode!(:active) == ~S("active")
      assert RFC8785.encode!(%{"status" => :active}) == ~S({"status":"active"})
    end

    test "the atom :null is a string, not the JSON literal" do
      assert RFC8785.encode!(:null) == ~S("null")
    end
  end

  describe "encode!/1 arrays" do
    test "empty and nested" do
      assert RFC8785.encode!([]) == "[]"
      assert RFC8785.encode!([1, [2, [3]], "x"]) == ~S([1,[2,[3]],"x"])
    end

    test "charlists encode as arrays of integers" do
      assert RFC8785.encode!(~c"abc") == "[97,98,99]"
    end

    test "improper lists are rejected with their path" do
      error = assert_raise RFC8785.EncodeError, fn -> RFC8785.encode!([1, [2 | 3]]) end
      assert error.message =~ "improper list"
      assert error.message =~ "$[1]"
    end
  end

  describe "encode!/1 objects" do
    test "empty object" do
      assert RFC8785.encode!(%{}) == "{}"
    end

    test "atom keys are coerced to strings" do
      assert RFC8785.encode!(%{b: 2, a: 1}) == ~S({"a":1,"b":2})
    end

    test "nil, true, and false keys coerce to their atom names" do
      assert RFC8785.encode!(%{nil => 1}) == ~S({"nil":1})
      assert RFC8785.encode!(%{true => 1}) == ~S({"true":1})
    end

    test "the empty string is a valid name and sorts first" do
      assert RFC8785.encode!(%{"" => 1, "a" => 2}) == ~S({"":1,"a":2})
    end

    test "duplicate names after atom coercion are rejected" do
      error = assert_raise RFC8785.EncodeError, fn -> RFC8785.encode!(%{:a => 1, "a" => 2}) end
      assert error.message =~ "duplicate object name"
      assert error.message =~ ~S("a")
    end

    test "non-string, non-atom keys are rejected" do
      for key <- [1, 1.0, [], {1, 2}, %{}] do
        error = assert_raise RFC8785.EncodeError, fn -> RFC8785.encode!(%{key => "x"}) end
        assert error.message =~ "invalid object key"
      end
    end

    test "structs are rejected with guidance" do
      error = assert_raise RFC8785.EncodeError, fn -> RFC8785.encode!(~D[2026-07-24]) end
      assert error.message =~ "Date"
      assert error.message =~ "plain map"

      assert_raise RFC8785.EncodeError, fn -> RFC8785.encode!(MapSet.new([1])) end
    end

    test "errors deep in a structure report a JSONPath-style location" do
      error =
        assert_raise RFC8785.EncodeError, fn ->
          RFC8785.encode!(%{"a" => [%{"b" => {:bad}}]})
        end

      assert error.message =~ "$.a[0].b"
    end

    test "non-identifier names are bracketed in paths" do
      error =
        assert_raise RFC8785.EncodeError, fn ->
          RFC8785.encode!(%{"weird key" => {:bad}})
        end

      assert error.message =~ ~S($["weird key"])
    end
  end

  describe "object name sorting (RFC 8785, Section 3.2.3)" do
    test "the RFC's own example, byte for byte" do
      # Input and expected output are built exclusively from ASCII escapes
      # and explicit codepoints: raw non-ASCII literals in source files are
      # at the mercy of editor/tooling Unicode normalization.
      actual =
        RFC8785.canonicalize!(~S({
          "\u20ac": "Euro Sign",
          "\r": "Carriage Return",
          "\ufb33": "Hebrew Letter Dalet With Dagesh",
          "1": "One",
          "\ud83d\ude02": "Smiley",
          "\u0080": "Control",
          "\u00f6": "Latin Small Letter O With Diaeresis"
        }))

      expected =
        ~S({"\r":"Carriage Return","1":"One",") <>
          <<0x80::utf8>> <>
          ~S(":"Control",") <>
          <<0xF6::utf8>> <>
          ~S(":"Latin Small Letter O With Diaeresis",") <>
          <<0x20AC::utf8>> <>
          ~S(":"Euro Sign",") <>
          <<0x1F602::utf8>> <>
          ~S(":"Smiley",") <>
          <<0xFB33::utf8>> <>
          ~S(":"Hebrew Letter Dalet With Dagesh"})

      assert actual == expected
    end

    test "surrogate-pair names sort by UTF-16 code units, not codepoints" do
      # U+1D11E (G clef) encodes as the surrogate pair D834 DD1E; U+FB33
      # (Hebrew dalet with dagesh) is a single unit FB33. Code-unit order
      # puts D834 before FB33, although codepoint order is the reverse.
      g_clef = <<0x1D11E::utf8>>
      dalet = <<0xFB33::utf8>>

      assert RFC8785.encode!(%{g_clef => 1, dalet => 2}) ==
               ~s({"#{g_clef}":1,"#{dalet}":2})
    end

    test "prefix names sort before their extensions" do
      assert RFC8785.encode!(%{"ab" => 1, "a" => 2}) == ~S({"a":2,"ab":1})
    end

    test "logically equal maps canonicalize identically" do
      map1 = %{"b" => 100.0, "aa" => 200, "a" => "x"}
      map2 = %{"a" => "x", "aa" => 200.0, "b" => 100}
      assert RFC8785.encode!(map1) == RFC8785.encode!(map2)
    end
  end

  describe "encode_to_iodata!/1" do
    test "iodata flattens to the expected canonical bytes" do
      term = %{"a" => [1, 2.5, "x"], "b" => %{"c" => nil}}

      assert IO.iodata_to_binary(RFC8785.encode_to_iodata!(term)) ==
               ~S({"a":[1,2.5,"x"],"b":{"c":null}})
    end
  end
end
