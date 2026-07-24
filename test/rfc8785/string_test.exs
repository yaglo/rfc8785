defmodule RFC8785.StringTest do
  use ExUnit.Case, async: true

  # RFC 8785, Section 3.2.2.2: the five named C0 escapes.
  @named_escapes %{
    0x08 => "\\b",
    0x09 => "\\t",
    0x0A => "\\n",
    0x0C => "\\f",
    0x0D => "\\r"
  }

  @noncharacters Enum.to_list(0xFDD0..0xFDEF) ++
                   Enum.flat_map(0..16, fn plane ->
                     base = plane * 0x10000
                     [base + 0xFFFE, base + 0xFFFF]
                   end)

  test "every C0 control character uses its required escape" do
    for byte <- 0x00..0x1F do
      expected =
        Map.get_lazy(@named_escapes, byte, fn ->
          hex = byte |> Integer.to_string(16) |> String.downcase()
          "\\u" <> String.pad_leading(hex, 4, "0")
        end)

      assert RFC8785.encode!(<<byte>>) == "\"" <> expected <> "\"",
             "0x#{Integer.to_string(byte, 16)} must serialize as #{expected}"
    end
  end

  test "hex escapes are lowercase" do
    assert RFC8785.encode!(<<0x1B>>) == "\"\\u001b\""
    assert RFC8785.encode!(<<0x0E>>) == "\"\\u000e\""
  end

  test "quote and backslash are escaped" do
    assert RFC8785.encode!(~S(a"b)) == ~S("a\"b")
    assert RFC8785.encode!("a\\b") == "\"a\\\\b\""
  end

  test "solidus is not escaped" do
    assert RFC8785.encode!("a/b") == ~S("a/b")
  end

  test "U+007F (DEL) is emitted as-is" do
    assert RFC8785.encode!(<<0x7F>>) == <<?", 0x7F, ?">>
  end

  test "U+0080 is emitted as-is in UTF-8" do
    assert RFC8785.encode!(<<0x80::utf8>>) == <<?", 0xC2, 0x80, ?">>
  end

  test "astral characters are emitted as-is, never as surrogate escapes" do
    smiley = <<0x1F602::utf8>>
    assert RFC8785.encode!(smiley) == <<?">> <> smiley <> <<?">>
  end

  test "mixed escapes and runs are byte-exact" do
    assert RFC8785.encode!("a\"b\\c\nd\te") == ~S("a\"b\\c\nd\te")
  end

  test "matches the JCS values.json string sample" do
    input = ~S("\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/")
    expected = <<?", 0x20AC::utf8>> <> ~S($\u000f\nA'B\"\\\\\"/) <> <<?">>
    assert RFC8785.canonicalize!(input) == expected
  end

  test "all 66 Unicode noncharacters are rejected from terms and JSON text" do
    assert length(@noncharacters) == 66

    for codepoint <- @noncharacters do
      string = <<codepoint::utf8>>

      assert {:error, %RFC8785.EncodeError{message: encode_message}} =
               RFC8785.encode(string)

      assert encode_message =~ "noncharacter"
      assert encode_message =~ "$"

      for json <- [<<?">> <> string <> <<?">>, escaped_json_string(codepoint)] do
        assert {:error, %RFC8785.DecodeError{message: decode_message}} =
                 RFC8785.canonicalize(json)

        assert decode_message =~ "noncharacter"
        assert decode_message =~ "$"
      end
    end
  end

  test "noncharacters are rejected at nested value and object-name paths" do
    noncharacter = <<0x10FFFF::utf8>>

    error =
      assert_raise RFC8785.EncodeError, fn ->
        RFC8785.encode!(%{"outer" => [noncharacter]})
      end

    assert error.message =~ "U+10FFFF"
    assert error.message =~ "$.outer[0]"

    error =
      assert_raise RFC8785.EncodeError, fn ->
        RFC8785.encode!(%{"outer" => %{noncharacter => 1}})
      end

    assert error.message =~ "object name"
    assert error.message =~ "$.outer"

    literal_value = ~S({"outer":[") <> noncharacter <> ~S("]})
    error = assert_raise RFC8785.DecodeError, fn -> RFC8785.canonicalize!(literal_value) end
    assert error.message =~ "$.outer[0]"

    literal_name = ~S({"outer":{") <> noncharacter <> ~S(":1}})
    error = assert_raise RFC8785.DecodeError, fn -> RFC8785.canonicalize!(literal_name) end
    assert error.message =~ "$.outer"
  end

  test "atom values and keys cannot bypass noncharacter validation" do
    noncharacter_atom = String.to_atom("atom-" <> <<0xFDD0::utf8>>)

    error =
      assert_raise RFC8785.EncodeError, fn ->
        RFC8785.encode!(%{"value" => noncharacter_atom})
      end

    assert error.message =~ "U+FDD0"
    assert error.message =~ "$.value"

    error =
      assert_raise RFC8785.EncodeError, fn ->
        RFC8785.encode!(%{noncharacter_atom => 1})
      end

    assert error.message =~ "U+FDD0"
    assert error.message =~ "$["
  end

  describe "invalid UTF-8 is rejected with EncodeError" do
    test "invalid leading byte" do
      error = assert_raise RFC8785.EncodeError, fn -> RFC8785.encode!(<<0xFF, 0xFE>>) end
      assert error.message =~ "not valid UTF-8"
    end

    test "lone continuation byte" do
      assert_raise RFC8785.EncodeError, fn -> RFC8785.encode!(<<?a, 0x80, ?b>>) end
    end

    test "truncated multi-byte sequence" do
      assert_raise RFC8785.EncodeError, fn -> RFC8785.encode!(<<0xE2, 0x82>>) end
    end

    test "overlong encoding" do
      assert_raise RFC8785.EncodeError, fn -> RFC8785.encode!(<<0xC0, 0x80>>) end
    end

    test "UTF-8-encoded surrogate" do
      assert_raise RFC8785.EncodeError, fn -> RFC8785.encode!(<<0xED, 0xA0, 0x80>>) end
    end

    test "error reports byte offset and path" do
      error =
        assert_raise RFC8785.EncodeError, fn ->
          RFC8785.encode!(%{"k" => <<"abc", 0xFF>>})
        end

      assert error.message =~ "offset 3"
      assert error.message =~ "$.k"
    end

    test "invalid UTF-8 in object names is also rejected" do
      assert_raise RFC8785.EncodeError, fn -> RFC8785.encode!(%{<<0xFF>> => 1}) end
    end
  end

  defp escaped_json_string(codepoint) when codepoint <= 0xFFFF do
    hex =
      codepoint
      |> Integer.to_string(16)
      |> String.upcase()
      |> String.pad_leading(4, "0")

    ~S("\u) <> hex <> "\""
  end

  defp escaped_json_string(codepoint) do
    offset = codepoint - 0x10000
    high = 0xD800 + div(offset, 0x400)
    low = 0xDC00 + rem(offset, 0x400)

    ~S("\u) <> hex4(high) <> ~S(\u) <> hex4(low) <> "\""
  end

  defp hex4(code_unit) do
    code_unit
    |> Integer.to_string(16)
    |> String.upcase()
    |> String.pad_leading(4, "0")
  end
end
