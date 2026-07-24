# Benchmark against OTP's :json encoder (non-canonical) for speed context:
#
#     MIX_ENV=dev mix run bench/run.exs

small = %{"a" => 1, "b" => [1.5, "x", nil], "c" => %{"d" => true}}

wide =
  Map.new(1..200, fn i -> {"key_#{i}", i * 1.5} end)

deep =
  Enum.reduce(1..50, "leaf", fn i, acc -> %{"level_#{i}" => [acc, i, i * 0.5]} end)

strings = %{
  "ascii" => String.duplicate("hello world ", 100),
  "escapes" => String.duplicate("line\n\ttab \"quote\" ", 50),
  "unicode" => String.duplicate("日本語テキスト🎌", 50)
}

Benchee.run(
  %{
    "RFC8785.encode!" => &RFC8785.encode!/1,
    ":json.encode (non-canonical baseline)" => fn term ->
      term |> :json.encode() |> IO.iodata_to_binary()
    end
  },
  inputs: %{
    "small map" => small,
    "wide map (200 keys)" => wide,
    "deeply nested" => deep,
    "string-heavy" => strings
  },
  time: 3,
  memory_time: 1
)
