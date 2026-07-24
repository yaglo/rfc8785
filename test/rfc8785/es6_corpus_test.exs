defmodule RFC8785.Es6CorpusTest do
  use ExUnit.Case, async: false

  # Number serialization against the es6testfile100m corpus of
  # cyberphone/json-canonicalization. test/support/es6_corpus.js generates
  # the corpus deterministically with the upstream algorithm, emitting
  # "hex-ieee,expected" lines plus "#checkpoint <n> <ok|mismatch> <hash>"
  # metadata at each published prefix checksum, so the stream is verified
  # byte-faithful to the official file while it is being consumed.
  #
  # The generator's output arrives in chunks that are carved into
  # complete-line blocks and checked across all schedulers; per-line port
  # messages would dominate the runtime at full corpus size.
  #
  # Excluded by default (requires node). The default checks 100,000 lines;
  # the full run (RFC8785_ES6_CORPUS_N=100000000) streams all 100 million
  # without needing the 4 GB corpus file on disk:
  #
  #     mix test --include es6_corpus

  @moduletag :es6_corpus
  @moduletag timeout: :infinity
  @mismatch_diagnostic_limit 5

  test "matches the cyberphone es6 number corpus" do
    node = System.find_executable("node") || raise "es6_corpus tests require node in PATH"
    lines = System.get_env("RFC8785_ES6_CORPUS_N", "100000")
    script = Path.expand("../support/es6_corpus.js", __DIR__)

    stats =
      block_stream(node, [script, lines])
      |> Task.async_stream(&check_block/1,
        max_concurrency: System.schedulers_online(),
        ordered: false,
        timeout: :infinity
      )
      |> Enum.reduce(
        %{lines: 0, mismatch_count: 0, mismatches: [], checkpoints: []},
        fn {:ok, block}, acc ->
          %{
            lines: acc.lines + block.lines,
            mismatch_count: acc.mismatch_count + block.mismatch_count,
            mismatches: Enum.take(block.mismatches ++ acc.mismatches, @mismatch_diagnostic_limit),
            checkpoints: block.checkpoints ++ acc.checkpoints
          }
        end
      )

    for {n, status, hash} <- stats.checkpoints do
      assert status == "ok",
             "generated stream diverges from the published corpus at line #{n} (SHA-256 #{hash})"
    end

    assert stats.lines == String.to_integer(lines)
    assert stats.checkpoints != [], "no published checkpoint was crossed"

    assert stats.mismatch_count == 0,
           "#{stats.mismatch_count} corpus mismatches; up to five samples: " <>
             inspect(stats.mismatches)
  end

  test "generator count is restricted to the published corpus range" do
    node = System.find_executable("node") || raise "es6_corpus tests require node in PATH"
    script = Path.expand("../support/es6_corpus.js", __DIR__)

    {output, 0} = System.cmd(node, [script, "1000"], stderr_to_stdout: true)
    records = String.split(output, "\n", trim: true)
    assert Enum.count(records, &(not String.starts_with?(&1, "#"))) == 1000
    assert List.last(records) =~ "#checkpoint 1000 ok "

    for invalid <- ["", "0", "999", "100000001", "1.0", "12lines", "9007199254740992"] do
      {error, status} = System.cmd(node, [script, invalid], stderr_to_stdout: true)
      assert status != 0, "es6_corpus.js unexpectedly accepted #{inspect(invalid)}"
      assert error =~ "line count must be a decimal integer from 1000 to 100000000"
    end
  end

  # Streams the generator's stdout as binaries of complete lines: each
  # element ends at a newline, and the remainder carries into the next.
  defp block_stream(executable, args) do
    Stream.resource(
      fn ->
        port =
          Port.open({:spawn_executable, executable}, [:binary, :exit_status, args: args])

        {port, ""}
      end,
      fn
        :done ->
          {:halt, :done}

        {port, carry} ->
          receive do
            {^port, {:data, chunk}} ->
              data = carry <> chunk

              case last_newline(data) do
                nil ->
                  {[], {port, data}}

                pos ->
                  {[binary_part(data, 0, pos)],
                   {port, binary_part(data, pos + 1, byte_size(data) - pos - 1)}}
              end

            {^port, {:exit_status, 0}} ->
              if carry == "", do: {:halt, :done}, else: {[carry], :done}

            {^port, {:exit_status, status}} ->
              raise "es6_corpus.js exited with status #{status}"
          end
      end,
      fn
        :done -> :ok
        {port, _carry} -> if Port.info(port), do: Port.close(port)
      end
    )
  end

  defp last_newline(data) do
    case :binary.matches(data, "\n") do
      [] -> nil
      matches -> matches |> List.last() |> elem(0)
    end
  end

  defp check_block(block) do
    block
    |> :binary.split("\n", [:global, :trim_all])
    |> Enum.reduce(%{lines: 0, mismatch_count: 0, mismatches: [], checkpoints: []}, fn
      "#checkpoint " <> checkpoint, acc ->
        [n, status, hash] = String.split(checkpoint, " ")
        %{acc | checkpoints: [{n, status, hash} | acc.checkpoints]}

      line, acc ->
        [hex, expected] = :binary.split(line, ",")
        <<value::float-64>> = <<String.to_integer(hex, 16)::64>>
        actual = RFC8785.encode!(value)
        acc = %{acc | lines: acc.lines + 1}

        if actual == expected, do: acc, else: record_mismatch(acc, hex, expected, actual)
    end)
  end

  # Every mismatch is counted; only the first few are kept for the failure
  # message, so a systemic corpus failure cannot exhaust memory.
  defp record_mismatch(acc, hex, expected, actual) do
    mismatches =
      if acc.mismatch_count < @mismatch_diagnostic_limit do
        [{hex, expected, actual} | acc.mismatches]
      else
        acc.mismatches
      end

    %{acc | mismatch_count: acc.mismatch_count + 1, mismatches: mismatches}
  end
end
