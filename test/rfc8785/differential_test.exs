defmodule RFC8785.DifferentialTest do
  use ExUnit.Case, async: false

  # Differential tests against Node.js, whose JSON.stringify implements the
  # ECMAScript serialization that RFC 8785 normatively references. Excluded
  # by default (they need a `node` executable); run with:
  #
  #     mix test --include differential
  #
  # Sample counts are tuned for CI; raise them via RFC8785_FUZZ_N for a
  # deeper local soak.

  @moduletag :differential
  @moduletag timeout: 600_000

  @support_dir Path.expand("../support", __DIR__)
  @double_edge_count 19
  @number_text_edge_count 41
  @mismatch_diagnostic_limit 5

  setup_all do
    case System.find_executable("node") do
      nil -> raise "differential tests require node in PATH"
      node -> {:ok, node: node}
    end
  end

  test "number serialization matches ES6 JSON.stringify", %{node: node} do
    n = System.get_env("RFC8785_FUZZ_N", "100000")

    {output, 0} =
      System.cmd(node, [Path.join(@support_dir, "gen_doubles.js"), n], stderr_to_stdout: false)

    records = String.split(output, "\n", trim: true)
    assert length(records) == String.to_integer(n) + @double_edge_count

    stats =
      Enum.reduce(records, %{mismatch_count: 0, mismatches: []}, fn line, stats ->
        [hex, expected] = String.split(line, "\t")
        <<value::float-64>> = Base.decode16!(hex, case: :lower)
        actual = RFC8785.encode!(value)

        if actual == expected do
          stats
        else
          add_mismatch(stats, {hex, expected, actual})
        end
      end)

    assert stats.mismatch_count == 0,
           "#{stats.mismatch_count} number mismatches; first five: " <>
             inspect(Enum.reverse(stats.mismatches))
  end

  test "string serialization matches ES6 JSON.stringify", %{node: node} do
    n = System.get_env("RFC8785_FUZZ_N", "20000")

    {output, 0} =
      System.cmd(node, [Path.join(@support_dir, "gen_strings.js"), n], stderr_to_stdout: false)

    records = String.split(output, "\n", trim: true)
    assert length(records) == String.to_integer(n)

    stats =
      Enum.reduce(records, %{mismatch_count: 0, mismatches: []}, fn line, stats ->
        [input_b64, expected_b64] = String.split(line, "\t")
        input = Base.decode64!(input_b64)
        expected = Base.decode64!(expected_b64)
        actual = RFC8785.encode!(input)

        if actual == expected do
          stats
        else
          add_mismatch(stats, {input, expected, actual})
        end
      end)

    assert stats.mismatch_count == 0,
           "#{stats.mismatch_count} string mismatches; first five: " <>
             inspect(Enum.reverse(stats.mismatches))
  end

  test "JSON number text parsing matches ES6 JSON.parse and JSON.stringify", %{node: node} do
    n = System.get_env("RFC8785_FUZZ_N", "100000")

    {output, 0} =
      System.cmd(node, [Path.join(@support_dir, "gen_number_texts.js"), n],
        stderr_to_stdout: false
      )

    records = String.split(output, "\n", trim: true)
    assert length(records) == String.to_integer(n) + @number_text_edge_count

    stats =
      Enum.reduce(records, %{mismatch_count: 0, mismatches: []}, fn line, stats ->
        [input, expected] = String.split(line, "\t", parts: 2)

        case RFC8785.canonicalize(input) do
          {:ok, ^expected} ->
            stats

          {:ok, actual} ->
            add_mismatch(stats, {input, expected, actual})

          {:error, error} ->
            add_mismatch(stats, {input, expected, error})
        end
      end)

    assert stats.mismatch_count == 0,
           "#{stats.mismatch_count} number-text mismatches; first five: " <>
             inspect(Enum.reverse(stats.mismatches))
  end

  test "negative-zero number tokens are rejected per RFC 8785 erratum 7920" do
    for input <- [
          "-0",
          "-0.0",
          "-0e0",
          "-0E+100",
          "-0.000e-100",
          "-1e-999",
          "-2.4703282292062327e-324"
        ] do
      assert {:error, %RFC8785.DecodeError{}} = RFC8785.canonicalize(input),
             "negative-zero token was accepted: #{input}"
    end
  end

  test "generators reject malformed or non-positive sample counts", %{node: node} do
    for script <- ["gen_doubles.js", "gen_strings.js", "gen_number_texts.js"],
        invalid <- ["", "0", "-1", "+1", "1.0", "1e3", "12samples", " 12", "9007199254740992"] do
      {output, status} =
        System.cmd(node, [Path.join(@support_dir, script), invalid], stderr_to_stdout: true)

      assert status != 0, "#{script} unexpectedly accepted #{inspect(invalid)}"
      assert output =~ "sample count must be a positive decimal integer"
    end
  end

  test "string generator rerolls every Unicode noncharacter", %{node: node} do
    script = Path.join(@support_dir, "gen_strings.js")

    probe = """
    const {isIJsonScalar, randomCodepoint} = require(process.argv[1]);
    const noncharacters = [];
    for (let cp = 0xfdd0; cp <= 0xfdef; cp++) noncharacters.push(cp);
    for (let plane = 0; plane <= 16; plane++) {
      noncharacters.push((plane << 16) | 0xfffe, (plane << 16) | 0xffff);
    }
    if (noncharacters.length !== 66) throw new Error('bad test vector');

    for (const cp of noncharacters) {
      if (isIJsonScalar(cp)) throw new Error('accepted U+' + cp.toString(16));
      const draws = cp < 0x10000
        ? [0.5, cp / 0x10000, 0.1, 0.5]
        : [0.9, (cp - 0x10000) / 0x100000, 0.1, 0.5];
      const got = randomCodepoint(() => draws.shift());
      if (got !== 0x40) throw new Error('did not reroll U+' + cp.toString(16));
    }
    process.stdout.write('66\\n');
    """

    assert {output, 0} = System.cmd(node, ["-e", probe, script], stderr_to_stdout: true)
    assert output == "66\n"
  end

  defp add_mismatch(stats, mismatch) do
    mismatches =
      if stats.mismatch_count < @mismatch_diagnostic_limit do
        [mismatch | stats.mismatches]
      else
        stats.mismatches
      end

    %{stats | mismatch_count: stats.mismatch_count + 1, mismatches: mismatches}
  end
end
