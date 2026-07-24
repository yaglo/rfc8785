defmodule RFC8785.MixProject do
  use Mix.Project

  @version "1.0.0"
  @source_url "https://github.com/yaglo/rfc8785"

  def project do
    [
      app: :rfc8785,
      version: @version,
      elixir: "~> 1.20 and >= 1.20.2",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      source_url: @source_url,
      homepage_url: @source_url,
      dialyzer: [
        # :underspecs would flag the term() specs on the public API, which
        # accepts any term and raises on unrepresentable input.
        flags: [:error_handling, :unmatched_returns],
        plt_add_apps: [:ex_unit]
      ]
    ]
  end

  def application do
    [
      extra_applications: []
    ]
  end

  defp description do
    """
    RFC 8785 JSON Canonicalization Scheme (JCS) in pure Elixir. Deterministic,
    byte-exact canonical JSON for hashing and signing. Zero runtime dependencies.
    """
  end

  defp package do
    [
      name: "rfc8785",
      files: ~w(lib mix.exs README.md LICENSE NOTICE .formatter.exs),
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url,
        "RFC 8785" => "https://www.rfc-editor.org/rfc/rfc8785"
      }
    ]
  end

  defp docs do
    [
      main: "RFC8785",
      source_ref: "v#{@version}",
      extras: ["README.md"]
    ]
  end

  defp deps do
    [
      # Test/dev only. The library itself has zero runtime dependencies.
      {:stream_data, "~> 1.1", only: [:dev, :test]},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:benchee, "~> 1.3", only: :dev}
    ]
  end
end
