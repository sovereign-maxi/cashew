defmodule Cashew.MixProject do
  use Mix.Project

  def project do
    [
      app: :cashew,
      version: "0.1.0",
      elixir: "~> 1.17",
      elixirc_options: [warnings_as_errors: true],
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      test_coverage: [tool: ExCoveralls],
      name: "Cashew",
      docs: [main: "Cashew", extras: ["README.md"]]
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto]]
  end

  def cli do
    [
      preferred_envs: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.html": :test
      ]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:rustler, "~> 0.36"},
      # Dev/Test
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:excoveralls, "~> 0.18", only: :test},
      {:stream_data, "~> 1.1", only: :test}
    ]
  end

  defp aliases do
    [
      test: ["test --color"],
      lint: ["credo --strict", "dialyzer"]
    ]
  end
end
