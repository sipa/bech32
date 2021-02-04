defmodule BIP0173.Mixfile do
  use Mix.Project

  def project do
    [ app: :bip0173,
      version: "0.1.2",
      elixir: "~> 1.3",
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      description: description(),
      package: package(),
      deps: deps()
    ]
  end

  def description do
    """
    Elixir implementation of Bitcoin's address format for native SegWit outputs.
    """
  end

  def package do
    [
      files: ["lib", "mix.exs", "README.md"],
      maintainers: ["Adán Sánchez de Pedro Crespo"],
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/stampery/elixir-bip0173",
        "BIP-0173" => "https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki",
        "Other reference implementations" => "https://github.com/sipa/bech32/tree/master/ref"
      }
    ]
  end

  defp deps do
    [ {:ex_doc, "~> 0.16", only: :dev},
      {:dialyxir, "~> 0.5", only: [:dev]} ]
  end
end
