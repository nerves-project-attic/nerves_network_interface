defmodule Nerves.NetworkInterface.Mixfile do
  use Mix.Project

  def project do
    [app: :nerves_network_interface,
     version: "0.3.1",
     elixir: ">= 1.0.0 and < 2.0.0",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     compilers: [:elixir_make] ++ Mix.compilers,
     make_clean: ["clean"],
     deps: deps(),
     docs: [extras: ["README.md"],
            main: "readme"],
     package: package(),
     description: description()
    ]
  end

  # Configuration for the OTP application
  #
  # Type `mix help compile.app` for more information
  def application do
    [applications: [:logger],
     mod: {Nerves.NetworkInterface, []}]
  end

  defp description do
    """
    Discover, setup, and get stats on network interfaces.
    """
  end

  defp package do
    %{files: ["lib", "src/*.[ch]", "test", "mix.exs", "README.md", "LICENSE", "CHANGELOG.md", "Makefile"],
      maintainers: ["Frank Hunleth"],
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/nerves-project/nerves_network_interface"}}
  end

  defp deps do
    [
      {:elixir_make, "~> 0.1"},
      {:earmark, "~> 0.1", only: :dev},
      {:ex_doc, "~> 0.11", only: :dev},
      {:credo, "~> 0.3", only: [:dev, :test]}
    ]
  end
end
