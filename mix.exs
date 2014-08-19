defmodule Mix.Tasks.Compile.NetBasic do
  @shortdoc "Compiles the port binary"
  def run(_) do
    0=Mix.Shell.IO.cmd("make priv/net_basic")
  end
end

defmodule NetBasic.Mixfile do
  use Mix.Project

  def project do
    [app: :net_basic,
     version: "0.0.1",
     elixir: "~> 0.15.1",
     compilers: [:NetBasic, :elixir, :app],
     deps: deps,
     package: package,
     description: description
    ]
  end

  # Configuration for the OTP application
  #
  # Type `mix help compile.app` for more information
  def application do
    [applications: []]
  end

  defp description do
    """
    Elixir interface to basic networking events and link-level and IP management.
    """
  end

  defp package do
    %{files: ["lib", "src/*.[ch]", "test", "mix.exs", "README.md", "LICENSE", "Makefile"],
      contributors: ["Frank Hunleth"],
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/fhunleth/net_basic.ex"}}
  end

  # Dependencies can be hex.pm packages:
  #
  #   {:mydep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:mydep, git: "https://github.com/elixir-lang/mydep.git", tag: "0.1"}
  #
  # Type `mix help deps` for more examples and options
  defp deps do
    []
  end
end
