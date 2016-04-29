defmodule Mix.Tasks.Compile.NetBasic do
  @shortdoc "Compiles the port binary"
  def run(_) do
    {result, _error_code} = System.cmd("make", ["priv/net_basic"], stderr_to_stdout: true)
    IO.binwrite result
    Mix.Project.build_structure
  end
end

defmodule NetBasic.Mixfile do
  use Mix.Project

  def project do
    [app: :net_basic,
     version: "0.0.1",
     elixir: ">= 1.0.0 and < 2.0.0",
     compilers: Mix.compilers ++ [:NetBasic],
     deps: deps,
     docs: [extras: ["README.md"]],
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

  defp deps do
    [
      {:earmark, "~> 0.1", only: :dev},
      {:ex_doc, "~> 0.11", only: :dev},
      {:credo, "~> 0.3", only: [:dev, :test]}
    ]
  end
end
