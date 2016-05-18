defmodule Mix.Tasks.Compile.NervesNetworkInterface do
  @shortdoc "Compiles the port binary"
  def run(_) do
    {result, error_code} = System.cmd("make", ["all"], stderr_to_stdout: true)
    IO.binwrite result
    if error_code != 0 do
      raise Mix.Error, "Make returned an error"
    end
    Mix.Project.build_structure
  end
end

defmodule NetBasic.Mixfile do
  use Mix.Project

  def project do
    [app: :net_basic,
     version: "0.2.0",
     elixir: ">= 1.0.0 and < 2.0.0",
     compilers: Mix.compilers ++ [:NervesNetworkInterface],
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
    [applications: [:logger]]
  end

  defp description do
    """
    Elixir interface to basic networking events and link-level and IP management.
    """
  end

  defp package do
    %{files: ["lib", "src/*.[ch]", "test", "mix.exs", "README.md", "LICENSE", "Makefile"],
      maintainers: ["Frank Hunleth"],
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/fhunleth/nerves_networkinterface"}}
  end

  defp deps do
    [
      {:earmark, "~> 0.1", only: :dev},
      {:ex_doc, "~> 0.11", only: :dev},
      {:credo, "~> 0.3", only: [:dev, :test]}
    ]
  end
end
