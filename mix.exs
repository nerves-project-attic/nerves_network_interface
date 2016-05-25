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

defmodule Nerves.NetworkInterface.Mixfile do
  use Mix.Project

  def project do
    [app: :nerves_network_interface,
     version: "0.3.1",
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
      {:earmark, "~> 0.1", only: :dev},
      {:ex_doc, "~> 0.11", only: :dev},
      {:credo, "~> 0.3", only: [:dev, :test]}
    ]
  end
end
