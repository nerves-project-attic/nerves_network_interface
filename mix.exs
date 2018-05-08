defmodule Nerves.NetworkInterface.Mixfile do
  use Mix.Project

  def project do
    [
      app: :nerves_network_interface,
      version: "0.4.4",
      elixir: "~> 1.6",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      compilers: [:elixir_make] ++ Mix.compilers(),
      make_clean: ["clean"],
      deps: deps(),
      docs: [extras: ["README.md"], main: "readme"],
      package: package(),
      aliases: [format: [&format_c/1, "format"]],
      description: description()
    ]
  end

  # Configuration for the OTP application
  #
  # Type `mix help compile.app` for more information
  def application do
    [extra_applications: [:logger], mod: {Nerves.NetworkInterface.Application, []}]
  end

  defp description do
    """
    Discover, setup, and get stats on network interfaces.
    """
  end

  defp package do
    %{
      files: [
        "lib",
        "src/*.[ch]",
        "src/test-c99.sh",
        "test",
        "mix.exs",
        "README.md",
        "LICENSE",
        "CHANGELOG.md",
        "Makefile"
      ],
      maintainers: ["Frank Hunleth"],
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/nerves-project/nerves_network_interface"}
    }
  end

  defp deps do
    [
      {:dialyxir, ">= 0.0.0", only: [:dev, :test]},
      {:system_registry, "~> 0.2.1"},
      {:elixir_make, "~> 0.4", runtime: false},
      {:ex_doc, "~> 0.11", only: :dev}
    ]
  end

  defp format_c([]) do
    astyle =
      System.find_executable("astyle") ||
        Mix.raise("""
        Could not format C code since astyle is not available.
        """)

    System.cmd(
      astyle,
      ["-n", "src/*.c", "src/*.h"],
      into: IO.stream(:stdio, :line)
    )
  end

  defp format_c(_args), do: true
end
