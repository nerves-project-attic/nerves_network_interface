defmodule Nerves.NetworkInterface.Application do
  @moduledoc false

  use Application

  def start(_type, _args) do
    import Supervisor.Spec, warn: false

    children = [
      worker(Nerves.NetworkInterface, [])
    ]

    opts = [strategy: :rest_for_one, name: Nerves.NervesInterface.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
