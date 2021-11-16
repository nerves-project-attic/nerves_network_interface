defmodule Nerves.NetworkInterface.Application do
  @moduledoc false

  use Application

  def start(_type, _args) do

    children = [
      %{id: Registry, start: {Registry, :start_link, [[keys: :duplicate, name: Nerves.NetworkInterface]]}},
      %{id: Nerves.NetworkInterface.Worker, start: {Nerves.NetworkInterface.Worker, :start_link, []}}
    ]

    opts = [strategy: :rest_for_one, name: Nerves.NervesInterface.Supervisor]
    Supervisor.start_link(children, opts)
  end

end
