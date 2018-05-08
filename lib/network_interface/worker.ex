# Copyright 2014-2017 Frank Hunleth
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

defmodule Nerves.NetworkInterface.Worker do
  @moduledoc """
  Working for NetworkInterface.
  See `Nerves.NetworkInterface` for more details.
  """

  use GenServer
  require Logger

  @enforce_keys [:port]
  defstruct [:port]

  @typedoc "State of the GenServer"
  @type t :: %__MODULE__{port: port}

  @typedoc "Setup options."
  @type options :: map

  @typedoc "Interface name"
  @type ifname :: String.t()

  @spec start_link() :: GenServer.on_start()
  def start_link() do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @spec stop() :: :ok
  def stop() do
    GenServer.cast(__MODULE__, :stop)
  end

  @spec interfaces() :: [ifname]
  def interfaces() do
    GenServer.call(__MODULE__, :interfaces)
  end

  @typep mac_address :: bitstring

  @type stats :: %{
          collisions: number,
          multicast: number,
          rx_bytes: number,
          rx_dropped: number,
          rx_errors: number,
          rx_packets: number,
          tx_bytes: number,
          tx_dropped: number,
          tx_errors: number,
          tx_packets: number
        }

  @typedoc "Status response"
  @type status :: %{
          ifname: ifname,
          type: :ethernet,
          index: number,
          is_broadcast: boolean,
          is_lower_up: boolean,
          is_multicast: boolean,
          is_up: boolean,
          is_running: boolean,
          mac_address: mac_address,
          mac_broadcast: mac_address,
          mtu: number,
          operstate: :up | :down,
          stats: stats
        }

  @spec status(ifname) :: {:ok, status}
  def status(ifname) do
    GenServer.call(__MODULE__, {:status, ifname})
  end

  @spec ifup(ifname) :: :ok
  def ifup(ifname) do
    GenServer.call(__MODULE__, {:ifup, ifname})
  end

  @spec ifdown(ifname) :: :ok
  def ifdown(ifname) do
    GenServer.call(__MODULE__, {:ifdown, ifname})
  end

  @type ip_address :: binary

  @typedoc "Interface settings"
  @type settings :: %{
          ipv4_address: ip_address,
          ipv4_broadcast: ip_address,
          ipv4_gateway: ip_address,
          ipv4_subnet_mask: ip_address
        }

  @spec settings(ifname) :: {:ok, settings}
  def settings(ifname) do
    GenServer.call(__MODULE__, {:settings, ifname})
  end

  @spec setup(ifname, Keyword.t() | options) :: :ok
  def setup(ifname, options) when is_list(options) do
    setup(ifname, :maps.from_list(options))
  end

  def setup(ifname, options) when is_map(options) do
    GenServer.call(__MODULE__, {:setup, ifname, options})
  end

  def init([]) do
    Logger.info("Start Network Interface Worker")
    executable = :code.priv_dir(:nerves_network_interface) ++ '/netif'
    port = Port.open({:spawn_executable, executable}, [{:packet, 2}, :use_stdio, :binary])
    {:ok, %Nerves.NetworkInterface.Worker{port: port}}
  end

  def handle_call(:interfaces, _from, state) do
    response = call_port(state, :interfaces, [])
    {:reply, response, state}
  end

  def handle_call({:status, ifname}, _from, state) do
    response = call_port(state, :status, ifname)
    {:reply, response, state}
  end

  def handle_call({:ifup, ifname}, _from, state) do
    response = call_port(state, :ifup, ifname)
    {:reply, response, state}
  end

  def handle_call({:ifdown, ifname}, _from, state) do
    response = call_port(state, :ifdown, ifname)
    {:reply, response, state}
  end

  def handle_call({:setup, ifname, options}, _from, state) do
    response = call_port(state, :setup, {ifname, options})
    {:reply, response, state}
  end

  def handle_call({:settings, ifname}, _from, state) do
    response = call_port(state, :settings, ifname)
    {:reply, response, state}
  end

  def handle_cast(:stop, state) do
    {:stop, :normal, state}
  end

  def handle_info({_, {:data, <<?n, message::binary>>}}, state) do
    {notif, data} = :erlang.binary_to_term(message)
    Logger.info("nerves_network_interface received #{inspect(notif)} and #{inspect(data)}")

    Registry.dispatch(Nerves.NetworkInterface, data.ifname, fn entries ->
      for {pid, _} <- entries do
        send(pid, {Nerves.NetworkInterface, notif, data})
      end
    end)

    {:noreply, state}
  end

  def handle_info({_, {:exit_status, _}}, state) do
    {:stop, :unexpected_exit, state}
  end

  @typedoc false
  @type port_resp :: any | no_return

  @typedoc "Command to be sent to the port."
  @type command :: :ifup | :ifdown | :setup | :settings | :interfaces

  @typedoc "Arguments for a command"
  @type command_arguments :: {ifname, options} | ifname
  # Private helper functions
  @spec call_port(t, command, command_arguments) :: port_resp
  defp call_port(state, command, arguments) do
    msg = {command, arguments}
    send(state.port, {self(), {:command, :erlang.term_to_binary(msg)}})

    receive do
      {_, {:data, <<?r, response::binary>>}} ->
        :erlang.binary_to_term(response)
    after
      4_000 ->
        # Not sure how this can be recovered
        exit(:port_timed_out)
    end
  end
end
