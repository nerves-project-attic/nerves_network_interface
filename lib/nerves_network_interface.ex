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
defmodule Nerves.NetworkInterface do
  @moduledoc """
  This module exposes a simplified view of Linux network configuration to
  applications.

  ## Overview

  This module should be added to a supervision tree or started via the
  `start_link/0` call. Once running, the module provides functions to
  list network interfaces, modify their state (up or down), get statistics
  and set IP networking parameters. Network events, such as when an Ethernet
  cable is connected, are reported via a Registry Nerves.NetworkInterface.

  ## Privilege

  The functions that return information don't require that the `Nerves.NetworkInterface`'s
  associated port process has privileged access to the system. If you
  need to change any parameters or bring up or down an interface, you should
  ensure that the port process is running as a privileged user.
  """

  use GenServer
  require Logger

  alias SystemRegistry, as: SR
  alias Nerves.NetworkInterface.{Rtnetlink, Config}

  defstruct port: nil,
            requests: [],
            interfaces: [],
            config: %{}

  @typedoc "Interface name"
  @type ifname :: String.t()

  @typedoc false
  @type state :: %__MODULE__{
          port: port,
          requests: [any],
          interfaces: [ifname],
          config: map
        }

  @doc false
  @spec start_link() :: GenServer.on_start()
  def start_link() do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @doc false
  @spec stop :: :ok
  def stop() do
    GenServer.cast(__MODULE__, :stop)
  end

  @doc "Get a list of all interfaces."
  @spec interfaces() :: [ifname]
  def interfaces() do
    GenServer.call(__MODULE__, :interfaces)
  end

  @doc """
  Refresh the current state of all interfaces.
  """
  @spec refresh() :: :ok
  def refresh() do
    GenServer.call(__MODULE__, :refresh)
  end

  @doc """
  Send a message through the interface

  Returns `:ok` on success or `{:error, reason}` if an error occurs.
  """
  @spec send(any) :: :ok | {:error, any}
  def send(msg) do
    GenServer.call(__MODULE__, {:send, msg})
  end

  def init([]) do
    Logger.info("Start Network Interface Worker")

    executable = :code.priv_dir(:nerves_network_interface) ++ '/netif'
    port = Port.open({:spawn_executable, executable}, [{:packet, 2}, :use_stdio, :binary])
    s = %Nerves.NetworkInterface{port: port}

    call_port(s.port, :refresh, [])

    SR.register()
    {:ok, s}
  end

  def handle_call(:interfaces, _from, s) do
    {:reply, s.interfaces, s}
  end

  def handle_call(:refresh, _from, %__MODULE__{} = s) do
    response = call_port(s.port, :refresh, [])
    {:reply, response, s}
  end

  def handle_call({:send, msg}, _from, %__MODULE__{} = s) do
    response = call_port(s.port, :send, msg)
    {:reply, response, s}
  end

  def handle_cast(:stop, state) do
    {:stop, :normal, state}
  end

  def handle_info({:system_registry, :global, registry}, %__MODULE__{} = s) do
    {config, msg} = Config.system_registry(registry, s.config, s.interfaces)
    send_msg(msg, s.port)
    {:noreply, %{s | config: config}}
  end

  def handle_info({_, {:data, <<?n, message::binary>>}}, state) do
    msg = :erlang.binary_to_term(message)
    Logger.info("nerves_network_interface received #{inspect(msg)}")
    {:ok, t, interfaces} = Rtnetlink.decode(msg, state.interfaces)
    SR.commit(t)
    {:noreply, %{state | interfaces: interfaces}}
  end

  def handle_info({_, {:exit_status, _}}, state) do
    {:stop, :unexpected_exit, state}
  end

  # Private helper functions
  @typedoc false
  @type port_resp :: any | no_return

  @typedoc "Command to be sent to the port."
  @type command :: :ifup | :ifdown | :setup | :settings | :interfaces | :refresh | :send

  @typedoc "Arguments for a command"
  @type command_arguments :: Keyword.t()
  # Private helper functions
  @spec call_port(port, command, command_arguments) :: port_resp
  defp call_port(port, command, arguments) when is_port(port) do
    msg = {command, arguments}
    send(port, {self(), {:command, :erlang.term_to_binary(msg)}})

    receive do
      {_, {:data, <<?r, response::binary>>}} ->
        :erlang.binary_to_term(response)
    after
      4_000 ->
        # Not sure how this can be recovered
        exit(:port_timed_out)
    end
  end

  defp send_msg([], _port), do: :noop

  defp send_msg(msg, port) do
    call_port(port, :send, msg)
  end
end
