# Copyright 2014 LKC Technologies, Inc.
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
  use GenServer
  require Logger

  alias SystemRegistry, as: SR
  alias Nerves.NetworkInterface.Rtnetlink

  @moduledoc false

  defstruct port: nil,
            requests: [],
            interfaces: []

  def start_link() do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  def stop() do
    GenServer.cast(__MODULE__, :stop)
  end

  def refresh() do
    GenServer.call(__MODULE__, :refresh)
  end

  def ifup(ifname) do
    GenServer.call(__MODULE__, {:ifup, ifname})
  end

  def ifdown(ifname) do
    GenServer.call(__MODULE__, {:ifdown, ifname})
  end

  def settings(ifname) do
    GenServer.call(__MODULE__, {:settings, ifname})
  end

  def setup(ifname, options) when is_list(options) do
    setup(ifname, :maps.from_list(options))
  end
  def setup(ifname, options) when is_map(options) do
    GenServer.call(__MODULE__, {:setup, ifname, options})
  end

  def init([]) do
    Logger.info "Start Network Interface Worker"
    executable = :code.priv_dir(:nerves_network_interface) ++ '/netif'
    port = Port.open({:spawn_executable, executable},
    [{:packet, 2}, :use_stdio, :binary])
    { :ok, %Nerves.NetworkInterface.Worker{port: port} }
  end

  def handle_call(:refresh, _from, state) do
    response = call_port(state, :refresh, [])
    {:reply, response, state }
  end
  def handle_call({:ifup, ifname}, _from, state) do
    response = call_port(state, :ifup, ifname)
    {:reply, response, state }
  end
  def handle_call({:ifdown, ifname}, _from, state) do
    response = call_port(state, :ifdown, ifname)
    {:reply, response, state }
  end
  def handle_call({:setup, ifname, options}, _from, state) do
    response = call_port(state, :setup, {ifname, options})
    {:reply, response, state }
  end
  def handle_call({:settings, ifname}, _from, state) do
    response = call_port(state, :settings, ifname)
    {:reply, response, state }
  end

  def handle_cast(:stop, state) do
    {:stop, :normal, state}
  end

  def handle_info({_, {:data, <<?n, message::binary>>}}, state) do
    msg = :erlang.binary_to_term(message)
    Logger.info "nerves_network_interface received #{inspect msg}"
    {:ok, t, interfaces} = Rtnetlink.decode(msg, state.interfaces)
    IO.inspect t, label: "T"
    IO.inspect interfaces, label: "If"
    SR.commit(t) |> IO.inspect
    {:noreply, %{state | interfaces: interfaces}}

  end
  def handle_info({_, {:exit_status, _}}, state) do
    {:stop, :unexpected_exit, state}
  end

  # Private helper functions
  defp call_port(state, command, arguments) do
    msg = {command, arguments}
    send state.port, {self(), {:command, :erlang.term_to_binary(msg)}}
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
