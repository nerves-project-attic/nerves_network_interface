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

  defstruct port: nil,
            manager: nil,
            requests: []

  def start_link() do
    { :ok, manager } = GenEvent.start_link
    GenServer.start_link(__MODULE__, manager, name: __MODULE__)
  end

  def event_manager() do
    GenServer.call(__MODULE__, :event_manager)
  end

  def stop() do
    GenServer.cast(__MODULE__, :stop)
  end

  def interfaces() do
    GenServer.call(__MODULE__, :interfaces)
  end

  def status(ifname) do
    GenServer.call(__MODULE__, {:status, ifname})
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

  def init(event_manager) do
    executable = :code.priv_dir(:nerves_networkinterface) ++ '/netif'
    port = Port.open({:spawn_executable, executable},
    [{:packet, 2}, :use_stdio, :binary])
    { :ok, %Nerves.NetworkInterface.Worker{port: port, manager: event_manager} }
  end

  def handle_call(:interfaces, _from, state) do
    response = call_port(state, :interfaces, [])
    {:reply, response, state }
  end
  def handle_call({:status, ifname}, _from, state) do
    response = call_port(state, :status, ifname)
    {:reply, response, state }
  end
  def handle_call(:event_manager, _from, state) do
    {:reply, state.manager, state}
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
    {notif, data} = :erlang.binary_to_term(message)
    Logger.info "net_basic received #{inspect notif} and #{inspect data}"
    GenEvent.notify(state.manager, {:net_basic, self, notif, data})
    {:noreply, state}
  end
  def handle_info({_, {:exit_status, _}}, state) do
    {:stop, :unexpected_exit, state}
  end

  # Private helper functions
  defp call_port(state, command, arguments) do
    msg = {command, arguments}
    send state.port, {self, {:command, :erlang.term_to_binary(msg)}}
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
