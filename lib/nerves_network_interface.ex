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

  @doc """
  Return the list of network interfaces on this machine.
  """
  defdelegate interfaces, to: Nerves.NetworkInterface.Worker

  @doc """
  Return link-level status on the specified interface.

  For example, `Nerves.NetworkInterface.status pid, "eth0"` could return:

      {:ok,
       %{ifname: "eth0", index: 2, is_broadcast: true, is_lower_up: true,
         is_multicast: true, is_running: true, is_up: true,
         mac_address: <<224, 219, 85, 231, 139, 93>>,
         mac_broadcast: <<255, 255, 255, 255, 255, 255>>, mtu: 1500, operstate: :up,
         stats: %{collisions: 0, multicast: 427, rx_bytes: 358417207, rx_dropped: 0,
           rx_errors: 0, rx_packets: 301021, tx_bytes: 22813761, tx_dropped: 0,
           tx_errors: 0, tx_packets: 212480}, type: :ethernet}}

  If the interface doesn't exist, `{:error, :enodev}` is returned.
  """
  defdelegate status(ifname), to: Nerves.NetworkInterface.Worker

  @doc """
  Bring the specified interface up.

  Returns `:ok` on success or `{:error, reason}` if an error occurs.
  """
  defdelegate ifup(ifname), to: Nerves.NetworkInterface.Worker

  @doc """
  Bring the specified interface down.

  Returns `:ok` on success or `{:error, reason}` if an error occurs.
  """
  defdelegate ifdown(ifname), to: Nerves.NetworkInterface.Worker

  @doc """
  Return the IP configuration for the specified interface as a map. See
  `setup/3` for options.

  Returns `{:ok, config}` on success or `{:error, reason}` if an error occurs.
  """
  defdelegate settings(ifname), to: Nerves.NetworkInterface.Worker

  @doc """
  Set IP settings for the specified interface. The following options are
  available:

    * `:ipv4_address` - the IPv4 address of the interface
    * `:ipv4_broadcast` - the IPv4 broadcast address for the interface
    * `:ipv4_subnet_mask` - the IPv4 subnet mask
    * `:ipv4_gateway` - the default gateway

  Options can be specified either as a keyword list or as a map.

  Returns `:ok` on success or `{:error, reason}` if an error occurs.
  """
  defdelegate setup(ifname, options), to: Nerves.NetworkInterface.Worker
end
