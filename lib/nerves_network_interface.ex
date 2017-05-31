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
  Refresh the current state of all interfaces.
  """
  defdelegate refresh(), to: Nerves.NetworkInterface.Worker

  @doc """
  Send a message through the interface

  Returns `:ok` on success or `{:error, reason}` if an error occurs.
  """
  defdelegate send(msg), to: Nerves.NetworkInterface.Worker

end
