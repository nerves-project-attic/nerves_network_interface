# Nerves.NetworkInterface
[![CircleCI](https://circleci.com/gh/nerves-project/nerves_network_interface.svg?style=svg)](https://circleci.com/gh/nerves-project/nerves_network_interface)

This package enables Elixir applications to configure, get the status of,
and listen to events from LAN and WiFi network interfaces. It is not meant
as a full-featured network interface management library and lacks a majority
of the features available. However, its goal is to support the set of
networking parameters that make sense for end systems in home, office, and
industrial environments. This includes:

 * Enumerating available interfaces
 * Reporting when new interfaces appear and disappear (USB WiFi dongle insertion/removal)
 * Querying link-level interface status and statistics
 * Reporting link-level interface status changes
 * Configuring IP addresses, subnets, gateways, etc.
 * Bringing interfaces up and down

Currently only IPv4 is supported. If you use IPv6, I'd be interested in
working with you to integrate IPv6 support.

## Nerves.NetworkInterface or [Nerves.Network](https://github.com/nerves-project/nerves_network)?

The purpose of `Nerves.NetworkInterface` is to handles low level access to Linux
network interfaces. `Nerves.Network` depends this project.

## Prerequisites

This module requires [libmnl](http://netfilter.org/projects/libmnl/) to build.
If you're running a Debian-based system, you can get it by running:

```bash
sudo apt-get install libmnl-dev
```

Nerves includes `libmnl` by default.

When not crosscompiling, be aware that the Makefile runs `sudo` to set the
permissions on the `priv/netif` binary, so you'll be asked your password towards
the end. If you do not require additional privileges to modify network
interfaces on your system, you can bypass the calls to sudo by setting the
SUDO environment variable to `true`. I.e., `SUDO=true make`.

## Installation
Add `nerves_network_interface` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [{:nerves_network_interface, "~> 0.3.2"}]
end
```

## Permissions

If an application just needs to get information about LAN interfaces,
this library does not require any additional privileges. If it is necessary
to modify the network interfaces, the same privilege needed to run applications
like `ifconfig` and `ip` will be needed. This can be accomplished by setting
the `netif` binary to be setuid root. E.g.,

    chown root:root priv/netif
    chmod +s priv/netif

Keep in mind that running `setuid` on the netif port binary could have
security implications in your system. The `Makefile` will automatically call
`sudo` to do this, but that can be disabled.

If you do not require additional privileges to modify network
interfaces on your system, you can bypass the calls to `sudo` by setting the
SUDO environment variable to `true`. I.e., `SUDO=true make`.

## Running

Start `iex`:

```bash
$ iex -S mix
```

The `Nerves.NetworkInterface` application will start automatically.

To see which interfaces are available, call `Nerves.NetworkInterface.interfaces\0`:

```elixir
iex> Nerves.NetworkInterface.interfaces
["lo", "eth0", "wlan0"]
```

To get link-level status information and statistics on an interface look inside
SystemRegistry:

```elixir
iex> SystemRegistry.match(%{state: %{network_interface: :_}})
%{
  state: %{
    network_interface: %{
      "eth0" => %{
        ifname: "eth0",
        index: 4,
        is_broadcast: true,
        is_lower_up: false,
        is_multicast: true,
        is_running: false,
        is_up: true,
        mac_address: "1c:1b:0d:0f:91:8d",
        mac_broadcast: "ff:ff:ff:ff:ff:ff",
        mtu: 1500,
        operstate: :down,
        stats: %{
          collisions: 0,
          multicast: 0,
          rx_bytes: 0,
          rx_dropped: 0,
          rx_errors: 0,
          rx_packets: 0,
          tx_bytes: 0,
          tx_dropped: 0,
          tx_errors: 0,
          tx_packets: 0
        },
        type: :ethernet
      }
    }
  }
}
```

Polling `Nerves.NetworkInterface` for status isn't that great, so it's possible to
register to events via [`SystemRegistry`](https://github.com/nerves-project/system_registry)

The following example shows how to view events at the prompt:

```elixir
iex> SystemRegistry.register()
{:ok, %{
   state: %{
     network_interface: %{
       "eth0" => %{
         ifname: "eth0",
         index: 4,
         is_broadcast: true,
         is_lower_up: false,
         is_multicast: true,
         is_running: false,
         is_up: true,
         mac_address: "1c:1b:0d:0f:91:8d",
         mac_broadcast: "ff:ff:ff:ff:ff:ff",
         mtu: 1500,
         operstate: :down,
         stats: %{
           collisions: 0,
           multicast: 0,
           rx_bytes: 0,
           rx_dropped: 0,
           rx_errors: 0,
           rx_packets: 0,
           tx_bytes: 0,
           tx_dropped: 0,
           tx_errors: 0,
           tx_packets: 0
         },
         type: :ethernet
       }
     }
   }
 }
}
# Plug Ethernet cable in
iex> flush()
{:ok, %{
  state: %{
    network_interface: %{
      "eth0" => %{
        ifname: "eth0",
        index: 4,
        is_broadcast: true,
        is_lower_up: true,
        is_multicast: true,
        is_running: true,
        is_up: true,
        mac_address: "1c:1b:0d:0f:91:8d",
        mac_broadcast: "ff:ff:ff:ff:ff:ff",
        mtu: 1500,
        operstate: :up,
        stats:%{
          collisions: 0,
          multicast: 14,
          rx_bytes: 3061718,
          rx_dropped: 0,
          rx_errors: 0,
          rx_packets: 7802,
          tx_bytes: 1273557,
          tx_dropped: 0,
          tx_errors: 0,
          tx_packets: 5068
        }
        type: :ethernet
      }
    }
  }
 }
}
```

IP configuration is also stored in SystemRegistry.

```elixir
%{
  state: %{
    network_interface: %{
      "eth0" => %{
        ifname: "eth0",
        index: 4,
        is_broadcast: true,
        is_lower_up: false,
        is_multicast: true,
        is_running: false,
        is_up: true,
        mac_address: "1c:1b:0d:0f:91:8d",
        mac_broadcast: "ff:ff:ff:ff:ff:ff",
        mtu: 1500,
        operstate: :down,
        addresses: %{
          "192.168.86.111" => %{
            address: "192.168.86.111",
            broadcast: "192.168.86.255",
            family: :af_inet,
            local: "192.168.86.111",
            prefixlen: 24,
            scope: 0
          },
          "fe80::8e19:f402:9be0:1437" => %{
            address: "fe80::8e19:f402:9be0:1437",
            family: :af_inet6,
            prefixlen: 64,
            scope: 253
          }
        },
        stats: %{
          collisions: 0,
          multicast: 0,
          rx_bytes: 0,
          rx_dropped: 0,
          rx_errors: 0,
          rx_packets: 0,
          tx_bytes: 0,
          tx_dropped: 0,
          tx_errors: 0,
          tx_packets: 0
        },
        type: :ethernet
      }
    }
  }
}
```

To setting IP addresses and other configuration, just call
`Nerves.NetworkInterface.setup/2` using keyword parameters or a map with what you'd like
to set. The following example uses keyword parameters:

```elixir
iex> Nerves.NetworkInterface.setup "eth0", ipv4_address: "192.168.25.200", ipv4_subnet_mask: "255.255.255.0")
:ok
```

If you get an error, check that you are running Elixir with sufficient privilege
to modify network interfaces or make the `netif` binary setuid root.

The library accepts both Erlang strings and Elixir strings. It,
however, only returns Elixir strings.

To enable or disable an interface, you can do so with `Nerves.NetworkInterface.ifup/1` and
`Nerves.NetworkInterface.ifdown/1`. As you would expect, these require privilege to run:

```elixir
iex> Nerves.NetworkInterface.ifdown "eth0"
:ok
```

## Testing
To run tests you will need a linux machine with `ip`, `iproute2` and `sudo` access. See (#Permissions)[Permissions] for more info.
by default `mix test` does not include `external`. To run all the unit tests you should do `mix test --include external`

## Licensing

This package is licensed under the Apache 2.0 license.
