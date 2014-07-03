# NetBasic

[![Build Status](https://travis-ci.org/fhunleth/net_basic.svg)](https://travis-ci.org/fhunleth/net_basic)

This package enables Elixir applications to configure, get the status of,
and listen to events from LAN and WiFi network interfaces. It is not meant
as a full-featured network interface management library and lacks a majority
of the features available. However, its goal is to support the set of
networking parameters that make sense for end systems in the majority
of home and office environments. This includes:

 * Enumerating available interfaces
 * Querying link-level interface status
 * Reporting link-level interface status changes
 * Getting link level statistics
 * Getting and setting IP addresses, subnets, gateways, etc.
 * Bringing interfaces up and down

Currently only IPv4 is supported. If you use IPv6, I'd be interested in
working with you to integrate IPv6 support.

## Building

This module requires [libmnl](http://netfilter.org/projects/libmnl/) to build.
If you're running a Debian-based system, you can get it by running:

    sudo apt-get install libmnl-dev

If building standalone, just run `make`. To pull in as a dependency to your
application, add the following line to your `mix.exs` deps list:

     {:net_basic, github: "fhunleth/net_basic.ex"}

## Permissions

If an application just needs to get information about the LAN interfaces,
this library does not require any additional privileges. If it is necessary
to modify the network interfaces, the same privilege needed to run applications
like `ifconfig` and `ip` will be needed. This can be accomplished by setting
the `net_basic` binary to be setuid root. E.g.,

    chown root:root priv/net_basic
    chmod +s priv/net_basic

Keep in mind that running `setuid` on the net_basic port binary could have
security implications in your system.

## Running

The first step is to create a `NetBasic` process. By default, `NetBasic` creates
a GenEvent process for notifying interface change events, but you can supply one
as an argument to `NetBasic.start_link/1`.

    iex> {:ok, pid} = NetBasic.start_link
    {:ok, #PID<0.82.0>}

To see which interfaces are available, call `NetBasic.interfaces\0`:

    iex> NetBasic.interfaces pid
	['lo', 'eth0', 'wlan0']

To get link-level status information and statistics on an interface, call
`NetBasic.status/2`:

    iex> NetBasic.status(pid, "eth0")
    %{ifname: 'eth0', index: 2, is_broadcast: true, is_lower_up: true,
      is_multicast: true, is_running: true, is_up: true,
      mac_address: <<224, 219, 85, 231, 139, 93>>,
      mac_broadcast: <<255, 255, 255, 255, 255, 255>>, mtu: 1500, operstate: [6],
      stats: %{collisions: 0, multicast: 7, rx_bytes: 2561254, rx_dropped: 0,
        rx_errors: 0, rx_packets: 5301, tx_bytes: 944159, tx_dropped: 0,
        tx_errors: 0, tx_packets: 3898}, type: :ethernet}

Polling `NetBasic` for status isn't that great, so it's possible to
register a `GenEvent` with `NetBasic`. If you don't supply one in the call
to `start_link`, one is automatically created and available via `NetBasic.event_manager/1`. The
following example shows how to view events at the prompt:

    iex> defmodule Forwarder do
    ...>  use GenEvent
    ...>  def handle_event(event, parent) do
    ...>    send parent, event
    ...>    {:ok, parent}
    ...>  end
    ...> end
    iex> NetBasic.event_manager(pid) |> GenEvent.add_handler(Forwarder, self())
    :ok
    iex> flush
    :ok
    # Plug Ethernet cable in
    iex> flush
    {:net_basic, #PID<0.62.0>, :ifchanged,
     %{ifname: 'eth0', index: 2, is_broadcast: true, is_lower_up: true,
       is_multicast: true, is_running: true, is_up: true,
       mac_address: <<224, 219, 85, 231, 139, 93>>,
       mac_broadcast: <<255, 255, 255, 255, 255, 255>>, mtu: 1500, operstate: [6],
       stats: %{collisions: 0, multicast: 14, rx_bytes: 3061718, rx_dropped: 0,
         rx_errors: 0, rx_packets: 7802, tx_bytes: 1273557, tx_dropped: 0,
         tx_errors: 0, tx_packets: 5068}, type: :ethernet}}

To get the IP configuration for an interface, call `NetBasic.get_config/2`:

    iex> NetBasic.get_config(pid, "eth0")
    %{ipv4_address: '192.168.25.114', ipv4_broadcast: '192.168.25.255',
      ipv4_gateway: '192.168.25.5', ipv4_subnet_mask: '255.255.255.0'}

To setting IP addresses and other configuration, just call
`NetBasic.set_config/3` using keyword parameters or a map with what you'd like
to set. The following example uses keyward parameters:

    iex> NetBasic.set_config(pid, "eth0", ipv4_address: "192.168.25.200",
    ...> ipv4_subnet_mask: "255.255.255.0")
    :ok

If you get an error, check that you are running Elixir with sufficient privilege
to modify network interfaces or make the `net_basic` binary setuid root.

Note that the library accepts both Erlang strings and Elixir strings. It,
however, only returns Erlang strings.

To enable or disable an interface, you can do so with `NetBasic.ifup/1` and
`NetBasic.ifdown/1`. As you would expect, these require privilege to run:

    iex> NetBasic.ifdown(pid, "eth0")
    :ok

## Licensing

This package is licensed under the Apache 2.0 license.
