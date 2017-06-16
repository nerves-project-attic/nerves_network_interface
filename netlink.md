# Notes for experimenting with rtnetlink

## Change the MAC address on eth0
```
iex> Nerves.NetworkInterface.send [{:newlink, %{ifname: "eth0", mac_address: "e0:db:55:e7:8b:51"}}]
```

Check it out with ip:

```bash
$ ip link
```

## Bring an interface up

```
iex> Nerves.NetworkInterface.send [{:newlink, %{ifname: "eth0", is_up: true}}]
```

## Bring an interface down

```
iex> Nerves.NetworkInterface.send [{:newlink, %{ifname: "eth0", is_up: false}}]
```

## Add an IP address

Set the IP address on "eth0" to "192.168.1.14". "eth0" is interface index 2 below.

```
iex> Nerves.NetworkInterface.send [{:newaddr, %{index: 2, family: :af_inet, prefixlen: 24, local: "192.168.1.14", address: "192.168.1.14"}}]
```

This also appears to be the minimal set needed to set the IP address. This doesn't set the broadcast address, so it's probably good to really do this:

```
iex> Nerves.NetworkInterface.send [{:newaddr, %{index: 2, family: :af_inet, prefixlen: 24, local: "192.168.1.14", address: "192.168.1.14", broadcast: "192.168.1.255"}}]
```

To see what happens, run this at the commandline:
```
$ ip address show dev eth0
```

You can have multiple addresses per Ethernet interface.

## Delete all IP addresses on an interface

In this case, "eth0" is interface index 2.

```
iex> Nerves.NetworkInterface.send [{:deladdr, %{index: 2, family: :af_inet, prefixlen: 24}]
```

## Delete one IP addresses on an interface

I don't know how to delete just one. It seems like deladdr ignores the "local" and "address" fields.

## Set the default gateway

```bash
# List routes
ip route

# Manually add route via ip command
sudo ip route add default via 192.168.1.1 dev wlan0 proto static

# Manually delete route via ip command
sudo ip route del default via 192.168.1.1 dev wlan0

# See the raw netlink message that the ip command sends
sudo strace -s256 ip route add default via 192.168.1.1 dev wlan0 proto static
```

```
iex> NI.send [newroute: %{family: :af_inet, gateway: "192.168.1.1", oif: 3, protocol: :static, scope: :universe, table: :main, type: :unicast}]

```
