defmodule RtnetlinkTest do
  use ExUnit.Case
  alias Nerves.NetworkInterface.Rtnetlink, as: R

  test "newlink returns system registry update tuple" do

    # The idea here is that this module knows how to translate rtnetlink messages
    # into the appropriate system registry key value pairs to pass to update.
    #
    # I probably will want to change the method call to
    #
    #  R.translate(state, :newlink, %{...})
    #
    # and have it return something like {newstate, :update, {key, value}} or {newstate, :delete, key},
    # but I haven't gotten there yet.
    #
    # State has to be maintained between calls for the address and route
    # updates, since rtnetlink doesn't provide enough information in its
    # updates. On initialization, I'll dump all addresses and routes to
    # build up the initial state.
    #
    ifaces = []
    {:ok, {_, t}} = R.newlink(ifaces, %{ifname: "wlan0", index: 3, is_broadcast: true})
    iface = get_in(t.updates, [:state, :network_interface, "wlan0"])
    assert iface == %{ifname: "wlan0", is_broadcast: true, index: 3}
  end

  test "first newaddr returns system registry update with an address" do
    ifaces = [%{ifname: "wlan0", index: 3, is_broadcast: true}]
    {:ok, {_ifaces, t}} = R.newaddr(ifaces, %{address: "192.168.1.15", index: 3})
    address = get_in(t.updates, [:state, :network_interface, "wlan0", :addresses, "192.168.1.15"])
    assert address == %{address: "192.168.1.15"}
  end

  test "newaddr drops label attribute" do
    ifaces = [%{ifname: "wlan0", index: 3, is_broadcast: true}]
    {:ok, {_ifaces, t}} = R.newaddr(ifaces, %{address: "192.168.1.15", index: 3, label: "wlan0"})
    address = get_in(t.updates, [:state, :network_interface, "wlan0", :addresses, "192.168.1.15"])
    assert address == %{address: "192.168.1.15"}
  end

  test "newaddr adds all attributes" do
    ifaces = [%{ifname: "wlan0", index: 3, is_broadcast: true}]
    {:ok, {_ifaces, t}} = R.newaddr(ifaces, %{address: "192.168.1.15", broadcast: "192.168.1.255", family: :af_inet, index: 3, label: "wlan0", local: "192.168.1.15", prefixlen: 24, scope: 0})
    address = get_in(t.updates, [:state, :network_interface, "wlan0", :addresses, "192.168.1.15"])
    assert address == %{address: "192.168.1.15", broadcast: "192.168.1.255", family: :af_inet, local: "192.168.1.15", prefixlen: 24, scope: 0}
  end

  test "deladdr returns a system registry key to delete" do
    ifaces = [%{ifname: "wlan0", index: 3, is_broadcast: true}]
    {:ok, {ifaces, _t}} = R.newaddr(ifaces, %{address: "fe80::863a:4bff:fe11:95f6", family: :af_inet6, index: 3, prefixlen: 64, scope: 253})
    {:ok, {_ifaces, t}} = R.deladdr(ifaces, %{address: "fe80::863a:4bff:fe11:95f6", family: :af_inet6, index: 3, prefixlen: 64, scope: 253})
    assert Enum.any?(t.deletes, & &1.node == [:state, :network_interface, "wlan0", :addresses, "fe80::863a:4bff:fe11:95f6"])
  end

  test "interface can support multiple addresses" do
    ifaces = [%{ifname: "wlan0", index: 3, is_broadcast: true}]
    {:ok, {ifaces, _t}} = R.newaddr(ifaces, %{address: "192.168.1.15", index: 3})
    {:ok, {ifaces, _t}} = R.newaddr(ifaces, %{address: "fe80::863a:4bff:fe11:95f6", index: 3})
    iface = Enum.find(ifaces, & &1.ifname == "wlan0")
    assert Enum.any?(iface.addresses, fn({addr, _}) -> addr == "192.168.1.15" end)
    assert Enum.any?(iface.addresses, fn({addr, _}) -> addr == "fe80::863a:4bff:fe11:95f6" end)
  end


  test "newroute returns system registry default gateway update" do
    ifaces = [%{ifname: "wlan0", index: 3, is_broadcast: true}]
    {:ok, {_ifaces, t}} = R.newroute(ifaces, %{oif: 3, gateway: "192.168.1.1"})
    routes = get_in(t.updates, [:state, :network_interface, "wlan0", :routes])
    gateway = get_in(t.updates, [:state, :network_interface, "wlan0", :gateway])
    assert routes == [%{gateway: "192.168.1.1"}]
    assert gateway == "192.168.1.1"
  end

  test "newroute without a gateway" do
    ifaces = [%{ifname: "wlan0", index: 3, is_broadcast: true}]

    {:ok, {_, t}} = R.newroute(ifaces, %{dst: "192.168.1.0", family: :af_inet, oif: 3, prefsrc: "192.168.1.15", priority: 600, protocol: :kernel, scope: :link, table: :main, tos: 0, type: :unicast})
    gateway = get_in(t.updates, [:state, :network_interface, "wlan0", :gateway])
    assert gateway == nil
  end

  test "dellink returns a system registry key to delete" do
    # NEED TO GET A USB WIFI DONGLE TO CAPTURE MESSAGE: assert R.dellink()
  end
end
