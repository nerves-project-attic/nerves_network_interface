defmodule RtnetlinkTest do
  use ExUnit.Case
  alias Nerves.NetworkInterface.Rtnetlink, as: R

  test "newlink returns system registry update tuple" do
    state = %{}

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

    {newstate, k, v} = R.newlink(state, %{ifname: "wlan0", index: 3, is_broadcast: true})

    assert k == [:state, :network_interface, 3]
    assert v == %{ifname: "wlan0", is_broadcast: true}
  end

  test "first newaddr returns system registry update with an address" do
    state = %{}
    {newstate, k, v} = R.newaddr(state, %{address: "192.168.1.15", index: 3})

    assert {k, v} == {[:state, :network_interface, 3, :addresses, 0], %{address: "192.168.1.15"}}
  end

  test "newaddr drops label attribute" do
    state = %{}
    {newstate, k, v} = R.newaddr(state, %{address: "192.168.1.15", index: 3, label: "wlan0"})

    assert {k, v} == {[:state, :network_interface, 3, :addresses, 0], %{address: "192.168.1.15"}}
  end

  test "newaddr adds all attributes" do
    state = %{}

    {newstate, k, v} = R.newaddr(state, %{address: "192.168.1.15", broadcast: "192.168.1.255", family: :af_inet, index: 3, label: "wlan0", local: "192.168.1.15", prefixlen: 24, scope: 0})

    assert {k, v} ==
      {[:state, :network_interface, 3, :addresses, 0], %{address: "192.168.1.15", broadcast: "192.168.1.255", family: :af_inet, local: "192.168.1.15", prefixlen: 24, scope: 0}}
  end

  test "deladdr returns a system registry key to delete" do
    state = %{}
    {state, _, _} = R.newaddr(state, %{address: "fe80::863a:4bff:fe11:95f6", family: :af_inet6, index: 3, prefixlen: 64, scope: 253})
    {state, k} = R.deladdr(state, %{address: "fe80::863a:4bff:fe11:95f6", family: :af_inet6, index: 3, prefixlen: 64, scope: 253})

    assert k == [:state, :network_interface, 3, :addresses, 0]
  end

  test "second newaddr returns system registry update with index 1" do
    state = %{}
    {state, _, _} = R.newaddr(state, %{address: "192.168.1.15", index: 3})
    {state, k, v} = R.newaddr(state, %{address: "fe80::863a:4bff:fe11:95f6", index: 3})

    assert {k, v} == {[:state, :network_interface, 3, :addresses, 1], %{address: "fe80::863a:4bff:fe11:95f6"}}
  end


  test "newroute returns system registry default gateway update" do
    state = %{}
    {state, k, v} = R.newroute(state, %{oif: 3, gateway: "192.168.1.1"})

    assert {k, v} ==
      {[:state, :network_interface, 3, :gateways, "192.168.1.1"], %{}}
  end
  test "newroute without a gateway does nothing" do
    state = %{}

    {state, k, v} = R.newroute(state, %{dst: "192.168.1.0", family: :af_inet, oif: 3, prefsrc: "192.168.1.15", priority: 600, protocol: :kernel, scope: :link, table: :main, tos: 0, type: :unicast})

    assert {k, v} == {:none, :none}
  end

  test "dellink returns a system registry key to delete" do
    # NEED TO GET A USB WIFI DONGLE TO CAPTURE MESSAGE: assert R.dellink()
  end
end
