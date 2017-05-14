defmodule RtnetlinkTest do
  use ExUnit.Case
  alias Nerves.NetworkInterface.Rtnetlink, as: R

  test "newlink returns system registry update" do
    assert R.newlink(%{ifname: "wlan0", index: 3, is_broadcast: true}) ==
      {[:state, :network_interface, 3], %{ifname: "wlan0", is_broadcast: true}}
  end

  test "newaddr returns system registry update" do
    assert R.newaddr(%{address: "192.168.1.15", index: 3}) ==
      {[:state, :network_interface, 3, :addresses, "192.168.1.15"], %{}}
  end
  test "newaddr drops label attribute" do
    assert R.newaddr(%{address: "192.168.1.15", index: 3, label: "wlan0"}) ==
      {[:state, :network_interface, 3, :addresses, "192.168.1.15"], %{}}
  end
  test "newaddr adds all attributes" do
    assert R.newaddr(%{address: "192.168.1.15", broadcast: "192.168.1.255", family: :af_inet, index: 3, label: "wlan0", local: "192.168.1.15", prefixlen: 24, scope: 0}) ==
      {[:state, :network_interface, 3, :addresses, "192.168.1.15"], %{broadcast: "192.168.1.255", family: :af_inet, local: "192.168.1.15", prefixlen: 24, scope: 0}}
  end

  test "newroute returns system registry default gateway update" do
    assert R.newroute(%{oif: 3, gateway: "192.168.1.1"}) ==
      {[:state, :network_interface, 3, :gateways, "192.168.1.1"], %{}}
  end
  test "newroute without a gateway does nothing" do
    assert R.newroute(%{dst: "192.168.1.0", family: :af_inet, oif: 3, prefsrc: "192.168.1.15", priority: 600, protocol: :kernel, scope: :link, table: :main, tos: 0, type: :unicast}) == :none
  end

  test "deladdr returns a system registry key to delete" do
    assert R.deladdr(%{address: "fe80::863a:4bff:fe11:95f6", family: :af_inet6, index: 3, prefixlen: 64, scope: 253}) ==
      [:state, :network_interface, 3, :addresses, "fe80::863a:4bff:fe11:95f6"]
  end
  test "dellink returns a system registry key to delete" do
    # NEED TO GET A USB WIFI DONGLE TO CAPTURE MESSAGE: assert R.dellink()
  end
end
