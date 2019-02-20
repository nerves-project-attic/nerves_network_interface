defmodule Nerves.NetworkInterfaceTest do
  use ExUnit.Case, async: false

  @moduletag :external

  defp add_dev(name) do
    {_, 0} = System.cmd("sudo", ~w"ip link add #{name}0 type veth peer name #{name}1")
  end

  defp del_dev(name) do
    {_, 0} = System.cmd("sudo", ~w"ip link del #{name}0")
  end

  test "lists devices" do
    first = Nerves.NetworkInterface.interfaces()

    refute "veth0" in first

    add_dev("veth")
    res = Nerves.NetworkInterface.interfaces()

    assert "veth0" in res

    del_dev("veth")
  end

  test "gets status" do
    add_dev("vetha")

    res = Nerves.NetworkInterface.status("vetha0")
    assert match?({:ok, _}, res)

    {:ok, status} = res

    assert status.ifname == "vetha0"
    del_dev("vetha")
  end

  test "gets events from registry" do
    {:ok, _} = Registry.register(Nerves.NetworkInterface, "vethb0", [])

    add_dev("vethb")

    assert_receive({Nerves.NetworkInterface, :ifadded, %{ifname: "vethb0"}})
    assert_receive({Nerves.NetworkInterface, :ifchanged, %{ifname: "vethb0"}})
    refute_receive({Nerves.NetworkInterface, :ifadded, %{ifname: "vethb1"}})
    refute_receive({Nerves.NetworkInterface, :ifchanged, %{ifname: "vethb1"}})
    del_dev("vethb")
  end
end
