defmodule Nerves.NetworkInterface.Rtnetlink do

  alias SystemRegistry, as: SR

  @doc """
  Convert newlink notifications into updates.
  """
  def newlink(ifaces, %{ifname: ifname} = iface) do
    {_, ifaces} =
      iface(ifaces, iface.index)

    t =
      SR.transaction
      |> SR.update([:state, :network_interface, ifname], iface)
    {:ok, {[iface | ifaces], t}}
  end

  @doc """
  Convert newaddr notifications into updates.
  """
  def newaddr(ifaces, address) do
    case iface(ifaces, address.index) do
      {[iface], ifaces} ->
        addr_key = address.address
        address = prune_address(address)

        addresses =
          iface
          |> Map.get(:addresses, %{})
          |> Map.put(addr_key, address)

        iface = Map.put(iface, :addresses, addresses)
        t =
          SR.transaction
          |> SR.update([:state, :network_interface, iface.ifname, :addresses, addr_key], address)
        reply =
          {[iface | ifaces], t}
        {:ok, reply}
      _ ->
        {:error, "unknown interface at index: #{address.index}"}
    end
  end

  @doc """
  Convert newaddr notifications into updates.
  """
  def deladdr(ifaces, address) do
    case iface(ifaces, address.index) do
      {[iface], ifaces} ->
        addr_key = address.address

        addresses =
          iface
          |> Map.get(:addresses, %{})
          |> Map.delete(addr_key)

        iface = Map.put(iface, :addresses, addresses)
        t =
          SR.transaction
          |> SR.delete([:state, :network_interface, iface.ifname, :addresses, addr_key])
        reply =
          {[iface | ifaces], t}
        {:ok, reply}
      _ ->
        {:error, "unknown interface at index: #{address.index}"}
    end
  end

  @doc """
  Convert newroute notifications into updates.
  """
  def newroute(ifaces, route) do
    case iface(ifaces, route.oif) do
      {[iface], ifaces} ->
        {_, routes} = route(Map.get(iface, :routes, []), route)
        route = prune_route(route)
        routes = [route | routes]
        gateway = Map.get(route, :gateway)
        iface =
          iface
          |> Map.put(:routes, routes)
          |> Map.put(:gateway, gateway)
        t =
          SR.transaction
          |> SR.update([:state, :network_interface, iface.ifname, :routes], routes)
          |> SR.update([:state, :network_interface, iface.ifname, :gateway], gateway)
        {:ok, {[iface | ifaces], t}}
      _ -> {:error, "unknown interface at index: #{route.oif}"}
    end
  end

  defp iface(ifaces, ifindex),
    do: Enum.split_with(ifaces, & &1.index == ifindex)

  defp route(routes, route),
    do: Enum.split_with(routes, & &1 == route)

  defp prune_address(address) do
    address
    |> Map.delete(:index)
    |> Map.delete(:label)
  end

  defp prune_route(route) do
    route
    |> Map.delete(:oif)
  end
end
