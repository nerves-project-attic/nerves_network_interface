defmodule Nerves.NetworkInterface.Rtnetlink do

  alias SystemRegistry, as: SR
  alias SystemRegistry.Transaction, as: T

  def decode(messages, ifaces) when is_list(messages) do
    Enum.reduce(messages, {:ok, T.begin, ifaces}, fn
      (msg, {error, t, ifaces}) ->
        case decode(t, msg, ifaces) do
          {:ok, t, ifaces} -> {error, t, ifaces}
          {:noop, t, ifaces} -> {error, t, ifaces}
          {:error, _, ifaces} -> {:error, t, ifaces}
        end
    end)
  end

  def decode(msg, ifaces) do
    decode(T.begin, msg, ifaces)
  end

  @doc """
  Convert newlink notifications into updates.
  """
  def decode(%T{} = t, {:newlink, msg}, ifaces) do
    iface = msg
    {_, ifaces} =
      iface(ifaces, iface.index)


    t = SR.update(t, [:state, :network_interface, iface.ifname], iface)
    {:ok, t, [iface | ifaces]}
  end

  @doc """
  Convert newaddr notifications into updates.
  """
  def decode(%T{} = t, {:newaddr, msg}, ifaces) do
    case iface(ifaces, msg.index) do
      {[iface], ifaces} ->
        addr_key = msg.address
        address = prune_address(msg)

        addresses =
          iface
          |> Map.get(:addresses, %{})
          |> Map.put(addr_key, address)

        iface = Map.put(iface, :addresses, addresses)
        t = SR.update(t, [:state, :network_interface, iface.ifname, :addresses, addr_key], address)

        {:ok, t, [iface | ifaces]}
      _ ->
        {:error, "unknown interface at index: #{msg.index}", ifaces}
    end
  end

  @doc """
  Convert newaddr notifications into updates.
  """
  def decode(%T{} = t, {:deladdr, msg}, ifaces) do
    case iface(ifaces, msg.index) do
      {[iface], ifaces} ->
        addr_key = msg.address

        addresses =
          iface
          |> Map.get(:addresses, %{})
          |> Map.delete(addr_key)

        iface = Map.put(iface, :addresses, addresses)
        t = SR.delete(t, [:state, :network_interface, iface.ifname, :addresses, addr_key])

        {:ok, t, [iface | ifaces]}
      _ ->
        {:error, "unknown interface at index: #{msg.index}", ifaces}
    end
  end

  @doc """
  Convert newroute notifications into updates.
  """
  def decode(%T{} = t, {:newroute, msg}, ifaces) do
    case iface(ifaces, msg.oif) do
      {[iface], ifaces} ->
        {_, routes} = route(Map.get(iface, :routes, []), msg)
        route = prune_route(msg)
        routes = [route | routes]
        gateway = Map.get(route, :gateway)
        iface =
          iface
          |> Map.put(:routes, routes)
          |> Map.put(:gateway, gateway)
        t =
          t
          |> SR.update([:state, :network_interface, iface.ifname, :routes], routes)
          |> SR.update([:state, :network_interface, iface.ifname, :gateway], gateway)
        {:ok, t, [iface | ifaces]}
      _ -> {:error, "unknown interface at index: #{msg.oif}", ifaces}
    end
  end

  def decode(t, _, ifaces), do: {:noop, t, ifaces}

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
