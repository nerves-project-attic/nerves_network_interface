defmodule Nerves.NetworkInterface.Config do
  require Logger
  alias SystemRegistry, as: SR

  @scope [:config, :network_interface]
  @priority :nerves_network_interface

  def up(iface) do
    scope(iface)
    |> SR.update(%{is_up: true}, priority: @priority)
  end

  def down(iface) do
    scope(iface)
    |> SR.update(%{is_up: false}, priority: @priority)
  end

  def mac_address(iface, mac_address) do
    scope(iface)
    |> SR.update(%{mac_address: mac_address}, priority: @priority)
  end

  def address_put(iface, %{address: address} = addr) do
    address_delete(iface, address)

    scope(iface, [:addresses, address])
    |> SR.update(addr, priority: @priority)
  end

  def address_delete(iface, address) when is_binary(address) do
    scope(iface, [:addresses, address])
    |> SR.delete(priority: @priority)
  end

  # def route_put(iface, address) do
  #   address_delete(iface, address)
  #   scope(iface, [:routes])
  #   |> SR.update(addr, priority: @priority)
  # end
  #
  # def route_delete(iface, route) do
  #   scope(iface, [:routes, route])
  #   |> SR.delete
  # end

  def get(config, interface) do
    Map.get(config, interface, %{})
  end

  def system_registry(registry, config, interfaces) do
    net_config = get_in(registry, @scope) || %{}
    update(net_config, config, interfaces)
  end

  def update(old, old, _) do
    {old, []}
  end

  def update(new, old, interfaces) do
    Logger.debug("Config Changed")
    {added, removed, modified} = changes(new, old)

    removed = Enum.map(removed, fn {k, _} -> {k, %{}} end)
    modified = added ++ modified ++ removed

    ifaces = Enum.map(interfaces, & &1.ifname)

    modified =
      Enum.filter(modified, fn {iface, _v} ->
        iface in ifaces
      end)

    msg =
      Enum.reduce(modified, [], fn {iface, _v} = new, msg ->
        old = Map.get(old, iface, %{})
        interface = Enum.find(interfaces, &(&1.ifname == iface))

        msg
        |> update_links(new, old)
        |> update_addresses(new, old, interface)
        |> update_routes(new, old, interface)
      end)

    {new, msg}
  end

  def update_links(msg, {iface, new}, old) do
    new = Map.drop(new, [:addresses, :routes])
    old = Map.drop(old, [:addresses, :routes])

    cond do
      new != old ->
        [{:newlink, Map.put(new, :ifname, iface)} | msg]

      true ->
        msg
    end
  end

  defp update_addresses(msg, {_iface, new}, old, %{index: index}) do
    new_addr = Map.get(new, :addresses, %{})
    old_addr = Map.get(old, :addresses, %{})

    cond do
      new != old ->
        {added, removed, modified} = changes(new_addr, old_addr)
        modified = added ++ modified

        msg =
          Enum.reduce(modified, msg, fn {_, v}, msg ->
            [{:newaddr, Map.put(v, :index, index)} | msg]
          end)

        Enum.reduce(removed, msg, fn {_, v}, msg ->
          [{:deladdr, Map.put(v, :index, index)} | msg]
        end)

      true ->
        msg
    end
  end

  def update_routes(msg, {_iface, _new}, _old, _interface) do
    msg
  end

  defp scope(iface, append \\ []) do
    @scope ++ [iface | append]
  end

  defp changes(new, old) do
    added = Enum.filter(new, fn {k, _} -> Map.get(old, k) == nil end)
    removed = Enum.filter(old, fn {k, _} -> Map.get(new, k) == nil end)

    modified =
      Enum.filter(new, fn {k, v} ->
        val = Map.get(old, k)
        val != nil and val != v
      end)

    {added, removed, modified}
  end
end
