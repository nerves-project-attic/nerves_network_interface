defmodule Nerves.NetworkInterface.Config do
  require Logger
  alias SystemRegistry, as: SR

  @scope [:config, :network_interface]
  @priority :nerves_network_interface

  @type ifname :: String.t()
  @type system_registry_response :: {:ok, {new :: map, old :: map}} | {:error, term}

  @spec up(ifname) :: system_registry_response
  def up(ifname) do
    scope(ifname)
    |> SR.update(%{is_up: true}, priority: @priority)
  end

  @spec down(ifname) :: system_registry_response
  def down(ifname) do
    scope(ifname)
    |> SR.update(%{is_up: false}, priority: @priority)
  end

  @spec mac_address(ifname, mac_address :: String.t()) :: system_registry_response
  def mac_address(ifname, mac_address) do
    scope(ifname)
    |> SR.update(%{mac_address: mac_address}, priority: @priority)
  end

  @spec address_put(ifname, %{address: address :: String.t()}) :: system_registry_response
  def address_put(ifname, %{address: address} = addr) do
    address_delete(ifname, address)

    scope(ifname, [:addresses, address])
    |> SR.update(addr, priority: @priority)
  end

  @spec address_delete(ifname, address :: String.t()) :: system_registry_response
  def address_delete(ifname, address) when is_binary(address) do
    scope(ifname, [:addresses, address])
    |> SR.delete(priority: @priority)
  end

  # def route_put(ifname, address) do
  #   address_delete(ifname, address)
  #   scope(ifname, [:routes])
  #   |> SR.update(addr, priority: @priority)
  # end
  #
  # def route_delete(ifname, route) do
  #   scope(ifname, [:routes, route])
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

    ifnames = Enum.map(interfaces, & &1.ifname)

    modified =
      Enum.filter(modified, fn {ifname, _v} ->
        ifname in ifnames
      end)

    msg =
      Enum.reduce(modified, [], fn {ifname, _v} = new, msg ->
        old = Map.get(old, ifname, %{})
        interface = Enum.find(interfaces, &(&1.ifname == ifname))

        msg
        |> update_links(new, old)
        |> update_addresses(new, old, interface)
        |> update_routes(new, old, interface)
      end)

    {new, msg}
  end

  def update_links(msg, {ifname, new}, old) do
    new = Map.drop(new, [:addresses, :routes])
    old = Map.drop(old, [:addresses, :routes])

    cond do
      new != old ->
        [{:newlink, Map.put(new, :ifname, ifname)} | msg]

      true ->
        msg
    end
  end

  defp update_addresses(msg, {_ifname, new}, old, %{index: index}) do
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

  def update_routes(msg, {_ifname, _new}, _old, _interface) do
    msg
  end

  defp scope(ifname, append \\ []) do
    @scope ++ [ifname | append]
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
