defmodule Nerves.NetworkInterface.Rtnetlink do

  @doc """
  Convert newlink notifications into updates.
  """
  def newlink(%{index: ifnum} = message) do
    new_message = Map.delete(message, :index)
    {[:state, :network_interface, ifnum], new_message}
  end

  @doc """
  Convert newaddr notifications into updates.
  """
  def newaddr(%{index: ifnum, address: address} = message) do
    new_message = message
    |> Map.delete(:index)
    |> Map.delete(:address)
    |> Map.delete(:label)

    {[:state, :network_interface, ifnum, :addresses, address], new_message}
  end

  @doc """
  Convert newroute notifications into updates.
  """
end
