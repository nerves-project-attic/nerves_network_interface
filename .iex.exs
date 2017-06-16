alias Nerves.NetworkInterface, as: NI
alias Nerves.NetworkInterface.Config

defmodule T do
  alias Nerves.NetworkInterface.Config

  def add_addr do
    Config.address_put "ens38", %{address: "172.16.52.134",
           broadcast: "172.16.52.255", family: :af_inet, local: "172.16.52.134",
           prefixlen: 24, scope: 0}
  end

  def remove_addr do
    Config.address_delete "ens38", "172.16.52.134"
  end
end
