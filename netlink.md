# Notes for experimenting with rtnetlink

## Change the MAC address on eth0
```
iex> Nerves.NetworkInterface.send [{:newlink, %{ifname: "eth0", mac_address: "e0:db:55:e7:8b:51"}}]
```


