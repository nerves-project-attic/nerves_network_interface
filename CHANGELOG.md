# Changelog

## v0.3.0

Renamed from `net_basic.ex` to `nerves_network_interface`

  * New features
    * Sends events when interfaces appear and disappear (insertion/removal of a
      USB WiFi dongle)
    * Now an OTP application. You no longer need to add it to a supervision tree
      for use.
