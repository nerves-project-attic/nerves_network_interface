# Changelog

## v0.4.6

* Bug fixes
  * Really build the C source code under the `_build` directory.

## v0.4.5

* Bug fixes
  * Build C source under the `_build` directory so that changing targets
    properly rebuilds the C code as well as the Elixir code.

## v0.4.4

  * Bug fixes
    * Fixed include path issue with C99 compiler test code. This fixes IFNAMSIZ
      compiler errors.

## v0.4.3

  * Bug fixes
    * Fixed issue with C99 compiler test not working right on some x86_64
      builds. It is more robust now.
    * Improved typespecs
    * Added a unit test

## v0.4.2

  * Bug fixes
    * Don't rely on hex preserving execute permissions on the shell script.

## v0.4.1

  * Enhancements
    * Support compilation on OSX. It won't run, but it's good enough for
      creating docs and pushing to hex.
    * Make MAC address handling more user friendly by using strings and
      supporting sets.

## v0.4.0

  * Enhancements
    * Replaced GenEvent with Registry

## v0.3.2

  * Bugs fixed
    * Clean up warnings for Elixir 1.4

## v0.3.2

  * Bugs fixed
    * Fix compilation error on Ubuntu 16.04

## v0.3.1

  * Bugs fixed
    * Fixes from integration with nerves_interim_wifi

## v0.3.0

Renamed from `net_basic.ex` to `nerves_network_interface`

  * New features
    * Sends events when interfaces appear and disappear (insertion/removal of a
      USB WiFi dongle)
    * Now an OTP application. You no longer need to add it to a supervision tree
      for use.
