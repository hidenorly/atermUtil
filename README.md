# atermUtil

This is utility program to control NEC Aterm Router (confirmed with Aterm WG1800HP2 with FW version 1.0.4).

Please note that I'm completely NOT related to NEC & the developers.

Aterm WG1800HP2 is excellent router but the administration is only available through web browser but I wanted to control it through console.

Currently what this utility can do is very limited.

# How to use

Always password is required. Please specify the password with -p.
Default User ID is "admin" (can be specified with ```-u``` ) and the router address is 192.168.10.1 (can be specified with ```-i``` )

## Reboot Aterm WG1800HP2

```
$ aterm_util.rb -p password
```

## Reboot Aterm WG1800HP2 (converter) connected to Aterm WG1800HP router

Aterm WG1800HP2 has 2 functionalities; router and converter. And in my case, I have 2 WG1800HP2 in my home. The one is router mode and the other is converter mode. To reboot the converter, please do following:

```
$ aterm_util.rb -p password -r xx:xx:xx:xx:xx:xx
```

* xx:xx:xx:xx:xx:xx is the converter's mac address.
* Please note that same ID & Password are required among WG1800HP2 router and the converter connected to the router.

## Show WAN IP

```
$ aterm_util.rb -p password -c showWANIP
```

## List DHCP Client List

```
$ aterm_util.rb -p password -c listDevices
```
