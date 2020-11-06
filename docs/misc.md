# Miscellaneous Notes

The following are a bunch of miscellaneous notes collected throughout the reverse engineering about processes used and the like.

## Capture Setup

The capture setup involves a VM on a Linux hypervisor with 2 physical network interfaces. The first one which will be called `eth0` for this example must be a physical Ethernet interface, It is connected directly to the `N5540A` chassis `MDI` or `MDI-X` port. The second interface, called `eth1` for this example can be either a physical Ethernet interface connected to your LAN, or WiFi, or any other interface where you can talk to your local network.

The VM has its internally exposed interface bridged to the hosts `eth0`, this lets it use the interface as its own, however because it's a bridge we can let `wireshark` put `eth0` into promiscuous mode and sniff all the traffic that goes over the interface, allowing the hypervisor to see all the incoming and outgoing traffic the VM generated without the VM noticing but also having the VM act as if it's on it's own dedicate interface.

The VM contains a Windows 7 install with the official Agilent `PCie_N5305A_SPT` software package installed on it.

The VMs interface is configured statically as `10.0.0.1/8` and runs a DHCP server with `BOOTP` support.

With all of that setup below, we can run the VM in headless mode, connect via RDP which is serving via the Virtual Box RDP server over our management interface `eth1` to start the software, then start the remote capture as noted below.

After the remote capture is started, the chassis can be powered on and then traffic should be visible to the hypervisor, and thus you running `wireshark` locally.


## Remote Packet Capture 

After ensuring that `wireshark` is installed on the hypervisor, and the user you plan to use is in the `wireshark` group, ensure that you have your public-key copied to the remote machine to avoid password prompts with `ssh-copy-id <host>` and test that you can connect.

If so, then you can run the following line below on your local system with the values substituted for your target user, host, and interface

```
wireshark -k -i <( ssh -l <USER> <HOST> tshark -i <INTERFACE> -w - ) -Y "not smb && not smb2 && not ssdp && not arp && not nbns && not llmnr"
```

There are some caveats to this, once you stop a capture you can't start one again without closing `wireshark`, hitting `^C` to terminate `tshark` then running the command again. Same for trying to restart a capture.

This can be fixed by making the FD that is opened here persistent but I can't be arsed about it right this second.

As mentioned prior when you exit `wireshark` you'll either need to `^C` a few time in the prompt or kill `tshark` on the hypervisor to close the socket.

The line `-Y "not smb && not smb2 && not ssdp && not arp && not nbns && not llmnr"` is a display filter to ignore all of the noise that Windows tends to generate by just existing.
