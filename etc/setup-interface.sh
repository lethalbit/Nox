#!/bin/bash
IFACE=enp3s0

if [ $# -eq 1 ]; then
	IFACE=$1
fi

ip address flush dev $IFACE
ip address add 10.0.0.1/8 broadcast + dev $IFACE
ip route add 10.0.0.0/8 via 10.0.0.1 dev $IFACE
ip link set $IFACE up
ip link set dev $IFACE promisc on
