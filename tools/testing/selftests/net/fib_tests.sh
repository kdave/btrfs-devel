#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# This test is for checking IPv4 and IPv6 FIB behavior in response to
# different events.
source lib.sh
ret=0

# all tests in this script. Can be overridden with -t option
TESTS="unregister down carrier nexthop suppress ipv6_notify ipv4_notify \
       ipv6_rt ipv4_rt ipv6_addr_metric ipv4_addr_metric ipv6_route_metrics \
       ipv4_route_metrics ipv4_route_v6_gw rp_filter ipv4_del_addr \
       ipv6_del_addr ipv4_mangle ipv6_mangle ipv4_bcast_neigh fib6_gc_test \
       ipv4_mpath_list ipv6_mpath_list ipv4_mpath_balance ipv6_mpath_balance"

VERBOSE=0
PAUSE_ON_FAIL=no
PAUSE=no

which ping6 > /dev/null 2>&1 && ping6=$(which ping6) || ping6=$(which ping)

log_test()
{
	local rc=$1
	local expected=$2
	local msg="$3"

	if [ ${rc} -eq ${expected} ]; then
		printf "    TEST: %-60s  [ OK ]\n" "${msg}"
		nsuccess=$((nsuccess+1))
	else
		ret=1
		nfail=$((nfail+1))
		printf "    TEST: %-60s  [FAIL]\n" "${msg}"
		if [ "${PAUSE_ON_FAIL}" = "yes" ]; then
		echo
			echo "hit enter to continue, 'q' to quit"
			read a
			[ "$a" = "q" ] && exit 1
		fi
	fi

	if [ "${PAUSE}" = "yes" ]; then
		echo
		echo "hit enter to continue, 'q' to quit"
		read a
		[ "$a" = "q" ] && exit 1
	fi
}

setup()
{
	set -e
	setup_ns ns1
	IP="$(which ip) -netns $ns1"
	NS_EXEC="$(which ip) netns exec $ns1"
	ip netns exec $ns1 sysctl -qw net.ipv4.ip_forward=1
	ip netns exec $ns1 sysctl -qw net.ipv6.conf.all.forwarding=1

	$IP link add dummy0 type dummy
	$IP link set dev dummy0 up
	$IP address add 198.51.100.1/24 dev dummy0
	$IP -6 address add 2001:db8:1::1/64 dev dummy0
	set +e

}

cleanup()
{
	$IP link del dev dummy0 &> /dev/null
	cleanup_ns $ns1 $ns2
}

get_linklocal()
{
	local dev=$1
	local addr

	addr=$($IP -6 -br addr show dev ${dev} | \
	awk '{
		for (i = 3; i <= NF; ++i) {
			if ($i ~ /^fe80/)
				print $i
		}
	}'
	)
	addr=${addr/\/*}

	[ -z "$addr" ] && return 1

	echo $addr

	return 0
}

fib_unreg_unicast_test()
{
	echo
	echo "Single path route test"

	setup

	echo "    Start point"
	$IP route get fibmatch 198.51.100.2 &> /dev/null
	log_test $? 0 "IPv4 fibmatch"
	$IP -6 route get fibmatch 2001:db8:1::2 &> /dev/null
	log_test $? 0 "IPv6 fibmatch"

	set -e
	$IP link del dev dummy0
	set +e

	echo "    Nexthop device deleted"
	$IP route get fibmatch 198.51.100.2 &> /dev/null
	log_test $? 2 "IPv4 fibmatch - no route"
	$IP -6 route get fibmatch 2001:db8:1::2 &> /dev/null
	log_test $? 2 "IPv6 fibmatch - no route"

	cleanup
}

fib_unreg_multipath_test()
{

	echo
	echo "Multipath route test"

	setup

	set -e
	$IP link add dummy1 type dummy
	$IP link set dev dummy1 up
	$IP address add 192.0.2.1/24 dev dummy1
	$IP -6 address add 2001:db8:2::1/64 dev dummy1

	$IP route add 203.0.113.0/24 \
		nexthop via 198.51.100.2 dev dummy0 \
		nexthop via 192.0.2.2 dev dummy1
	$IP -6 route add 2001:db8:3::/64 \
		nexthop via 2001:db8:1::2 dev dummy0 \
		nexthop via 2001:db8:2::2 dev dummy1
	set +e

	echo "    Start point"
	$IP route get fibmatch 203.0.113.1 &> /dev/null
	log_test $? 0 "IPv4 fibmatch"
	$IP -6 route get fibmatch 2001:db8:3::1 &> /dev/null
	log_test $? 0 "IPv6 fibmatch"

	set -e
	$IP link del dev dummy0
	set +e

	echo "    One nexthop device deleted"
	$IP route get fibmatch 203.0.113.1 &> /dev/null
	log_test $? 2 "IPv4 - multipath route removed on delete"

	$IP -6 route get fibmatch 2001:db8:3::1 &> /dev/null
	# In IPv6 we do not flush the entire multipath route.
	log_test $? 0 "IPv6 - multipath down to single path"

	set -e
	$IP link del dev dummy1
	set +e

	echo "    Second nexthop device deleted"
	$IP -6 route get fibmatch 2001:db8:3::1 &> /dev/null
	log_test $? 2 "IPv6 - no route"

	cleanup
}

fib_unreg_test()
{
	fib_unreg_unicast_test
	fib_unreg_multipath_test
}

fib_down_unicast_test()
{
	echo
	echo "Single path, admin down"

	setup

	echo "    Start point"
	$IP route get fibmatch 198.51.100.2 &> /dev/null
	log_test $? 0 "IPv4 fibmatch"
	$IP -6 route get fibmatch 2001:db8:1::2 &> /dev/null
	log_test $? 0 "IPv6 fibmatch"

	set -e
	$IP link set dev dummy0 down
	set +e

	echo "    Route deleted on down"
	$IP route get fibmatch 198.51.100.2 &> /dev/null
	log_test $? 2 "IPv4 fibmatch"
	$IP -6 route get fibmatch 2001:db8:1::2 &> /dev/null
	log_test $? 2 "IPv6 fibmatch"

	cleanup
}

fib_down_multipath_test_do()
{
	local down_dev=$1
	local up_dev=$2

	$IP route get fibmatch 203.0.113.1 \
		oif $down_dev &> /dev/null
	log_test $? 2 "IPv4 fibmatch on down device"
	$IP -6 route get fibmatch 2001:db8:3::1 \
		oif $down_dev &> /dev/null
	log_test $? 2 "IPv6 fibmatch on down device"

	$IP route get fibmatch 203.0.113.1 \
		oif $up_dev &> /dev/null
	log_test $? 0 "IPv4 fibmatch on up device"
	$IP -6 route get fibmatch 2001:db8:3::1 \
		oif $up_dev &> /dev/null
	log_test $? 0 "IPv6 fibmatch on up device"

	$IP route get fibmatch 203.0.113.1 | \
		grep $down_dev | grep -q "dead linkdown"
	log_test $? 0 "IPv4 flags on down device"
	$IP -6 route get fibmatch 2001:db8:3::1 | \
		grep $down_dev | grep -q "dead linkdown"
	log_test $? 0 "IPv6 flags on down device"

	$IP route get fibmatch 203.0.113.1 | \
		grep $up_dev | grep -q "dead linkdown"
	log_test $? 1 "IPv4 flags on up device"
	$IP -6 route get fibmatch 2001:db8:3::1 | \
		grep $up_dev | grep -q "dead linkdown"
	log_test $? 1 "IPv6 flags on up device"
}

fib_down_multipath_test()
{
	echo
	echo "Admin down multipath"

	setup

	set -e
	$IP link add dummy1 type dummy
	$IP link set dev dummy1 up

	$IP address add 192.0.2.1/24 dev dummy1
	$IP -6 address add 2001:db8:2::1/64 dev dummy1

	$IP route add 203.0.113.0/24 \
		nexthop via 198.51.100.2 dev dummy0 \
		nexthop via 192.0.2.2 dev dummy1
	$IP -6 route add 2001:db8:3::/64 \
		nexthop via 2001:db8:1::2 dev dummy0 \
		nexthop via 2001:db8:2::2 dev dummy1
	set +e

	echo "    Verify start point"
	$IP route get fibmatch 203.0.113.1 &> /dev/null
	log_test $? 0 "IPv4 fibmatch"

	$IP -6 route get fibmatch 2001:db8:3::1 &> /dev/null
	log_test $? 0 "IPv6 fibmatch"

	set -e
	$IP link set dev dummy0 down
	set +e

	echo "    One device down, one up"
	fib_down_multipath_test_do "dummy0" "dummy1"

	set -e
	$IP link set dev dummy0 up
	$IP link set dev dummy1 down
	set +e

	echo "    Other device down and up"
	fib_down_multipath_test_do "dummy1" "dummy0"

	set -e
	$IP link set dev dummy0 down
	set +e

	echo "    Both devices down"
	$IP route get fibmatch 203.0.113.1 &> /dev/null
	log_test $? 2 "IPv4 fibmatch"
	$IP -6 route get fibmatch 2001:db8:3::1 &> /dev/null
	log_test $? 2 "IPv6 fibmatch"

	$IP link del dev dummy1
	cleanup
}

fib_down_test()
{
	fib_down_unicast_test
	fib_down_multipath_test
}

# Local routes should not be affected when carrier changes.
fib_carrier_local_test()
{
	echo
	echo "Local carrier tests - single path"

	setup

	set -e
	$IP link set dev dummy0 carrier on
	set +e

	echo "    Start point"
	$IP route get fibmatch 198.51.100.1 &> /dev/null
	log_test $? 0 "IPv4 fibmatch"
	$IP -6 route get fibmatch 2001:db8:1::1 &> /dev/null
	log_test $? 0 "IPv6 fibmatch"

	$IP route get fibmatch 198.51.100.1 | \
		grep -q "linkdown"
	log_test $? 1 "IPv4 - no linkdown flag"
	$IP -6 route get fibmatch 2001:db8:1::1 | \
		grep -q "linkdown"
	log_test $? 1 "IPv6 - no linkdown flag"

	set -e
	$IP link set dev dummy0 carrier off
	sleep 1
	set +e

	echo "    Carrier off on nexthop"
	$IP route get fibmatch 198.51.100.1 &> /dev/null
	log_test $? 0 "IPv4 fibmatch"
	$IP -6 route get fibmatch 2001:db8:1::1 &> /dev/null
	log_test $? 0 "IPv6 fibmatch"

	$IP route get fibmatch 198.51.100.1 | \
		grep -q "linkdown"
	log_test $? 1 "IPv4 - linkdown flag set"
	$IP -6 route get fibmatch 2001:db8:1::1 | \
		grep -q "linkdown"
	log_test $? 1 "IPv6 - linkdown flag set"

	set -e
	$IP address add 192.0.2.1/24 dev dummy0
	$IP -6 address add 2001:db8:2::1/64 dev dummy0
	set +e

	echo "    Route to local address with carrier down"
	$IP route get fibmatch 192.0.2.1 &> /dev/null
	log_test $? 0 "IPv4 fibmatch"
	$IP -6 route get fibmatch 2001:db8:2::1 &> /dev/null
	log_test $? 0 "IPv6 fibmatch"

	$IP route get fibmatch 192.0.2.1 | \
		grep -q "linkdown"
	log_test $? 1 "IPv4 linkdown flag set"
	$IP -6 route get fibmatch 2001:db8:2::1 | \
		grep -q "linkdown"
	log_test $? 1 "IPv6 linkdown flag set"

	cleanup
}

fib_carrier_unicast_test()
{
	ret=0

	echo
	echo "Single path route carrier test"

	setup

	set -e
	$IP link set dev dummy0 carrier on
	set +e

	echo "    Start point"
	$IP route get fibmatch 198.51.100.2 &> /dev/null
	log_test $? 0 "IPv4 fibmatch"
	$IP -6 route get fibmatch 2001:db8:1::2 &> /dev/null
	log_test $? 0 "IPv6 fibmatch"

	$IP route get fibmatch 198.51.100.2 | \
		grep -q "linkdown"
	log_test $? 1 "IPv4 no linkdown flag"
	$IP -6 route get fibmatch 2001:db8:1::2 | \
		grep -q "linkdown"
	log_test $? 1 "IPv6 no linkdown flag"

	set -e
	$IP link set dev dummy0 carrier off
	sleep 1
	set +e

	echo "    Carrier down"
	$IP route get fibmatch 198.51.100.2 &> /dev/null
	log_test $? 0 "IPv4 fibmatch"
	$IP -6 route get fibmatch 2001:db8:1::2 &> /dev/null
	log_test $? 0 "IPv6 fibmatch"

	$IP route get fibmatch 198.51.100.2 | \
		grep -q "linkdown"
	log_test $? 0 "IPv4 linkdown flag set"
	$IP -6 route get fibmatch 2001:db8:1::2 | \
		grep -q "linkdown"
	log_test $? 0 "IPv6 linkdown flag set"

	set -e
	$IP address add 192.0.2.1/24 dev dummy0
	$IP -6 address add 2001:db8:2::1/64 dev dummy0
	set +e

	echo "    Second address added with carrier down"
	$IP route get fibmatch 192.0.2.2 &> /dev/null
	log_test $? 0 "IPv4 fibmatch"
	$IP -6 route get fibmatch 2001:db8:2::2 &> /dev/null
	log_test $? 0 "IPv6 fibmatch"

	$IP route get fibmatch 192.0.2.2 | \
		grep -q "linkdown"
	log_test $? 0 "IPv4 linkdown flag set"
	$IP -6 route get fibmatch 2001:db8:2::2 | \
		grep -q "linkdown"
	log_test $? 0 "IPv6 linkdown flag set"

	cleanup
}

fib_carrier_test()
{
	fib_carrier_local_test
	fib_carrier_unicast_test
}

fib_rp_filter_test()
{
	echo
	echo "IPv4 rp_filter tests"

	setup

	set -e
	setup_ns ns2

	$IP link add name veth1 type veth peer name veth2
	$IP link set dev veth2 netns $ns2
	$IP address add 192.0.2.1/24 dev veth1
	ip -netns $ns2 address add 192.0.2.1/24 dev veth2
	$IP link set dev veth1 up
	ip -netns $ns2 link set dev veth2 up

	$IP link set dev lo address 52:54:00:6a:c7:5e
	$IP link set dev veth1 address 52:54:00:6a:c7:5e
	ip -netns $ns2 link set dev lo address 52:54:00:6a:c7:5e
	ip -netns $ns2 link set dev veth2 address 52:54:00:6a:c7:5e

	# 1. (ns2) redirect lo's egress to veth2's egress
	ip netns exec $ns2 tc qdisc add dev lo parent root handle 1: fq_codel
	ip netns exec $ns2 tc filter add dev lo parent 1: protocol arp basic \
		action mirred egress redirect dev veth2
	ip netns exec $ns2 tc filter add dev lo parent 1: protocol ip basic \
		action mirred egress redirect dev veth2

	# 2. (ns1) redirect veth1's ingress to lo's ingress
	$NS_EXEC tc qdisc add dev veth1 ingress
	$NS_EXEC tc filter add dev veth1 ingress protocol arp basic \
		action mirred ingress redirect dev lo
	$NS_EXEC tc filter add dev veth1 ingress protocol ip basic \
		action mirred ingress redirect dev lo

	# 3. (ns1) redirect lo's egress to veth1's egress
	$NS_EXEC tc qdisc add dev lo parent root handle 1: fq_codel
	$NS_EXEC tc filter add dev lo parent 1: protocol arp basic \
		action mirred egress redirect dev veth1
	$NS_EXEC tc filter add dev lo parent 1: protocol ip basic \
		action mirred egress redirect dev veth1

	# 4. (ns2) redirect veth2's ingress to lo's ingress
	ip netns exec $ns2 tc qdisc add dev veth2 ingress
	ip netns exec $ns2 tc filter add dev veth2 ingress protocol arp basic \
		action mirred ingress redirect dev lo
	ip netns exec $ns2 tc filter add dev veth2 ingress protocol ip basic \
		action mirred ingress redirect dev lo

	$NS_EXEC sysctl -qw net.ipv4.conf.all.rp_filter=1
	$NS_EXEC sysctl -qw net.ipv4.conf.all.accept_local=1
	$NS_EXEC sysctl -qw net.ipv4.conf.all.route_localnet=1
	ip netns exec $ns2 sysctl -qw net.ipv4.conf.all.rp_filter=1
	ip netns exec $ns2 sysctl -qw net.ipv4.conf.all.accept_local=1
	ip netns exec $ns2 sysctl -qw net.ipv4.conf.all.route_localnet=1
	set +e

	run_cmd "ip netns exec $ns2 ping -w1 -c1 192.0.2.1"
	log_test $? 0 "rp_filter passes local packets"

	run_cmd "ip netns exec $ns2 ping -w1 -c1 127.0.0.1"
	log_test $? 0 "rp_filter passes loopback packets"

	cleanup
}

################################################################################
# Tests on nexthop spec

# run 'ip route add' with given spec
add_rt()
{
	local desc="$1"
	local erc=$2
	local vrf=$3
	local pfx=$4
	local gw=$5
	local dev=$6
	local cmd out rc

	[ "$vrf" = "-" ] && vrf="default"
	[ -n "$gw" ] && gw="via $gw"
	[ -n "$dev" ] && dev="dev $dev"

	cmd="$IP route add vrf $vrf $pfx $gw $dev"
	if [ "$VERBOSE" = "1" ]; then
		printf "\n    COMMAND: $cmd\n"
	fi

	out=$(eval $cmd 2>&1)
	rc=$?
	if [ "$VERBOSE" = "1" -a -n "$out" ]; then
		echo "    $out"
	fi
	log_test $rc $erc "$desc"
}

fib4_nexthop()
{
	echo
	echo "IPv4 nexthop tests"

	echo "<<< write me >>>"
}

fib6_nexthop()
{
	local lldummy=$(get_linklocal dummy0)
	local llv1=$(get_linklocal dummy0)

	if [ -z "$lldummy" ]; then
		echo "Failed to get linklocal address for dummy0"
		return 1
	fi
	if [ -z "$llv1" ]; then
		echo "Failed to get linklocal address for veth1"
		return 1
	fi

	echo
	echo "IPv6 nexthop tests"

	add_rt "Directly connected nexthop, unicast address" 0 \
		- 2001:db8:101::/64 2001:db8:1::2
	add_rt "Directly connected nexthop, unicast address with device" 0 \
		- 2001:db8:102::/64 2001:db8:1::2 "dummy0"
	add_rt "Gateway is linklocal address" 0 \
		- 2001:db8:103::1/64 $llv1 "veth0"

	# fails because LL address requires a device
	add_rt "Gateway is linklocal address, no device" 2 \
		- 2001:db8:104::1/64 $llv1

	# local address can not be a gateway
	add_rt "Gateway can not be local unicast address" 2 \
		- 2001:db8:105::/64 2001:db8:1::1
	add_rt "Gateway can not be local unicast address, with device" 2 \
		- 2001:db8:106::/64 2001:db8:1::1 "dummy0"
	add_rt "Gateway can not be a local linklocal address" 2 \
		- 2001:db8:107::1/64 $lldummy "dummy0"

	# VRF tests
	add_rt "Gateway can be local address in a VRF" 0 \
		- 2001:db8:108::/64 2001:db8:51::2
	add_rt "Gateway can be local address in a VRF, with device" 0 \
		- 2001:db8:109::/64 2001:db8:51::2 "veth0"
	add_rt "Gateway can be local linklocal address in a VRF" 0 \
		- 2001:db8:110::1/64 $llv1 "veth0"

	add_rt "Redirect to VRF lookup" 0 \
		- 2001:db8:111::/64 "" "red"

	add_rt "VRF route, gateway can be local address in default VRF" 0 \
		red 2001:db8:112::/64 2001:db8:51::1

	# local address in same VRF fails
	add_rt "VRF route, gateway can not be a local address" 2 \
		red 2001:db8:113::1/64 2001:db8:2::1
	add_rt "VRF route, gateway can not be a local addr with device" 2 \
		red 2001:db8:114::1/64 2001:db8:2::1 "dummy1"
}

# Default VRF:
#   dummy0 - 198.51.100.1/24 2001:db8:1::1/64
#   veth0  - 192.0.2.1/24    2001:db8:51::1/64
#
# VRF red:
#   dummy1 - 192.168.2.1/24 2001:db8:2::1/64
#   veth1  - 192.0.2.2/24   2001:db8:51::2/64
#
#  [ dummy0   veth0 ]--[ veth1   dummy1 ]

fib_nexthop_test()
{
	setup

	set -e

	$IP -4 rule add pref 32765 table local
	$IP -4 rule del pref 0
	$IP -6 rule add pref 32765 table local
	$IP -6 rule del pref 0

	$IP link add red type vrf table 1
	$IP link set red up
	$IP -4 route add vrf red unreachable default metric 4278198272
	$IP -6 route add vrf red unreachable default metric 4278198272

	$IP link add veth0 type veth peer name veth1
	$IP link set dev veth0 up
	$IP address add 192.0.2.1/24 dev veth0
	$IP -6 address add 2001:db8:51::1/64 dev veth0

	$IP link set dev veth1 vrf red up
	$IP address add 192.0.2.2/24 dev veth1
	$IP -6 address add 2001:db8:51::2/64 dev veth1

	$IP link add dummy1 type dummy
	$IP link set dev dummy1 vrf red up
	$IP address add 192.168.2.1/24 dev dummy1
	$IP -6 address add 2001:db8:2::1/64 dev dummy1
	set +e

	sleep 1
	fib4_nexthop
	fib6_nexthop

	(
	$IP link del dev dummy1
	$IP link del veth0
	$IP link del red
	) 2>/dev/null
	cleanup
}

fib6_notify_test()
{
	setup

	echo
	echo "Fib6 info length calculation in route notify test"
	set -e

	for i in 10 20 30 40 50 60 70;
	do
		$IP link add dummy_$i type dummy
		$IP link set dev dummy_$i up
		$IP -6 address add 2001:$i::1/64 dev dummy_$i
	done

	$NS_EXEC ip monitor route &> errors.txt &
	sleep 2

	$IP -6 route add 2001::/64 \
                nexthop via 2001:10::2 dev dummy_10 \
                nexthop encap ip6 dst 2002::20 via 2001:20::2 dev dummy_20 \
                nexthop encap ip6 dst 2002::30 via 2001:30::2 dev dummy_30 \
                nexthop encap ip6 dst 2002::40 via 2001:40::2 dev dummy_40 \
                nexthop encap ip6 dst 2002::50 via 2001:50::2 dev dummy_50 \
                nexthop encap ip6 dst 2002::60 via 2001:60::2 dev dummy_60 \
                nexthop encap ip6 dst 2002::70 via 2001:70::2 dev dummy_70

	set +e

	err=`cat errors.txt |grep "Message too long"`
	if [ -z "$err" ];then
		ret=0
	else
		ret=1
	fi

	log_test $ret 0 "ipv6 route add notify"

	kill_process %%

	#rm errors.txt

	cleanup &> /dev/null
}


fib_notify_test()
{
	setup

	echo
	echo "Fib4 info length calculation in route notify test"

	set -e

	for i in 10 20 30 40 50 60 70;
	do
		$IP link add dummy_$i type dummy
		$IP link set dev dummy_$i up
		$IP address add 20.20.$i.2/24 dev dummy_$i
	done

	$NS_EXEC ip monitor route &> errors.txt &
	sleep 2

        $IP route add 10.0.0.0/24 \
                nexthop via 20.20.10.1 dev dummy_10 \
                nexthop encap ip dst 192.168.10.20 via 20.20.20.1 dev dummy_20 \
                nexthop encap ip dst 192.168.10.30 via 20.20.30.1 dev dummy_30 \
                nexthop encap ip dst 192.168.10.40 via 20.20.40.1 dev dummy_40 \
                nexthop encap ip dst 192.168.10.50 via 20.20.50.1 dev dummy_50 \
                nexthop encap ip dst 192.168.10.60 via 20.20.60.1 dev dummy_60 \
                nexthop encap ip dst 192.168.10.70 via 20.20.70.1 dev dummy_70

	set +e

	err=`cat errors.txt |grep "Message too long"`
	if [ -z "$err" ];then
		ret=0
	else
		ret=1
	fi

	log_test $ret 0 "ipv4 route add notify"

	kill_process %%

	rm  errors.txt

	cleanup &> /dev/null
}

# Create a new dummy_10 to remove all associated routes.
reset_dummy_10()
{
	$IP link del dev dummy_10

	$IP link add dummy_10 type dummy
	$IP link set dev dummy_10 up
	$IP -6 address add 2001:10::1/64 dev dummy_10
}

check_rt_num()
{
    local expected=$1
    local num=$2

    if [ $num -ne $expected ]; then
	echo "FAIL: Expected $expected routes, got $num"
	ret=1
    else
	ret=0
    fi
}

check_rt_num_clean()
{
    local expected=$1
    local num=$2

    if [ $num -ne $expected ]; then
	log_test 1 0 "expected $expected routes, got $num"
	set +e
	cleanup &> /dev/null
	return 1
    fi
    return 0
}

fib6_gc_test()
{
	setup

	echo
	echo "Fib6 garbage collection test"
	set -e

	EXPIRE=5
	GC_WAIT_TIME=$((EXPIRE * 2 + 2))

	# Check expiration of routes every $EXPIRE seconds (GC)
	$NS_EXEC sysctl -wq net.ipv6.route.gc_interval=$EXPIRE

	$IP link add dummy_10 type dummy
	$IP link set dev dummy_10 up
	$IP -6 address add 2001:10::1/64 dev dummy_10

	$NS_EXEC sysctl -wq net.ipv6.route.flush=1

	# Temporary routes
	for i in $(seq 1 5); do
	    # Expire route after $EXPIRE seconds
	    $IP -6 route add 2001:20::$i \
		via 2001:10::2 dev dummy_10 expires $EXPIRE
	done
	sleep $GC_WAIT_TIME
	$NS_EXEC sysctl -wq net.ipv6.route.flush=1
	check_rt_num 0 $($IP -6 route list |grep expires|wc -l)
	log_test $ret 0 "ipv6 route garbage collection"

	reset_dummy_10

	# Permanent routes
	for i in $(seq 1 5); do
	    $IP -6 route add 2001:30::$i \
		via 2001:10::2 dev dummy_10
	done
	# Temporary routes
	for i in $(seq 1 5); do
	    # Expire route after $EXPIRE seconds
	    $IP -6 route add 2001:20::$i \
		via 2001:10::2 dev dummy_10 expires $EXPIRE
	done
	# Wait for GC
	sleep $GC_WAIT_TIME
	check_rt_num 0 $($IP -6 route list |grep expires|wc -l)
	log_test $ret 0 "ipv6 route garbage collection (with permanent routes)"

	reset_dummy_10

	# Permanent routes
	for i in $(seq 1 5); do
	    $IP -6 route add 2001:20::$i \
		via 2001:10::2 dev dummy_10
	done
	# Replace with temporary routes
	for i in $(seq 1 5); do
	    # Expire route after $EXPIRE seconds
	    $IP -6 route replace 2001:20::$i \
		via 2001:10::2 dev dummy_10 expires $EXPIRE
	done
	# Wait for GC
	sleep $GC_WAIT_TIME
	check_rt_num 0 $($IP -6 route list |grep expires|wc -l)
	log_test $ret 0 "ipv6 route garbage collection (replace with expires)"

	reset_dummy_10

	# Temporary routes
	for i in $(seq 1 5); do
	    # Expire route after $EXPIRE seconds
	    $IP -6 route add 2001:20::$i \
		via 2001:10::2 dev dummy_10 expires $EXPIRE
	done
	# Replace with permanent routes
	for i in $(seq 1 5); do
	    $IP -6 route replace 2001:20::$i \
		via 2001:10::2 dev dummy_10
	done
	check_rt_num_clean 0 $($IP -6 route list |grep expires|wc -l) || return

	# Wait for GC
	sleep $GC_WAIT_TIME
	check_rt_num 5 $($IP -6 route list |grep -v expires|grep 2001:20::|wc -l)
	log_test $ret 0 "ipv6 route garbage collection (replace with permanent)"

	# ra6 is required for the next test. (ipv6toolkit)
	if [ ! -x "$(command -v ra6)" ]; then
	    echo "SKIP: ra6 not found."
	    set +e
	    cleanup &> /dev/null
	    return
	fi

	# Delete dummy_10 and remove all routes
	$IP link del dev dummy_10

	# Create a pair of veth devices to send a RA message from one
	# device to another.
	$IP link add veth1 type veth peer name veth2
	$IP link set dev veth1 up
	$IP link set dev veth2 up
	$IP -6 address add 2001:10::1/64 dev veth1 nodad
	$IP -6 address add 2001:10::2/64 dev veth2 nodad

	# Make veth1 ready to receive RA messages.
	$NS_EXEC sysctl -wq net.ipv6.conf.veth1.accept_ra=2

	# Send a RA message with a route from veth2 to veth1.
	$NS_EXEC ra6 -i veth2 -d 2001:10::1 -t $EXPIRE

	# Wait for the RA message.
	sleep 1

	# systemd may mess up the test.  You syould make sure that
	# systemd-networkd.service and systemd-networkd.socket are stopped.
	check_rt_num_clean 1 $($IP -6 route list|grep expires|wc -l) || return

	# Wait for GC
	sleep $GC_WAIT_TIME
	check_rt_num 0 $($IP -6 route list |grep expires|wc -l)
	log_test $ret 0 "ipv6 route garbage collection (RA message)"

	set +e

	cleanup &> /dev/null
}

fib_suppress_test()
{
	echo
	echo "FIB rule with suppress_prefixlength"
	setup

	$IP link add dummy1 type dummy
	$IP link set dummy1 up
	$IP -6 route add default dev dummy1
	$IP -6 rule add table main suppress_prefixlength 0
	ping -f -c 1000 -W 1 1234::1 >/dev/null 2>&1
	$IP -6 rule del table main suppress_prefixlength 0
	$IP link del dummy1

	# If we got here without crashing, we're good.
	log_test 0 0 "FIB rule suppress test"

	cleanup
}

################################################################################
# Tests on route add and replace

run_cmd()
{
	local cmd="$1"
	local out
	local stderr="2>/dev/null"

	if [ "$VERBOSE" = "1" ]; then
		printf "    COMMAND: $cmd\n"
		stderr=
	fi

	out=$(eval $cmd $stderr)
	rc=$?
	if [ "$VERBOSE" = "1" -a -n "$out" ]; then
		echo "    $out"
	fi

	[ "$VERBOSE" = "1" ] && echo

	return $rc
}

check_expected()
{
	local out="$1"
	local expected="$2"
	local rc=0

	[ "${out}" = "${expected}" ] && return 0

	if [ -z "${out}" ]; then
		if [ "$VERBOSE" = "1" ]; then
			printf "\nNo route entry found\n"
			printf "Expected:\n"
			printf "    ${expected}\n"
		fi
		return 1
	fi

	# tricky way to convert output to 1-line without ip's
	# messy '\'; this drops all extra white space
	out=$(echo ${out})
	if [ "${out}" != "${expected}" ]; then
		rc=1
		if [ "${VERBOSE}" = "1" ]; then
			printf "    Unexpected route entry. Have:\n"
			printf "        ${out}\n"
			printf "    Expected:\n"
			printf "        ${expected}\n\n"
		fi
	fi

	return $rc
}

# add route for a prefix, flushing any existing routes first
# expected to be the first step of a test
add_route6()
{
	local pfx="$1"
	local nh="$2"
	local out

	if [ "$VERBOSE" = "1" ]; then
		echo
		echo "    ##################################################"
		echo
	fi

	run_cmd "$IP -6 ro flush ${pfx}"
	[ $? -ne 0 ] && exit 1

	out=$($IP -6 ro ls match ${pfx})
	if [ -n "$out" ]; then
		echo "Failed to flush routes for prefix used for tests."
		exit 1
	fi

	run_cmd "$IP -6 ro add ${pfx} ${nh}"
	if [ $? -ne 0 ]; then
		echo "Failed to add initial route for test."
		exit 1
	fi
}

# add initial route - used in replace route tests
add_initial_route6()
{
	add_route6 "2001:db8:104::/64" "$1"
}

check_route6()
{
	local pfx
	local expected="$1"
	local out
	local rc=0

	set -- $expected
	pfx=$1

	out=$($IP -6 ro ls match ${pfx} | sed -e 's/ pref medium//')
	check_expected "${out}" "${expected}"
}

route_cleanup()
{
	$IP li del red 2>/dev/null
	$IP li del dummy1 2>/dev/null
	$IP li del veth1 2>/dev/null
	$IP li del veth3 2>/dev/null

	cleanup &> /dev/null
}

route_setup()
{
	route_cleanup
	setup

	[ "${VERBOSE}" = "1" ] && set -x
	set -e

	setup_ns ns2
	ip netns exec $ns2 sysctl -qw net.ipv4.ip_forward=1
	ip netns exec $ns2 sysctl -qw net.ipv6.conf.all.forwarding=1

	$IP li add veth1 type veth peer name veth2
	$IP li add veth3 type veth peer name veth4

	$IP li set veth1 up
	$IP li set veth3 up
	$IP li set veth2 netns $ns2 up
	$IP li set veth4 netns $ns2 up
	ip -netns $ns2 li add dummy1 type dummy
	ip -netns $ns2 li set dummy1 up

	$IP -6 addr add 2001:db8:101::1/64 dev veth1 nodad
	$IP -6 addr add 2001:db8:103::1/64 dev veth3 nodad
	$IP addr add 172.16.101.1/24 dev veth1
	$IP addr add 172.16.103.1/24 dev veth3

	ip -netns $ns2 -6 addr add 2001:db8:101::2/64 dev veth2 nodad
	ip -netns $ns2 -6 addr add 2001:db8:103::2/64 dev veth4 nodad
	ip -netns $ns2 -6 addr add 2001:db8:104::1/64 dev dummy1 nodad

	ip -netns $ns2 addr add 172.16.101.2/24 dev veth2
	ip -netns $ns2 addr add 172.16.103.2/24 dev veth4
	ip -netns $ns2 addr add 172.16.104.1/24 dev dummy1

	set +e
}

forwarding_cleanup()
{
	cleanup_ns $ns3

	route_cleanup
}

# extend route_setup with an ns3 reachable through ns2 over both devices
forwarding_setup()
{
	forwarding_cleanup

	route_setup

	setup_ns ns3

	ip link add veth5 netns $ns3 type veth peer name veth6 netns $ns2
	ip -netns $ns3 link set veth5 up
	ip -netns $ns2 link set veth6 up

	ip -netns $ns3 -4 addr add dev veth5 172.16.105.1/24
	ip -netns $ns2 -4 addr add dev veth6 172.16.105.2/24
	ip -netns $ns3 -4 route add 172.16.100.0/22 via 172.16.105.2

	ip -netns $ns3 -6 addr add dev veth5 2001:db8:105::1/64 nodad
	ip -netns $ns2 -6 addr add dev veth6 2001:db8:105::2/64 nodad
	ip -netns $ns3 -6 route add 2001:db8:101::/33 via 2001:db8:105::2
}

# assumption is that basic add of a single path route works
# otherwise just adding an address on an interface is broken
ipv6_rt_add()
{
	local rc

	echo
	echo "IPv6 route add / append tests"

	# route add same prefix - fails with EEXISTS b/c ip adds NLM_F_EXCL
	add_route6 "2001:db8:104::/64" "via 2001:db8:101::2"
	run_cmd "$IP -6 ro add 2001:db8:104::/64 via 2001:db8:103::2"
	log_test $? 2 "Attempt to add duplicate route - gw"

	# route add same prefix - fails with EEXISTS b/c ip adds NLM_F_EXCL
	add_route6 "2001:db8:104::/64" "via 2001:db8:101::2"
	run_cmd "$IP -6 ro add 2001:db8:104::/64 dev veth3"
	log_test $? 2 "Attempt to add duplicate route - dev only"

	# route add same prefix - fails with EEXISTS b/c ip adds NLM_F_EXCL
	add_route6 "2001:db8:104::/64" "via 2001:db8:101::2"
	run_cmd "$IP -6 ro add unreachable 2001:db8:104::/64"
	log_test $? 2 "Attempt to add duplicate route - reject route"

	# route append with same prefix adds a new route
	# - iproute2 sets NLM_F_CREATE | NLM_F_APPEND
	add_route6 "2001:db8:104::/64" "via 2001:db8:101::2"
	run_cmd "$IP -6 ro append 2001:db8:104::/64 via 2001:db8:103::2"
	check_route6 "2001:db8:104::/64 metric 1024 nexthop via 2001:db8:101::2 dev veth1 weight 1 nexthop via 2001:db8:103::2 dev veth3 weight 1"
	log_test $? 0 "Append nexthop to existing route - gw"

	# insert mpath directly
	add_route6 "2001:db8:104::/64" "nexthop via 2001:db8:101::2 nexthop via 2001:db8:103::2"
	check_route6  "2001:db8:104::/64 metric 1024 nexthop via 2001:db8:101::2 dev veth1 weight 1 nexthop via 2001:db8:103::2 dev veth3 weight 1"
	log_test $? 0 "Add multipath route"

	add_route6 "2001:db8:104::/64" "nexthop via 2001:db8:101::2 nexthop via 2001:db8:103::2"
	run_cmd "$IP -6 ro add 2001:db8:104::/64 nexthop via 2001:db8:101::2 nexthop via 2001:db8:103::2"
	log_test $? 2 "Attempt to add duplicate multipath route"

	# insert of a second route without append but different metric
	add_route6 "2001:db8:104::/64" "via 2001:db8:101::2"
	run_cmd "$IP -6 ro add 2001:db8:104::/64 via 2001:db8:103::2 metric 512"
	rc=$?
	if [ $rc -eq 0 ]; then
		run_cmd "$IP -6 ro add 2001:db8:104::/64 via 2001:db8:103::3 metric 256"
		rc=$?
	fi
	log_test $rc 0 "Route add with different metrics"

	run_cmd "$IP -6 ro del 2001:db8:104::/64 metric 512"
	rc=$?
	if [ $rc -eq 0 ]; then
		check_route6 "2001:db8:104::/64 via 2001:db8:103::3 dev veth3 metric 256 2001:db8:104::/64 via 2001:db8:101::2 dev veth1 metric 1024"
		rc=$?
	fi
	log_test $rc 0 "Route delete with metric"
}

ipv6_rt_replace_single()
{
	# single path with single path
	#
	add_initial_route6 "via 2001:db8:101::2"
	run_cmd "$IP -6 ro replace 2001:db8:104::/64 via 2001:db8:103::2"
	check_route6 "2001:db8:104::/64 via 2001:db8:103::2 dev veth3 metric 1024"
	log_test $? 0 "Single path with single path"

	# single path with multipath
	#
	add_initial_route6 "nexthop via 2001:db8:101::2"
	run_cmd "$IP -6 ro replace 2001:db8:104::/64 nexthop via 2001:db8:101::3 nexthop via 2001:db8:103::2"
	check_route6 "2001:db8:104::/64 metric 1024 nexthop via 2001:db8:101::3 dev veth1 weight 1 nexthop via 2001:db8:103::2 dev veth3 weight 1"
	log_test $? 0 "Single path with multipath"

	# single path with single path using MULTIPATH attribute
	#
	add_initial_route6 "via 2001:db8:101::2"
	run_cmd "$IP -6 ro replace 2001:db8:104::/64 nexthop via 2001:db8:103::2"
	check_route6 "2001:db8:104::/64 via 2001:db8:103::2 dev veth3 metric 1024"
	log_test $? 0 "Single path with single path via multipath attribute"

	# route replace fails - invalid nexthop
	add_initial_route6 "via 2001:db8:101::2"
	run_cmd "$IP -6 ro replace 2001:db8:104::/64 via 2001:db8:104::2"
	if [ $? -eq 0 ]; then
		# previous command is expected to fail so if it returns 0
		# that means the test failed.
		log_test 0 1 "Invalid nexthop"
	else
		check_route6 "2001:db8:104::/64 via 2001:db8:101::2 dev veth1 metric 1024"
		log_test $? 0 "Invalid nexthop"
	fi

	# replace non-existent route
	# - note use of change versus replace since ip adds NLM_F_CREATE
	#   for replace
	add_initial_route6 "via 2001:db8:101::2"
	run_cmd "$IP -6 ro change 2001:db8:105::/64 via 2001:db8:101::2"
	log_test $? 2 "Single path - replace of non-existent route"
}

ipv6_rt_replace_mpath()
{
	# multipath with multipath
	add_initial_route6 "nexthop via 2001:db8:101::2 nexthop via 2001:db8:103::2"
	run_cmd "$IP -6 ro replace 2001:db8:104::/64 nexthop via 2001:db8:101::3 nexthop via 2001:db8:103::3"
	check_route6  "2001:db8:104::/64 metric 1024 nexthop via 2001:db8:101::3 dev veth1 weight 1 nexthop via 2001:db8:103::3 dev veth3 weight 1"
	log_test $? 0 "Multipath with multipath"

	# multipath with single
	add_initial_route6 "nexthop via 2001:db8:101::2 nexthop via 2001:db8:103::2"
	run_cmd "$IP -6 ro replace 2001:db8:104::/64 via 2001:db8:101::3"
	check_route6  "2001:db8:104::/64 via 2001:db8:101::3 dev veth1 metric 1024"
	log_test $? 0 "Multipath with single path"

	# multipath with single
	add_initial_route6 "nexthop via 2001:db8:101::2 nexthop via 2001:db8:103::2"
	run_cmd "$IP -6 ro replace 2001:db8:104::/64 nexthop via 2001:db8:101::3"
	check_route6 "2001:db8:104::/64 via 2001:db8:101::3 dev veth1 metric 1024"
	log_test $? 0 "Multipath with single path via multipath attribute"

	# multipath with dev-only
	add_initial_route6 "nexthop via 2001:db8:101::2 nexthop via 2001:db8:103::2"
	run_cmd "$IP -6 ro replace 2001:db8:104::/64 dev veth1"
	check_route6 "2001:db8:104::/64 dev veth1 metric 1024"
	log_test $? 0 "Multipath with dev-only"

	# route replace fails - invalid nexthop 1
	add_initial_route6 "nexthop via 2001:db8:101::2 nexthop via 2001:db8:103::2"
	run_cmd "$IP -6 ro replace 2001:db8:104::/64 nexthop via 2001:db8:111::3 nexthop via 2001:db8:103::3"
	check_route6  "2001:db8:104::/64 metric 1024 nexthop via 2001:db8:101::2 dev veth1 weight 1 nexthop via 2001:db8:103::2 dev veth3 weight 1"
	log_test $? 0 "Multipath - invalid first nexthop"

	# route replace fails - invalid nexthop 2
	add_initial_route6 "nexthop via 2001:db8:101::2 nexthop via 2001:db8:103::2"
	run_cmd "$IP -6 ro replace 2001:db8:104::/64 nexthop via 2001:db8:101::3 nexthop via 2001:db8:113::3"
	check_route6  "2001:db8:104::/64 metric 1024 nexthop via 2001:db8:101::2 dev veth1 weight 1 nexthop via 2001:db8:103::2 dev veth3 weight 1"
	log_test $? 0 "Multipath - invalid second nexthop"

	# multipath non-existent route
	add_initial_route6 "nexthop via 2001:db8:101::2 nexthop via 2001:db8:103::2"
	run_cmd "$IP -6 ro change 2001:db8:105::/64 nexthop via 2001:db8:101::3 nexthop via 2001:db8:103::3"
	log_test $? 2 "Multipath - replace of non-existent route"
}

ipv6_rt_replace()
{
	echo
	echo "IPv6 route replace tests"

	ipv6_rt_replace_single
	ipv6_rt_replace_mpath
}

ipv6_rt_dsfield()
{
	echo
	echo "IPv6 route with dsfield tests"

	run_cmd "$IP -6 route flush 2001:db8:102::/64"

	# IPv6 doesn't support routing based on dsfield
	run_cmd "$IP -6 route add 2001:db8:102::/64 dsfield 0x04 via 2001:db8:101::2"
	log_test $? 2 "Reject route with dsfield"
}

ipv6_route_test()
{
	route_setup

	ipv6_rt_add
	ipv6_rt_replace
	ipv6_rt_dsfield

	route_cleanup
}

ip_addr_metric_check()
{
	ip addr help 2>&1 | grep -q metric
	if [ $? -ne 0 ]; then
		echo "iproute2 command does not support metric for addresses. Skipping test"
		return 1
	fi

	return 0
}

ipv6_addr_metric_test()
{
	local rc

	echo
	echo "IPv6 prefix route tests"

	ip_addr_metric_check || return 1

	setup

	set -e
	$IP li add dummy1 type dummy
	$IP li add dummy2 type dummy
	$IP li set dummy1 up
	$IP li set dummy2 up

	# default entry is metric 256
	run_cmd "$IP -6 addr add dev dummy1 2001:db8:104::1/64"
	run_cmd "$IP -6 addr add dev dummy2 2001:db8:104::2/64"
	set +e

	check_route6 "2001:db8:104::/64 dev dummy1 proto kernel metric 256 2001:db8:104::/64 dev dummy2 proto kernel metric 256"
	log_test $? 0 "Default metric"

	set -e
	run_cmd "$IP -6 addr flush dev dummy1"
	run_cmd "$IP -6 addr add dev dummy1 2001:db8:104::1/64 metric 257"
	set +e

	check_route6 "2001:db8:104::/64 dev dummy2 proto kernel metric 256 2001:db8:104::/64 dev dummy1 proto kernel metric 257"
	log_test $? 0 "User specified metric on first device"

	set -e
	run_cmd "$IP -6 addr flush dev dummy2"
	run_cmd "$IP -6 addr add dev dummy2 2001:db8:104::2/64 metric 258"
	set +e

	check_route6 "2001:db8:104::/64 dev dummy1 proto kernel metric 257 2001:db8:104::/64 dev dummy2 proto kernel metric 258"
	log_test $? 0 "User specified metric on second device"

	run_cmd "$IP -6 addr del dev dummy1 2001:db8:104::1/64 metric 257"
	rc=$?
	if [ $rc -eq 0 ]; then
		check_route6 "2001:db8:104::/64 dev dummy2 proto kernel metric 258"
		rc=$?
	fi
	log_test $rc 0 "Delete of address on first device"

	run_cmd "$IP -6 addr change dev dummy2 2001:db8:104::2/64 metric 259"
	rc=$?
	if [ $rc -eq 0 ]; then
		check_route6 "2001:db8:104::/64 dev dummy2 proto kernel metric 259"
		rc=$?
	fi
	log_test $rc 0 "Modify metric of address"

	# verify prefix route removed on down
	run_cmd "ip netns exec $ns1 sysctl -qw net.ipv6.conf.all.keep_addr_on_down=1"
	run_cmd "$IP li set dev dummy2 down"
	rc=$?
	if [ $rc -eq 0 ]; then
		out=$($IP -6 ro ls match 2001:db8:104::/64)
		check_expected "${out}" ""
		rc=$?
	fi
	log_test $rc 0 "Prefix route removed on link down"

	# verify prefix route re-inserted with assigned metric
	run_cmd "$IP li set dev dummy2 up"
	rc=$?
	if [ $rc -eq 0 ]; then
		check_route6 "2001:db8:104::/64 dev dummy2 proto kernel metric 259"
		rc=$?
	fi
	log_test $rc 0 "Prefix route with metric on link up"

	# verify peer metric added correctly
	set -e
	run_cmd "$IP -6 addr flush dev dummy2"
	run_cmd "$IP -6 addr add dev dummy2 2001:db8:104::1 peer 2001:db8:104::2 metric 260"
	set +e

	check_route6 "2001:db8:104::1 dev dummy2 proto kernel metric 260"
	log_test $? 0 "Set metric with peer route on local side"
	check_route6 "2001:db8:104::2 dev dummy2 proto kernel metric 260"
	log_test $? 0 "Set metric with peer route on peer side"

	set -e
	run_cmd "$IP -6 addr change dev dummy2 2001:db8:104::1 peer 2001:db8:104::3 metric 261"
	set +e

	check_route6 "2001:db8:104::1 dev dummy2 proto kernel metric 261"
	log_test $? 0 "Modify metric and peer address on local side"
	check_route6 "2001:db8:104::3 dev dummy2 proto kernel metric 261"
	log_test $? 0 "Modify metric and peer address on peer side"

	$IP li del dummy1
	$IP li del dummy2
	cleanup
}

ipv6_route_metrics_test()
{
	local rc

	echo
	echo "IPv6 routes with metrics"

	route_setup

	#
	# single path with metrics
	#
	run_cmd "$IP -6 ro add 2001:db8:111::/64 via 2001:db8:101::2 mtu 1400"
	rc=$?
	if [ $rc -eq 0 ]; then
		check_route6  "2001:db8:111::/64 via 2001:db8:101::2 dev veth1 metric 1024 mtu 1400"
		rc=$?
	fi
	log_test $rc 0 "Single path route with mtu metric"


	#
	# multipath via separate routes with metrics
	#
	run_cmd "$IP -6 ro add 2001:db8:112::/64 via 2001:db8:101::2 mtu 1400"
	run_cmd "$IP -6 ro append 2001:db8:112::/64 via 2001:db8:103::2"
	rc=$?
	if [ $rc -eq 0 ]; then
		check_route6 "2001:db8:112::/64 metric 1024 mtu 1400 nexthop via 2001:db8:101::2 dev veth1 weight 1 nexthop via 2001:db8:103::2 dev veth3 weight 1"
		rc=$?
	fi
	log_test $rc 0 "Multipath route via 2 single routes with mtu metric on first"

	# second route is coalesced to first to make a multipath route.
	# MTU of the second path is hidden from display!
	run_cmd "$IP -6 ro add 2001:db8:113::/64 via 2001:db8:101::2"
	run_cmd "$IP -6 ro append 2001:db8:113::/64 via 2001:db8:103::2 mtu 1400"
	rc=$?
	if [ $rc -eq 0 ]; then
		check_route6 "2001:db8:113::/64 metric 1024 nexthop via 2001:db8:101::2 dev veth1 weight 1 nexthop via 2001:db8:103::2 dev veth3 weight 1"
		rc=$?
	fi
	log_test $rc 0 "Multipath route via 2 single routes with mtu metric on 2nd"

	run_cmd "$IP -6 ro del 2001:db8:113::/64 via 2001:db8:101::2"
	if [ $? -eq 0 ]; then
		check_route6 "2001:db8:113::/64 via 2001:db8:103::2 dev veth3 metric 1024 mtu 1400"
		log_test $? 0 "    MTU of second leg"
	fi

	#
	# multipath with metrics
	#
	run_cmd "$IP -6 ro add 2001:db8:115::/64 mtu 1400 nexthop via 2001:db8:101::2 nexthop via 2001:db8:103::2"
	rc=$?
	if [ $rc -eq 0 ]; then
		check_route6  "2001:db8:115::/64 metric 1024 mtu 1400 nexthop via 2001:db8:101::2 dev veth1 weight 1 nexthop via 2001:db8:103::2 dev veth3 weight 1"
		rc=$?
	fi
	log_test $rc 0 "Multipath route with mtu metric"

	$IP -6 ro add 2001:db8:104::/64 via 2001:db8:101::2 mtu 1300
	run_cmd "ip netns exec $ns1 ${ping6} -w1 -c1 -s 1500 2001:db8:104::1"
	log_test $? 0 "Using route with mtu metric"

	run_cmd "$IP -6 ro add 2001:db8:114::/64 via  2001:db8:101::2  congctl lock foo"
	log_test $? 2 "Invalid metric (fails metric_convert)"

	route_cleanup
}

# add route for a prefix, flushing any existing routes first
# expected to be the first step of a test
add_route()
{
	local pfx="$1"
	local nh="$2"
	local out

	if [ "$VERBOSE" = "1" ]; then
		echo
		echo "    ##################################################"
		echo
	fi

	run_cmd "$IP ro flush ${pfx}"
	[ $? -ne 0 ] && exit 1

	out=$($IP ro ls match ${pfx})
	if [ -n "$out" ]; then
		echo "Failed to flush routes for prefix used for tests."
		exit 1
	fi

	run_cmd "$IP ro add ${pfx} ${nh}"
	if [ $? -ne 0 ]; then
		echo "Failed to add initial route for test."
		exit 1
	fi
}

# add initial route - used in replace route tests
add_initial_route()
{
	add_route "172.16.104.0/24" "$1"
}

check_route()
{
	local pfx
	local expected="$1"
	local out

	set -- $expected
	pfx=$1
	[ "${pfx}" = "unreachable" ] && pfx=$2

	out=$($IP ro ls match ${pfx})
	check_expected "${out}" "${expected}"
}

# assumption is that basic add of a single path route works
# otherwise just adding an address on an interface is broken
ipv4_rt_add()
{
	local rc

	echo
	echo "IPv4 route add / append tests"

	# route add same prefix - fails with EEXISTS b/c ip adds NLM_F_EXCL
	add_route "172.16.104.0/24" "via 172.16.101.2"
	run_cmd "$IP ro add 172.16.104.0/24 via 172.16.103.2"
	log_test $? 2 "Attempt to add duplicate route - gw"

	# route add same prefix - fails with EEXISTS b/c ip adds NLM_F_EXCL
	add_route "172.16.104.0/24" "via 172.16.101.2"
	run_cmd "$IP ro add 172.16.104.0/24 dev veth3"
	log_test $? 2 "Attempt to add duplicate route - dev only"

	# route add same prefix - fails with EEXISTS b/c ip adds NLM_F_EXCL
	add_route "172.16.104.0/24" "via 172.16.101.2"
	run_cmd "$IP ro add unreachable 172.16.104.0/24"
	log_test $? 2 "Attempt to add duplicate route - reject route"

	# iproute2 prepend only sets NLM_F_CREATE
	# - adds a new route; does NOT convert existing route to ECMP
	add_route "172.16.104.0/24" "via 172.16.101.2"
	run_cmd "$IP ro prepend 172.16.104.0/24 via 172.16.103.2"
	check_route "172.16.104.0/24 via 172.16.103.2 dev veth3 172.16.104.0/24 via 172.16.101.2 dev veth1"
	log_test $? 0 "Add new nexthop for existing prefix"

	# route append with same prefix adds a new route
	# - iproute2 sets NLM_F_CREATE | NLM_F_APPEND
	add_route "172.16.104.0/24" "via 172.16.101.2"
	run_cmd "$IP ro append 172.16.104.0/24 via 172.16.103.2"
	check_route "172.16.104.0/24 via 172.16.101.2 dev veth1 172.16.104.0/24 via 172.16.103.2 dev veth3"
	log_test $? 0 "Append nexthop to existing route - gw"

	add_route "172.16.104.0/24" "via 172.16.101.2"
	run_cmd "$IP ro append 172.16.104.0/24 dev veth3"
	check_route "172.16.104.0/24 via 172.16.101.2 dev veth1 172.16.104.0/24 dev veth3 scope link"
	log_test $? 0 "Append nexthop to existing route - dev only"

	add_route "172.16.104.0/24" "via 172.16.101.2"
	run_cmd "$IP ro append unreachable 172.16.104.0/24"
	check_route "172.16.104.0/24 via 172.16.101.2 dev veth1 unreachable 172.16.104.0/24"
	log_test $? 0 "Append nexthop to existing route - reject route"

	run_cmd "$IP ro flush 172.16.104.0/24"
	run_cmd "$IP ro add unreachable 172.16.104.0/24"
	run_cmd "$IP ro append 172.16.104.0/24 via 172.16.103.2"
	check_route "unreachable 172.16.104.0/24 172.16.104.0/24 via 172.16.103.2 dev veth3"
	log_test $? 0 "Append nexthop to existing reject route - gw"

	run_cmd "$IP ro flush 172.16.104.0/24"
	run_cmd "$IP ro add unreachable 172.16.104.0/24"
	run_cmd "$IP ro append 172.16.104.0/24 dev veth3"
	check_route "unreachable 172.16.104.0/24 172.16.104.0/24 dev veth3 scope link"
	log_test $? 0 "Append nexthop to existing reject route - dev only"

	# insert mpath directly
	add_route "172.16.104.0/24" "nexthop via 172.16.101.2 nexthop via 172.16.103.2"
	check_route  "172.16.104.0/24 nexthop via 172.16.101.2 dev veth1 weight 1 nexthop via 172.16.103.2 dev veth3 weight 1"
	log_test $? 0 "add multipath route"

	add_route "172.16.104.0/24" "nexthop via 172.16.101.2 nexthop via 172.16.103.2"
	run_cmd "$IP ro add 172.16.104.0/24 nexthop via 172.16.101.2 nexthop via 172.16.103.2"
	log_test $? 2 "Attempt to add duplicate multipath route"

	# insert of a second route without append but different metric
	add_route "172.16.104.0/24" "via 172.16.101.2"
	run_cmd "$IP ro add 172.16.104.0/24 via 172.16.103.2 metric 512"
	rc=$?
	if [ $rc -eq 0 ]; then
		run_cmd "$IP ro add 172.16.104.0/24 via 172.16.103.3 metric 256"
		rc=$?
	fi
	log_test $rc 0 "Route add with different metrics"

	run_cmd "$IP ro del 172.16.104.0/24 metric 512"
	rc=$?
	if [ $rc -eq 0 ]; then
		check_route "172.16.104.0/24 via 172.16.101.2 dev veth1 172.16.104.0/24 via 172.16.103.3 dev veth3 metric 256"
		rc=$?
	fi
	log_test $rc 0 "Route delete with metric"
}

ipv4_rt_replace_single()
{
	# single path with single path
	#
	add_initial_route "via 172.16.101.2"
	run_cmd "$IP ro replace 172.16.104.0/24 via 172.16.103.2"
	check_route "172.16.104.0/24 via 172.16.103.2 dev veth3"
	log_test $? 0 "Single path with single path"

	# single path with multipath
	#
	add_initial_route "nexthop via 172.16.101.2"
	run_cmd "$IP ro replace 172.16.104.0/24 nexthop via 172.16.101.3 nexthop via 172.16.103.2"
	check_route "172.16.104.0/24 nexthop via 172.16.101.3 dev veth1 weight 1 nexthop via 172.16.103.2 dev veth3 weight 1"
	log_test $? 0 "Single path with multipath"

	# single path with reject
	#
	add_initial_route "nexthop via 172.16.101.2"
	run_cmd "$IP ro replace unreachable 172.16.104.0/24"
	check_route "unreachable 172.16.104.0/24"
	log_test $? 0 "Single path with reject route"

	# single path with single path using MULTIPATH attribute
	#
	add_initial_route "via 172.16.101.2"
	run_cmd "$IP ro replace 172.16.104.0/24 nexthop via 172.16.103.2"
	check_route "172.16.104.0/24 via 172.16.103.2 dev veth3"
	log_test $? 0 "Single path with single path via multipath attribute"

	# route replace fails - invalid nexthop
	add_initial_route "via 172.16.101.2"
	run_cmd "$IP ro replace 172.16.104.0/24 via 2001:db8:104::2"
	if [ $? -eq 0 ]; then
		# previous command is expected to fail so if it returns 0
		# that means the test failed.
		log_test 0 1 "Invalid nexthop"
	else
		check_route "172.16.104.0/24 via 172.16.101.2 dev veth1"
		log_test $? 0 "Invalid nexthop"
	fi

	# replace non-existent route
	# - note use of change versus replace since ip adds NLM_F_CREATE
	#   for replace
	add_initial_route "via 172.16.101.2"
	run_cmd "$IP ro change 172.16.105.0/24 via 172.16.101.2"
	log_test $? 2 "Single path - replace of non-existent route"
}

ipv4_rt_replace_mpath()
{
	# multipath with multipath
	add_initial_route "nexthop via 172.16.101.2 nexthop via 172.16.103.2"
	run_cmd "$IP ro replace 172.16.104.0/24 nexthop via 172.16.101.3 nexthop via 172.16.103.3"
	check_route  "172.16.104.0/24 nexthop via 172.16.101.3 dev veth1 weight 1 nexthop via 172.16.103.3 dev veth3 weight 1"
	log_test $? 0 "Multipath with multipath"

	# multipath with single
	add_initial_route "nexthop via 172.16.101.2 nexthop via 172.16.103.2"
	run_cmd "$IP ro replace 172.16.104.0/24 via 172.16.101.3"
	check_route  "172.16.104.0/24 via 172.16.101.3 dev veth1"
	log_test $? 0 "Multipath with single path"

	# multipath with single
	add_initial_route "nexthop via 172.16.101.2 nexthop via 172.16.103.2"
	run_cmd "$IP ro replace 172.16.104.0/24 nexthop via 172.16.101.3"
	check_route "172.16.104.0/24 via 172.16.101.3 dev veth1"
	log_test $? 0 "Multipath with single path via multipath attribute"

	# multipath with reject
	add_initial_route "nexthop via 172.16.101.2 nexthop via 172.16.103.2"
	run_cmd "$IP ro replace unreachable 172.16.104.0/24"
	check_route "unreachable 172.16.104.0/24"
	log_test $? 0 "Multipath with reject route"

	# route replace fails - invalid nexthop 1
	add_initial_route "nexthop via 172.16.101.2 nexthop via 172.16.103.2"
	run_cmd "$IP ro replace 172.16.104.0/24 nexthop via 172.16.111.3 nexthop via 172.16.103.3"
	check_route  "172.16.104.0/24 nexthop via 172.16.101.2 dev veth1 weight 1 nexthop via 172.16.103.2 dev veth3 weight 1"
	log_test $? 0 "Multipath - invalid first nexthop"

	# route replace fails - invalid nexthop 2
	add_initial_route "nexthop via 172.16.101.2 nexthop via 172.16.103.2"
	run_cmd "$IP ro replace 172.16.104.0/24 nexthop via 172.16.101.3 nexthop via 172.16.113.3"
	check_route  "172.16.104.0/24 nexthop via 172.16.101.2 dev veth1 weight 1 nexthop via 172.16.103.2 dev veth3 weight 1"
	log_test $? 0 "Multipath - invalid second nexthop"

	# multipath non-existent route
	add_initial_route "nexthop via 172.16.101.2 nexthop via 172.16.103.2"
	run_cmd "$IP ro change 172.16.105.0/24 nexthop via 172.16.101.3 nexthop via 172.16.103.3"
	log_test $? 2 "Multipath - replace of non-existent route"
}

ipv4_rt_replace()
{
	echo
	echo "IPv4 route replace tests"

	ipv4_rt_replace_single
	ipv4_rt_replace_mpath
}

# checks that cached input route on VRF port is deleted
# when VRF is deleted
ipv4_local_rt_cache()
{
	run_cmd "ip addr add 10.0.0.1/32 dev lo"
	run_cmd "setup_ns test-ns"
	run_cmd "ip link add veth-outside type veth peer name veth-inside"
	run_cmd "ip link add vrf-100 type vrf table 1100"
	run_cmd "ip link set veth-outside master vrf-100"
	run_cmd "ip link set veth-inside netns $test-ns"
	run_cmd "ip link set veth-outside up"
	run_cmd "ip link set vrf-100 up"
	run_cmd "ip route add 10.1.1.1/32 dev veth-outside table 1100"
	run_cmd "ip netns exec $test-ns ip link set veth-inside up"
	run_cmd "ip netns exec $test-ns ip addr add 10.1.1.1/32 dev veth-inside"
	run_cmd "ip netns exec $test-ns ip route add 10.0.0.1/32 dev veth-inside"
	run_cmd "ip netns exec $test-ns ip route add default via 10.0.0.1"
	run_cmd "ip netns exec $test-ns ping 10.0.0.1 -c 1 -i 1"
	run_cmd "ip link delete vrf-100"

	# if we do not hang test is a success
	log_test $? 0 "Cached route removed from VRF port device"
}

ipv4_rt_dsfield()
{
	echo
	echo "IPv4 route with dsfield tests"

	run_cmd "$IP route flush 172.16.102.0/24"

	# New routes should reject dsfield options that interfere with ECN
	run_cmd "$IP route add 172.16.102.0/24 dsfield 0x01 via 172.16.101.2"
	log_test $? 2 "Reject route with dsfield 0x01"

	run_cmd "$IP route add 172.16.102.0/24 dsfield 0x02 via 172.16.101.2"
	log_test $? 2 "Reject route with dsfield 0x02"

	run_cmd "$IP route add 172.16.102.0/24 dsfield 0x03 via 172.16.101.2"
	log_test $? 2 "Reject route with dsfield 0x03"

	# A generic route that doesn't take DSCP into account
	run_cmd "$IP route add 172.16.102.0/24 via 172.16.101.2"

	# A more specific route for DSCP 0x10
	run_cmd "$IP route add 172.16.102.0/24 dsfield 0x10 via 172.16.103.2"

	# DSCP 0x10 should match the specific route, no matter the ECN bits
	$IP route get fibmatch 172.16.102.1 dsfield 0x10 | \
		grep -q "172.16.102.0/24 tos 0x10 via 172.16.103.2"
	log_test $? 0 "IPv4 route with DSCP and ECN:Not-ECT"

	$IP route get fibmatch 172.16.102.1 dsfield 0x11 | \
		grep -q "172.16.102.0/24 tos 0x10 via 172.16.103.2"
	log_test $? 0 "IPv4 route with DSCP and ECN:ECT(1)"

	$IP route get fibmatch 172.16.102.1 dsfield 0x12 | \
		grep -q "172.16.102.0/24 tos 0x10 via 172.16.103.2"
	log_test $? 0 "IPv4 route with DSCP and ECN:ECT(0)"

	$IP route get fibmatch 172.16.102.1 dsfield 0x13 | \
		grep -q "172.16.102.0/24 tos 0x10 via 172.16.103.2"
	log_test $? 0 "IPv4 route with DSCP and ECN:CE"

	# Unknown DSCP should match the generic route, no matter the ECN bits
	$IP route get fibmatch 172.16.102.1 dsfield 0x14 | \
		grep -q "172.16.102.0/24 via 172.16.101.2"
	log_test $? 0 "IPv4 route with unknown DSCP and ECN:Not-ECT"

	$IP route get fibmatch 172.16.102.1 dsfield 0x15 | \
		grep -q "172.16.102.0/24 via 172.16.101.2"
	log_test $? 0 "IPv4 route with unknown DSCP and ECN:ECT(1)"

	$IP route get fibmatch 172.16.102.1 dsfield 0x16 | \
		grep -q "172.16.102.0/24 via 172.16.101.2"
	log_test $? 0 "IPv4 route with unknown DSCP and ECN:ECT(0)"

	$IP route get fibmatch 172.16.102.1 dsfield 0x17 | \
		grep -q "172.16.102.0/24 via 172.16.101.2"
	log_test $? 0 "IPv4 route with unknown DSCP and ECN:CE"

	# Null DSCP should match the generic route, no matter the ECN bits
	$IP route get fibmatch 172.16.102.1 dsfield 0x00 | \
		grep -q "172.16.102.0/24 via 172.16.101.2"
	log_test $? 0 "IPv4 route with no DSCP and ECN:Not-ECT"

	$IP route get fibmatch 172.16.102.1 dsfield 0x01 | \
		grep -q "172.16.102.0/24 via 172.16.101.2"
	log_test $? 0 "IPv4 route with no DSCP and ECN:ECT(1)"

	$IP route get fibmatch 172.16.102.1 dsfield 0x02 | \
		grep -q "172.16.102.0/24 via 172.16.101.2"
	log_test $? 0 "IPv4 route with no DSCP and ECN:ECT(0)"

	$IP route get fibmatch 172.16.102.1 dsfield 0x03 | \
		grep -q "172.16.102.0/24 via 172.16.101.2"
	log_test $? 0 "IPv4 route with no DSCP and ECN:CE"
}

ipv4_route_test()
{
	route_setup

	ipv4_rt_add
	ipv4_rt_replace
	ipv4_local_rt_cache
	ipv4_rt_dsfield

	route_cleanup
}

ipv4_addr_metric_test()
{
	local rc

	echo
	echo "IPv4 prefix route tests"

	ip_addr_metric_check || return 1

	setup

	set -e
	$IP li add dummy1 type dummy
	$IP li add dummy2 type dummy
	$IP li set dummy1 up
	$IP li set dummy2 up

	# default entry is metric 256
	run_cmd "$IP addr add dev dummy1 172.16.104.1/24"
	run_cmd "$IP addr add dev dummy2 172.16.104.2/24"
	set +e

	check_route "172.16.104.0/24 dev dummy1 proto kernel scope link src 172.16.104.1 172.16.104.0/24 dev dummy2 proto kernel scope link src 172.16.104.2"
	log_test $? 0 "Default metric"

	set -e
	run_cmd "$IP addr flush dev dummy1"
	run_cmd "$IP addr add dev dummy1 172.16.104.1/24 metric 257"
	set +e

	check_route "172.16.104.0/24 dev dummy2 proto kernel scope link src 172.16.104.2 172.16.104.0/24 dev dummy1 proto kernel scope link src 172.16.104.1 metric 257"
	log_test $? 0 "User specified metric on first device"

	set -e
	run_cmd "$IP addr flush dev dummy2"
	run_cmd "$IP addr add dev dummy2 172.16.104.2/24 metric 258"
	set +e

	check_route "172.16.104.0/24 dev dummy1 proto kernel scope link src 172.16.104.1 metric 257 172.16.104.0/24 dev dummy2 proto kernel scope link src 172.16.104.2 metric 258"
	log_test $? 0 "User specified metric on second device"

	run_cmd "$IP addr del dev dummy1 172.16.104.1/24 metric 257"
	rc=$?
	if [ $rc -eq 0 ]; then
		check_route "172.16.104.0/24 dev dummy2 proto kernel scope link src 172.16.104.2 metric 258"
		rc=$?
	fi
	log_test $rc 0 "Delete of address on first device"

	run_cmd "$IP addr change dev dummy2 172.16.104.2/24 metric 259"
	rc=$?
	if [ $rc -eq 0 ]; then
		check_route "172.16.104.0/24 dev dummy2 proto kernel scope link src 172.16.104.2 metric 259"
		rc=$?
	fi
	log_test $rc 0 "Modify metric of address"

	# verify prefix route removed on down
	run_cmd "$IP li set dev dummy2 down"
	rc=$?
	if [ $rc -eq 0 ]; then
		out=$($IP ro ls match 172.16.104.0/24)
		check_expected "${out}" ""
		rc=$?
	fi
	log_test $rc 0 "Prefix route removed on link down"

	# verify prefix route re-inserted with assigned metric
	run_cmd "$IP li set dev dummy2 up"
	rc=$?
	if [ $rc -eq 0 ]; then
		check_route "172.16.104.0/24 dev dummy2 proto kernel scope link src 172.16.104.2 metric 259"
		rc=$?
	fi
	log_test $rc 0 "Prefix route with metric on link up"

	# explicitly check for metric changes on edge scenarios
	run_cmd "$IP addr flush dev dummy2"
	run_cmd "$IP addr add dev dummy2 172.16.104.0/24 metric 259"
	run_cmd "$IP addr change dev dummy2 172.16.104.0/24 metric 260"
	rc=$?
	if [ $rc -eq 0 ]; then
		check_route "172.16.104.0/24 dev dummy2 proto kernel scope link src 172.16.104.0 metric 260"
		rc=$?
	fi
	log_test $rc 0 "Modify metric of .0/24 address"

	run_cmd "$IP addr flush dev dummy2"
	run_cmd "$IP addr add dev dummy2 172.16.104.1/32 peer 172.16.104.2 metric 260"
	rc=$?
	if [ $rc -eq 0 ]; then
		check_route "172.16.104.2 dev dummy2 proto kernel scope link src 172.16.104.1 metric 260"
		rc=$?
	fi
	log_test $rc 0 "Set metric of address with peer route"

	run_cmd "$IP addr change dev dummy2 172.16.104.1/32 peer 172.16.104.3 metric 261"
	rc=$?
	if [ $rc -eq 0 ]; then
		check_route "172.16.104.3 dev dummy2 proto kernel scope link src 172.16.104.1 metric 261"
		rc=$?
	fi
	log_test $rc 0 "Modify metric and peer address for peer route"

	$IP li del dummy1
	$IP li del dummy2
	cleanup
}

ipv4_route_metrics_test()
{
	local rc

	echo
	echo "IPv4 route add / append tests"

	route_setup

	run_cmd "$IP ro add 172.16.111.0/24 via 172.16.101.2 mtu 1400"
	rc=$?
	if [ $rc -eq 0 ]; then
		check_route "172.16.111.0/24 via 172.16.101.2 dev veth1 mtu 1400"
		rc=$?
	fi
	log_test $rc 0 "Single path route with mtu metric"


	run_cmd "$IP ro add 172.16.112.0/24 mtu 1400 nexthop via 172.16.101.2 nexthop via 172.16.103.2"
	rc=$?
	if [ $rc -eq 0 ]; then
		check_route "172.16.112.0/24 mtu 1400 nexthop via 172.16.101.2 dev veth1 weight 1 nexthop via 172.16.103.2 dev veth3 weight 1"
		rc=$?
	fi
	log_test $rc 0 "Multipath route with mtu metric"

	$IP ro add 172.16.104.0/24 via 172.16.101.2 mtu 1300
	run_cmd "ip netns exec $ns1 ping -w1 -c1 -s 1500 172.16.104.1"
	log_test $? 0 "Using route with mtu metric"

	run_cmd "$IP ro add 172.16.111.0/24 via 172.16.101.2 congctl lock foo"
	log_test $? 2 "Invalid metric (fails metric_convert)"

	route_cleanup
}

ipv4_del_addr_test()
{
	echo
	echo "IPv4 delete address route tests"

	setup

	set -e
	$IP li add dummy1 type dummy
	$IP li set dummy1 up
	$IP li add dummy2 type dummy
	$IP li set dummy2 up
	$IP li add red type vrf table 1111
	$IP li set red up
	$IP ro add vrf red unreachable default
	$IP li set dummy2 vrf red

	$IP addr add dev dummy1 172.16.104.1/24
	$IP addr add dev dummy1 172.16.104.11/24
	$IP addr add dev dummy1 172.16.104.12/24
	$IP addr add dev dummy1 172.16.104.13/24
	$IP addr add dev dummy2 172.16.104.1/24
	$IP addr add dev dummy2 172.16.104.11/24
	$IP addr add dev dummy2 172.16.104.12/24
	$IP route add 172.16.105.0/24 via 172.16.104.2 src 172.16.104.11
	$IP route add 172.16.106.0/24 dev lo src 172.16.104.12
	$IP route add table 0 172.16.107.0/24 via 172.16.104.2 src 172.16.104.13
	$IP route add vrf red 172.16.105.0/24 via 172.16.104.2 src 172.16.104.11
	$IP route add vrf red 172.16.106.0/24 dev lo src 172.16.104.12
	set +e

	# removing address from device in vrf should only remove route from vrf table
	echo "    Regular FIB info"

	$IP addr del dev dummy2 172.16.104.11/24
	$IP ro ls vrf red | grep -q 172.16.105.0/24
	log_test $? 1 "Route removed from VRF when source address deleted"

	$IP ro ls | grep -q 172.16.105.0/24
	log_test $? 0 "Route in default VRF not removed"

	$IP addr add dev dummy2 172.16.104.11/24
	$IP route add vrf red 172.16.105.0/24 via 172.16.104.2 src 172.16.104.11

	$IP addr del dev dummy1 172.16.104.11/24
	$IP ro ls | grep -q 172.16.105.0/24
	log_test $? 1 "Route removed in default VRF when source address deleted"

	$IP ro ls vrf red | grep -q 172.16.105.0/24
	log_test $? 0 "Route in VRF is not removed by address delete"

	# removing address from device in vrf should only remove route from vrf
	# table even when the associated fib info only differs in table ID
	echo "    Identical FIB info with different table ID"

	$IP addr del dev dummy2 172.16.104.12/24
	$IP ro ls vrf red | grep -q 172.16.106.0/24
	log_test $? 1 "Route removed from VRF when source address deleted"

	$IP ro ls | grep -q 172.16.106.0/24
	log_test $? 0 "Route in default VRF not removed"

	$IP addr add dev dummy2 172.16.104.12/24
	$IP route add vrf red 172.16.106.0/24 dev lo src 172.16.104.12

	$IP addr del dev dummy1 172.16.104.12/24
	$IP ro ls | grep -q 172.16.106.0/24
	log_test $? 1 "Route removed in default VRF when source address deleted"

	$IP ro ls vrf red | grep -q 172.16.106.0/24
	log_test $? 0 "Route in VRF is not removed by address delete"

	# removing address from device in default vrf should remove route from
	# the default vrf even when route was inserted with a table ID of 0.
	echo "    Table ID 0"

	$IP addr del dev dummy1 172.16.104.13/24
	$IP ro ls | grep -q 172.16.107.0/24
	log_test $? 1 "Route removed in default VRF when source address deleted"

	$IP li del dummy1
	$IP li del dummy2
	cleanup
}

ipv6_del_addr_test()
{
	echo
	echo "IPv6 delete address route tests"

	setup

	set -e
	for i in $(seq 6); do
		$IP li add dummy${i} up type dummy
	done

	$IP li add red up type vrf table 1111
	$IP ro add vrf red unreachable default
	for i in $(seq 4 6); do
		$IP li set dummy${i} vrf red
	done

	$IP addr add dev dummy1 fe80::1/128
	$IP addr add dev dummy1 2001:db8:101::1/64
	$IP addr add dev dummy1 2001:db8:101::10/64
	$IP addr add dev dummy1 2001:db8:101::11/64
	$IP addr add dev dummy1 2001:db8:101::12/64
	$IP addr add dev dummy1 2001:db8:101::13/64
	$IP addr add dev dummy1 2001:db8:101::14/64
	$IP addr add dev dummy1 2001:db8:101::15/64
	$IP addr add dev dummy2 fe80::1/128
	$IP addr add dev dummy2 2001:db8:101::1/64
	$IP addr add dev dummy2 2001:db8:101::11/64
	$IP addr add dev dummy3 fe80::1/128

	$IP addr add dev dummy4 2001:db8:101::1/64
	$IP addr add dev dummy4 2001:db8:101::10/64
	$IP addr add dev dummy4 2001:db8:101::11/64
	$IP addr add dev dummy4 2001:db8:101::12/64
	$IP addr add dev dummy4 2001:db8:101::13/64
	$IP addr add dev dummy4 2001:db8:101::14/64
	$IP addr add dev dummy5 2001:db8:101::1/64
	$IP addr add dev dummy5 2001:db8:101::11/64

	# Single device using src address
	$IP route add 2001:db8:110::/64 dev dummy3 src 2001:db8:101::10
	# Two devices with the same source address
	$IP route add 2001:db8:111::/64 dev dummy3 src 2001:db8:101::11
	# VRF with single device using src address
	$IP route add vrf red 2001:db8:110::/64 dev dummy6 src 2001:db8:101::10
	# VRF with two devices using src address
	$IP route add vrf red 2001:db8:111::/64 dev dummy6 src 2001:db8:101::11
	# src address and nexthop dev in same VRF
	$IP route add 2001:db8:112::/64 dev dummy3 src 2001:db8:101::12
	$IP route add vrf red 2001:db8:112::/64 dev dummy6 src 2001:db8:101::12
	# src address and nexthop device in different VRF
	$IP route add 2001:db8:113::/64 dev lo src 2001:db8:101::13
	$IP route add vrf red 2001:db8:113::/64 dev lo src 2001:db8:101::13
	# table ID 0
	$IP route add table 0 2001:db8:115::/64 via 2001:db8:101::2 src 2001:db8:101::15
	# Link local source route
	$IP route add 2001:db8:116::/64 dev dummy2 src fe80::1
	$IP route add 2001:db8:117::/64 dev dummy3 src fe80::1
	set +e

	echo "    Single device using src address"

	$IP addr del dev dummy1 2001:db8:101::10/64
	$IP -6 route show | grep -q "src 2001:db8:101::10 "
	log_test $? 1 "Prefsrc removed when src address removed on other device"

	echo "    Two devices with the same source address"

	$IP addr del dev dummy1 2001:db8:101::11/64
	$IP -6 route show | grep -q "src 2001:db8:101::11 "
	log_test $? 0 "Prefsrc not removed when src address exist on other device"

	$IP addr del dev dummy2 2001:db8:101::11/64
	$IP -6 route show | grep -q "src 2001:db8:101::11 "
	log_test $? 1 "Prefsrc removed when src address removed on all devices"

	echo "    VRF with single device using src address"

	$IP addr del dev dummy4 2001:db8:101::10/64
	$IP -6 route show vrf red | grep -q "src 2001:db8:101::10 "
	log_test $? 1 "Prefsrc removed when src address removed on other device"

	echo "    VRF with two devices using src address"

	$IP addr del dev dummy4 2001:db8:101::11/64
	$IP -6 route show vrf red | grep -q "src 2001:db8:101::11 "
	log_test $? 0 "Prefsrc not removed when src address exist on other device"

	$IP addr del dev dummy5 2001:db8:101::11/64
	$IP -6 route show vrf red | grep -q "src 2001:db8:101::11 "
	log_test $? 1 "Prefsrc removed when src address removed on all devices"

	echo "    src address and nexthop dev in same VRF"

	$IP addr del dev dummy4 2001:db8:101::12/64
	$IP -6 route show vrf red | grep -q "src 2001:db8:101::12 "
	log_test $? 1 "Prefsrc removed from VRF when source address deleted"
	$IP -6 route show | grep -q " src 2001:db8:101::12 "
	log_test $? 0 "Prefsrc in default VRF not removed"

	$IP addr add dev dummy4 2001:db8:101::12/64
	$IP route replace vrf red 2001:db8:112::/64 dev dummy6 src 2001:db8:101::12
	$IP addr del dev dummy1 2001:db8:101::12/64
	$IP -6 route show vrf red | grep -q "src 2001:db8:101::12 "
	log_test $? 0 "Prefsrc not removed from VRF when source address exist"
	$IP -6 route show | grep -q " src 2001:db8:101::12 "
	log_test $? 1 "Prefsrc in default VRF removed"

	echo "    src address and nexthop device in different VRF"

	$IP addr del dev dummy4 2001:db8:101::13/64
	$IP -6 route show vrf red | grep -q "src 2001:db8:101::13 "
	log_test $? 0 "Prefsrc not removed from VRF when nexthop dev in diff VRF"
	$IP -6 route show | grep -q "src 2001:db8:101::13 "
	log_test $? 0 "Prefsrc not removed in default VRF"

	$IP addr add dev dummy4 2001:db8:101::13/64
	$IP addr del dev dummy1 2001:db8:101::13/64
	$IP -6 route show vrf red | grep -q "src 2001:db8:101::13 "
	log_test $? 1 "Prefsrc removed from VRF when nexthop dev in diff VRF"
	$IP -6 route show | grep -q "src 2001:db8:101::13 "
	log_test $? 1 "Prefsrc removed in default VRF"

	echo "    Table ID 0"

	$IP addr del dev dummy1 2001:db8:101::15/64
	$IP -6 route show | grep -q "src 2001:db8:101::15"
	log_test $? 1 "Prefsrc removed from default VRF when source address deleted"

	echo "    Link local source route"
	$IP addr del dev dummy1 fe80::1/128
	$IP -6 route show | grep -q "2001:db8:116::/64 dev dummy2 src fe80::1"
	log_test $? 0 "Prefsrc not removed when delete ll addr from other dev"
	$IP addr del dev dummy2 fe80::1/128
	$IP -6 route show | grep -q "2001:db8:116::/64 dev dummy2 src fe80::1"
	log_test $? 1 "Prefsrc removed when delete ll addr"
	$IP -6 route show | grep -q "2001:db8:117::/64 dev dummy3 src fe80::1"
	log_test $? 0 "Prefsrc not removed when delete ll addr from other dev"
	$IP addr add dev dummy1 fe80::1/128
	$IP addr del dev dummy3 fe80::1/128
	$IP -6 route show | grep -q "2001:db8:117::/64 dev dummy3 src fe80::1"
	log_test $? 1 "Prefsrc removed even ll addr still exist on other dev"

	for i in $(seq 6); do
		$IP li del dummy${i}
	done
	cleanup
}

ipv4_route_v6_gw_test()
{
	local rc

	echo
	echo "IPv4 route with IPv6 gateway tests"

	route_setup
	sleep 2

	#
	# single path route
	#
	run_cmd "$IP ro add 172.16.104.0/24 via inet6 2001:db8:101::2"
	rc=$?
	log_test $rc 0 "Single path route with IPv6 gateway"
	if [ $rc -eq 0 ]; then
		check_route "172.16.104.0/24 via inet6 2001:db8:101::2 dev veth1"
	fi

	run_cmd "ip netns exec $ns1 ping -w1 -c1 172.16.104.1"
	log_test $rc 0 "Single path route with IPv6 gateway - ping"

	run_cmd "$IP ro del 172.16.104.0/24 via inet6 2001:db8:101::2"
	rc=$?
	log_test $rc 0 "Single path route delete"
	if [ $rc -eq 0 ]; then
		check_route "172.16.112.0/24"
	fi

	#
	# multipath - v6 then v4
	#
	run_cmd "$IP ro add 172.16.104.0/24 nexthop via inet6 2001:db8:101::2 dev veth1 nexthop via 172.16.103.2 dev veth3"
	rc=$?
	log_test $rc 0 "Multipath route add - v6 nexthop then v4"
	if [ $rc -eq 0 ]; then
		check_route "172.16.104.0/24 nexthop via inet6 2001:db8:101::2 dev veth1 weight 1 nexthop via 172.16.103.2 dev veth3 weight 1"
	fi

	run_cmd "$IP ro del 172.16.104.0/24 nexthop via 172.16.103.2 dev veth3 nexthop via inet6 2001:db8:101::2 dev veth1"
	log_test $? 2 "    Multipath route delete - nexthops in wrong order"

	run_cmd "$IP ro del 172.16.104.0/24 nexthop via inet6 2001:db8:101::2 dev veth1 nexthop via 172.16.103.2 dev veth3"
	log_test $? 0 "    Multipath route delete exact match"

	#
	# multipath - v4 then v6
	#
	run_cmd "$IP ro add 172.16.104.0/24 nexthop via 172.16.103.2 dev veth3 nexthop via inet6 2001:db8:101::2 dev veth1"
	rc=$?
	log_test $rc 0 "Multipath route add - v4 nexthop then v6"
	if [ $rc -eq 0 ]; then
		check_route "172.16.104.0/24 nexthop via 172.16.103.2 dev veth3 weight 1 nexthop via inet6 2001:db8:101::2 dev veth1 weight 1"
	fi

	run_cmd "$IP ro del 172.16.104.0/24 nexthop via inet6 2001:db8:101::2 dev veth1 nexthop via 172.16.103.2 dev veth3"
	log_test $? 2 "    Multipath route delete - nexthops in wrong order"

	run_cmd "$IP ro del 172.16.104.0/24 nexthop via 172.16.103.2 dev veth3 nexthop via inet6 2001:db8:101::2 dev veth1"
	log_test $? 0 "    Multipath route delete exact match"

	route_cleanup
}

socat_check()
{
	if [ ! -x "$(command -v socat)" ]; then
		echo "socat command not found. Skipping test"
		return 1
	fi

	return 0
}

iptables_check()
{
	iptables -t mangle -L OUTPUT &> /dev/null
	if [ $? -ne 0 ]; then
		echo "iptables configuration not supported. Skipping test"
		return 1
	fi

	return 0
}

ip6tables_check()
{
	ip6tables -t mangle -L OUTPUT &> /dev/null
	if [ $? -ne 0 ]; then
		echo "ip6tables configuration not supported. Skipping test"
		return 1
	fi

	return 0
}

ipv4_mangle_test()
{
	local rc

	echo
	echo "IPv4 mangling tests"

	socat_check || return 1
	iptables_check || return 1

	route_setup
	sleep 2

	local tmp_file=$(mktemp)
	ip netns exec $ns2 socat UDP4-LISTEN:54321,fork $tmp_file &

	# Add a FIB rule and a route that will direct our connection to the
	# listening server.
	$IP rule add pref 100 ipproto udp sport 12345 dport 54321 table 123
	$IP route add table 123 172.16.101.0/24 dev veth1

	# Add an unreachable route to the main table that will block our
	# connection in case the FIB rule is not hit.
	$IP route add unreachable 172.16.101.2/32

	run_cmd "echo a | $NS_EXEC socat STDIN UDP4:172.16.101.2:54321,sourceport=12345"
	log_test $? 0 "    Connection with correct parameters"

	run_cmd "echo a | $NS_EXEC socat STDIN UDP4:172.16.101.2:54321,sourceport=11111"
	log_test $? 1 "    Connection with incorrect parameters"

	# Add a mangling rule and make sure connection is still successful.
	$NS_EXEC iptables -t mangle -A OUTPUT -j MARK --set-mark 1

	run_cmd "echo a | $NS_EXEC socat STDIN UDP4:172.16.101.2:54321,sourceport=12345"
	log_test $? 0 "    Connection with correct parameters - mangling"

	# Delete the mangling rule and make sure connection is still
	# successful.
	$NS_EXEC iptables -t mangle -D OUTPUT -j MARK --set-mark 1

	run_cmd "echo a | $NS_EXEC socat STDIN UDP4:172.16.101.2:54321,sourceport=12345"
	log_test $? 0 "    Connection with correct parameters - no mangling"

	# Verify connections were indeed successful on server side.
	[[ $(cat $tmp_file | wc -l) -eq 3 ]]
	log_test $? 0 "    Connection check - server side"

	$IP route del unreachable 172.16.101.2/32
	$IP route del table 123 172.16.101.0/24 dev veth1
	$IP rule del pref 100

	kill_process %%
	rm $tmp_file

	route_cleanup
}

ipv6_mangle_test()
{
	local rc

	echo
	echo "IPv6 mangling tests"

	socat_check || return 1
	ip6tables_check || return 1

	route_setup
	sleep 2

	local tmp_file=$(mktemp)
	ip netns exec $ns2 socat UDP6-LISTEN:54321,fork $tmp_file &

	# Add a FIB rule and a route that will direct our connection to the
	# listening server.
	$IP -6 rule add pref 100 ipproto udp sport 12345 dport 54321 table 123
	$IP -6 route add table 123 2001:db8:101::/64 dev veth1

	# Add an unreachable route to the main table that will block our
	# connection in case the FIB rule is not hit.
	$IP -6 route add unreachable 2001:db8:101::2/128

	run_cmd "echo a | $NS_EXEC socat STDIN UDP6:[2001:db8:101::2]:54321,sourceport=12345"
	log_test $? 0 "    Connection with correct parameters"

	run_cmd "echo a | $NS_EXEC socat STDIN UDP6:[2001:db8:101::2]:54321,sourceport=11111"
	log_test $? 1 "    Connection with incorrect parameters"

	# Add a mangling rule and make sure connection is still successful.
	$NS_EXEC ip6tables -t mangle -A OUTPUT -j MARK --set-mark 1

	run_cmd "echo a | $NS_EXEC socat STDIN UDP6:[2001:db8:101::2]:54321,sourceport=12345"
	log_test $? 0 "    Connection with correct parameters - mangling"

	# Delete the mangling rule and make sure connection is still
	# successful.
	$NS_EXEC ip6tables -t mangle -D OUTPUT -j MARK --set-mark 1

	run_cmd "echo a | $NS_EXEC socat STDIN UDP6:[2001:db8:101::2]:54321,sourceport=12345"
	log_test $? 0 "    Connection with correct parameters - no mangling"

	# Verify connections were indeed successful on server side.
	[[ $(cat $tmp_file | wc -l) -eq 3 ]]
	log_test $? 0 "    Connection check - server side"

	$IP -6 route del unreachable 2001:db8:101::2/128
	$IP -6 route del table 123 2001:db8:101::/64 dev veth1
	$IP -6 rule del pref 100

	kill_process %%
	rm $tmp_file

	route_cleanup
}

ip_neigh_get_check()
{
	ip neigh help 2>&1 | grep -q 'ip neigh get'
	if [ $? -ne 0 ]; then
		echo "iproute2 command does not support neigh get. Skipping test"
		return 1
	fi

	return 0
}

ipv4_bcast_neigh_test()
{
	local rc

	echo
	echo "IPv4 broadcast neighbour tests"

	ip_neigh_get_check || return 1

	setup

	set -e
	run_cmd "$IP neigh add 192.0.2.111 lladdr 00:11:22:33:44:55 nud perm dev dummy0"
	run_cmd "$IP neigh add 192.0.2.255 lladdr 00:11:22:33:44:55 nud perm dev dummy0"

	run_cmd "$IP neigh get 192.0.2.111 dev dummy0"
	run_cmd "$IP neigh get 192.0.2.255 dev dummy0"

	run_cmd "$IP address add 192.0.2.1/24 broadcast 192.0.2.111 dev dummy0"

	run_cmd "$IP neigh add 203.0.113.111 nud failed dev dummy0"
	run_cmd "$IP neigh add 203.0.113.255 nud failed dev dummy0"

	run_cmd "$IP neigh get 203.0.113.111 dev dummy0"
	run_cmd "$IP neigh get 203.0.113.255 dev dummy0"

	run_cmd "$IP address add 203.0.113.1/24 broadcast 203.0.113.111 dev dummy0"
	set +e

	run_cmd "$IP neigh get 192.0.2.111 dev dummy0"
	log_test $? 0 "Resolved neighbour for broadcast address"

	run_cmd "$IP neigh get 192.0.2.255 dev dummy0"
	log_test $? 0 "Resolved neighbour for network broadcast address"

	run_cmd "$IP neigh get 203.0.113.111 dev dummy0"
	log_test $? 2 "Unresolved neighbour for broadcast address"

	run_cmd "$IP neigh get 203.0.113.255 dev dummy0"
	log_test $? 2 "Unresolved neighbour for network broadcast address"

	cleanup
}

mpath_dep_check()
{
	if [ ! -x "$(command -v mausezahn)" ]; then
		echo "mausezahn command not found. Skipping test"
		return 1
	fi

	if [ ! -x "$(command -v jq)" ]; then
		echo "jq command not found. Skipping test"
		return 1
	fi

	if [ ! -x "$(command -v bc)" ]; then
		echo "bc command not found. Skipping test"
		return 1
	fi

	if [ ! -x "$(command -v perf)" ]; then
		echo "perf command not found. Skipping test"
		return 1
	fi

	perf list fib:* | grep -q fib_table_lookup
	if [ $? -ne 0 ]; then
		echo "IPv4 FIB tracepoint not found. Skipping test"
		return 1
	fi

	perf list fib6:* | grep -q fib6_table_lookup
	if [ $? -ne 0 ]; then
		echo "IPv6 FIB tracepoint not found. Skipping test"
		return 1
	fi

	return 0
}

link_stats_get()
{
	local ns=$1; shift
	local dev=$1; shift
	local dir=$1; shift
	local stat=$1; shift

	ip -n $ns -j -s link show dev $dev \
		| jq '.[]["stats64"]["'$dir'"]["'$stat'"]'
}

list_rcv_eval()
{
	local file=$1; shift
	local expected=$1; shift

	local count=$(tail -n 1 $file | jq '.["counter-value"] | tonumber | floor')
	local ratio=$(echo "scale=2; $count / $expected" | bc -l)
	local res=$(echo "$ratio >= 0.95" | bc)
	[[ $res -eq 1 ]]
	log_test $? 0 "Multipath route hit ratio ($ratio)"
}

ipv4_mpath_list_test()
{
	echo
	echo "IPv4 multipath list receive tests"

	mpath_dep_check || return 1

	route_setup

	set -e
	run_cmd "ip netns exec $ns1 ethtool -K veth1 tcp-segmentation-offload off"

	run_cmd "ip netns exec $ns2 bash -c \"echo 20000 > /sys/class/net/veth2/gro_flush_timeout\""
	run_cmd "ip netns exec $ns2 bash -c \"echo 1 > /sys/class/net/veth2/napi_defer_hard_irqs\""
	run_cmd "ip netns exec $ns2 ethtool -K veth2 generic-receive-offload on"
	run_cmd "ip -n $ns2 link add name nh1 up type dummy"
	run_cmd "ip -n $ns2 link add name nh2 up type dummy"
	run_cmd "ip -n $ns2 address add 172.16.201.1/24 dev nh1"
	run_cmd "ip -n $ns2 address add 172.16.202.1/24 dev nh2"
	run_cmd "ip -n $ns2 neigh add 172.16.201.2 lladdr 00:11:22:33:44:55 nud perm dev nh1"
	run_cmd "ip -n $ns2 neigh add 172.16.202.2 lladdr 00:aa:bb:cc:dd:ee nud perm dev nh2"
	run_cmd "ip -n $ns2 route add 203.0.113.0/24
		nexthop via 172.16.201.2 nexthop via 172.16.202.2"
	run_cmd "ip netns exec $ns2 sysctl -qw net.ipv4.fib_multipath_hash_policy=1"
	set +e

	local dmac=$(ip -n $ns2 -j link show dev veth2 | jq -r '.[]["address"]')
	local tmp_file=$(mktemp)
	local cmd="ip netns exec $ns1 mausezahn veth1 -a own -b $dmac
		-A 172.16.101.1 -B 203.0.113.1 -t udp 'sp=12345,dp=0-65535' -q"

	# Packets forwarded in a list using a multipath route must not reuse a
	# cached result so that a flow always hits the same nexthop. In other
	# words, the FIB lookup tracepoint needs to be triggered for every
	# packet.
	local t0_rx_pkts=$(link_stats_get $ns2 veth2 rx packets)
	run_cmd "perf stat -a -e fib:fib_table_lookup --filter 'err == 0' -j -o $tmp_file -- $cmd"
	local t1_rx_pkts=$(link_stats_get $ns2 veth2 rx packets)
	local diff=$(echo $t1_rx_pkts - $t0_rx_pkts | bc -l)
	list_rcv_eval $tmp_file $diff

	rm $tmp_file
	route_cleanup
}

ipv6_mpath_list_test()
{
	echo
	echo "IPv6 multipath list receive tests"

	mpath_dep_check || return 1

	route_setup

	set -e
	run_cmd "ip netns exec $ns1 ethtool -K veth1 tcp-segmentation-offload off"

	run_cmd "ip netns exec $ns2 bash -c \"echo 20000 > /sys/class/net/veth2/gro_flush_timeout\""
	run_cmd "ip netns exec $ns2 bash -c \"echo 1 > /sys/class/net/veth2/napi_defer_hard_irqs\""
	run_cmd "ip netns exec $ns2 ethtool -K veth2 generic-receive-offload on"
	run_cmd "ip -n $ns2 link add name nh1 up type dummy"
	run_cmd "ip -n $ns2 link add name nh2 up type dummy"
	run_cmd "ip -n $ns2 -6 address add 2001:db8:201::1/64 dev nh1"
	run_cmd "ip -n $ns2 -6 address add 2001:db8:202::1/64 dev nh2"
	run_cmd "ip -n $ns2 -6 neigh add 2001:db8:201::2 lladdr 00:11:22:33:44:55 nud perm dev nh1"
	run_cmd "ip -n $ns2 -6 neigh add 2001:db8:202::2 lladdr 00:aa:bb:cc:dd:ee nud perm dev nh2"
	run_cmd "ip -n $ns2 -6 route add 2001:db8:301::/64
		nexthop via 2001:db8:201::2 nexthop via 2001:db8:202::2"
	run_cmd "ip netns exec $ns2 sysctl -qw net.ipv6.fib_multipath_hash_policy=1"
	set +e

	local dmac=$(ip -n $ns2 -j link show dev veth2 | jq -r '.[]["address"]')
	local tmp_file=$(mktemp)
	local cmd="ip netns exec $ns1 mausezahn -6 veth1 -a own -b $dmac
		-A 2001:db8:101::1 -B 2001:db8:301::1 -t udp 'sp=12345,dp=0-65535' -q"

	# Packets forwarded in a list using a multipath route must not reuse a
	# cached result so that a flow always hits the same nexthop. In other
	# words, the FIB lookup tracepoint needs to be triggered for every
	# packet.
	local t0_rx_pkts=$(link_stats_get $ns2 veth2 rx packets)
	run_cmd "perf stat -a -e fib6:fib6_table_lookup --filter 'err == 0' -j -o $tmp_file -- $cmd"
	local t1_rx_pkts=$(link_stats_get $ns2 veth2 rx packets)
	local diff=$(echo $t1_rx_pkts - $t0_rx_pkts | bc -l)
	list_rcv_eval $tmp_file $diff

	rm $tmp_file
	route_cleanup
}

tc_set_flower_counter__saddr_syn() {
	tc_set_flower_counter $1 $2 $3 "src_ip $4 ip_proto tcp tcp_flags 0x2"
}

ip_mpath_balance_dep_check()
{
	if [ ! -x "$(command -v socat)" ]; then
		echo "socat command not found. Skipping test"
		return 1
	fi

	if [ ! -x "$(command -v jq)" ]; then
		echo "jq command not found. Skipping test"
		return 1
	fi
}

ip_mpath_balance() {
	local -r ipver=$1
	local -r daddr=$2
	local -r num_conn=20

	for i in $(seq 1 $num_conn); do
		ip netns exec $ns3 socat $ipver TCP-LISTEN:8000 STDIO >/dev/null &
		sleep 0.02
		echo -n a | ip netns exec $ns1 socat $ipver STDIO TCP:$daddr:8000
	done

	local -r syn0="$(tc_get_flower_counter $ns1 veth1)"
	local -r syn1="$(tc_get_flower_counter $ns1 veth3)"
	local -r syns=$((syn0+syn1))

	[ "$VERBOSE" = "1" ] && echo "multipath: syns seen: ($syn0,$syn1)"

	[[ $syns -ge $num_conn ]] && [[ $syn0 -gt 0 ]] && [[ $syn1 -gt 0 ]]
}

ipv4_mpath_balance_test()
{
	echo
	echo "IPv4 multipath load balance test"

	ip_mpath_balance_dep_check || return 1
	forwarding_setup

	$IP route add 172.16.105.1 \
		nexthop via 172.16.101.2 \
		nexthop via 172.16.103.2

	ip netns exec $ns1 \
		sysctl -q -w net.ipv4.fib_multipath_hash_policy=1

	tc_set_flower_counter__saddr_syn $ns1 4 veth1 172.16.101.1
	tc_set_flower_counter__saddr_syn $ns1 4 veth3 172.16.103.1

	ip_mpath_balance -4 172.16.105.1

	log_test $? 0 "IPv4 multipath loadbalance"

	forwarding_cleanup
}

ipv6_mpath_balance_test()
{
	echo
	echo "IPv6 multipath load balance test"

	ip_mpath_balance_dep_check || return 1
	forwarding_setup

	$IP route add 2001:db8:105::1\
		nexthop via 2001:db8:101::2 \
		nexthop via 2001:db8:103::2

	ip netns exec $ns1 \
		sysctl -q -w net.ipv6.fib_multipath_hash_policy=1

	tc_set_flower_counter__saddr_syn $ns1 6 veth1 2001:db8:101::1
	tc_set_flower_counter__saddr_syn $ns1 6 veth3 2001:db8:103::1

	ip_mpath_balance -6 "[2001:db8:105::1]"

	log_test $? 0 "IPv6 multipath loadbalance"

	forwarding_cleanup
}

################################################################################
# usage

usage()
{
	cat <<EOF
usage: ${0##*/} OPTS

        -t <test>   Test(s) to run (default: all)
                    (options: $TESTS)
        -p          Pause on fail
        -P          Pause after each test before cleanup
        -v          verbose mode (show commands and output)
EOF
}

################################################################################
# main

trap cleanup EXIT

while getopts :t:pPhv o
do
	case $o in
		t) TESTS=$OPTARG;;
		p) PAUSE_ON_FAIL=yes;;
		P) PAUSE=yes;;
		v) VERBOSE=$(($VERBOSE + 1));;
		h) usage; exit 0;;
		*) usage; exit 1;;
	esac
done

PEER_CMD="ip netns exec ${PEER_NS}"

# make sure we don't pause twice
[ "${PAUSE}" = "yes" ] && PAUSE_ON_FAIL=no

if [ "$(id -u)" -ne 0 ];then
	echo "SKIP: Need root privileges"
	exit $ksft_skip;
fi

if [ ! -x "$(command -v ip)" ]; then
	echo "SKIP: Could not run test without ip tool"
	exit $ksft_skip
fi

ip route help 2>&1 | grep -q fibmatch
if [ $? -ne 0 ]; then
	echo "SKIP: iproute2 too old, missing fibmatch"
	exit $ksft_skip
fi

# start clean
cleanup &> /dev/null

for t in $TESTS
do
	case $t in
	fib_unreg_test|unregister)	fib_unreg_test;;
	fib_down_test|down)		fib_down_test;;
	fib_carrier_test|carrier)	fib_carrier_test;;
	fib_rp_filter_test|rp_filter)	fib_rp_filter_test;;
	fib_nexthop_test|nexthop)	fib_nexthop_test;;
	fib_notify_test|ipv4_notify)	fib_notify_test;;
	fib6_notify_test|ipv6_notify)	fib6_notify_test;;
	fib_suppress_test|suppress)	fib_suppress_test;;
	ipv6_route_test|ipv6_rt)	ipv6_route_test;;
	ipv4_route_test|ipv4_rt)	ipv4_route_test;;
	ipv6_addr_metric)		ipv6_addr_metric_test;;
	ipv4_addr_metric)		ipv4_addr_metric_test;;
	ipv4_del_addr)			ipv4_del_addr_test;;
	ipv6_del_addr)			ipv6_del_addr_test;;
	ipv6_route_metrics)		ipv6_route_metrics_test;;
	ipv4_route_metrics)		ipv4_route_metrics_test;;
	ipv4_route_v6_gw)		ipv4_route_v6_gw_test;;
	ipv4_mangle)			ipv4_mangle_test;;
	ipv6_mangle)			ipv6_mangle_test;;
	ipv4_bcast_neigh)		ipv4_bcast_neigh_test;;
	fib6_gc_test|ipv6_gc)		fib6_gc_test;;
	ipv4_mpath_list)		ipv4_mpath_list_test;;
	ipv6_mpath_list)		ipv6_mpath_list_test;;
	ipv4_mpath_balance)		ipv4_mpath_balance_test;;
	ipv6_mpath_balance)		ipv6_mpath_balance_test;;

	help) echo "Test names: $TESTS"; exit 0;;
	esac
done

if [ "$TESTS" != "none" ]; then
	printf "\nTests passed: %3d\n" ${nsuccess}
	printf "Tests failed: %3d\n"   ${nfail}
fi

exit $ret
