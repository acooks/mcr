#!/bin/bash
sudo ip netns add test-src
sudo ip link add veth-test0 type veth peer name veth-test1
sudo ip link set veth-test0 netns test-src
sudo ip netns exec test-src ip addr add 10.0.1.1/24 dev veth-test0
sudo ip netns exec test-src ip link set veth-test0 up
echo "=== Routes WITHOUT multicast route ==="
sudo ip netns exec test-src ip route show
echo ""
echo "=== Routes WITH multicast route ==="
sudo ip netns exec test-src ip route add 239.255.0.0/24 dev veth-test0
sudo ip netns exec test-src ip route show
sudo ip netns del test-src
