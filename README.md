# mitm

## allow ipv4 forwarding (not persistent)
sysctl -w net.ipv4.ip_forward=1

## allow your firewall to forward packets

something like this...
sudo iptables -A FORWARD_direct -j ACCEPT
