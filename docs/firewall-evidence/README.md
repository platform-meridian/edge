# The appliance's ingress firewall, the evidence

Run on 2026-10-28, against edge-bundle's `machineconfig::with_firewall` as
committed with this directory.

The VM was stock Talos v1.14.1 (the factory's nocloud image), not Meridian's
media: the Proxmox host was not reachable from the workstation's network that
day, and Meridian's media needs every image built. It ran as
`meridian-dev-firewall` under the workstation's libvirt, with two ports: the
management port on libvirt's default network (DHCP, `192.168.122.151`) and the
operator island on `meridian-operator` (`10.51.0.1/24` and `fe80::ed6e:1/64`,
the workstation at `10.51.0.2`). It was destroyed afterwards.

Its config was `talosctl gen config` with those two interfaces, then run
through `with_firewall` with the `management` rule for `192.168.122.0/24`, as
provisioning renders a site that names it. Talos validated it (`--strict`). The
documents are [firewall.yaml](firewall.yaml); the ingress chain Talos made from
them is [ingress-chain.yaml](ingress-chain.yaml).

Flannel and kube-proxy ran in place of edge-cni. A hostNetwork pod stood in for
core and edge-gateway: it listened on `0.0.0.0` on UDP 7600 (core's component
port), TCP and UDP 443 (the console), and TCP 9999 (a port nothing declares).
Service `platform-core` selected it on UDP 7600, as on a unit. The listeners on
the node are in [listeners.txt](listeners.txt).

## From outside

From the workstation, at both the management address and the island address
([outside.txt](outside.txt)):

| port | result |
| --- | --- |
| UDP 7600 | no answer: dropped |
| TCP 9999 | no answer: dropped |
| TCP 443 | connected, the stand-in answered |
| UDP 443 | the stand-in answered |
| TCP 50000, 6443 | connected: the workstation is on the management network and on the island |
| TCP 50001 (trustd), 10250 (kubelet), 2379, 2380 (etcd), 10256 | no answer: dropped |

## From a pod

A pod on the pod network (`component`, `10.244.0.3`) sent UDP datagrams to
7600, through Service `platform-core` and to the node's address; all four
reached the listener. Of the six the workstation sent to 7600, none did
([udp7600.txt](udp7600.txt)). The same pod reached TCP 9999 on the node:
everything is open to the pods, and nothing else is.
