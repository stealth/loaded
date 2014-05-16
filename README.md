loaded - a IPv4/IPv6 load balancer for Linux
=============================================

Pre
---

It's under a BSDish license. For the source, see

https://github.com/stealth/loaded


Requirements
------------

Loaded requires _netfilter_ and the __NFQUEUE__ target enabled in kernel which is
default on most Linux distros.
Usually it's in the `nfnetlink_queue` LKM and loaded by the
`loaded.config` script.

For Loaded to build, you need some netfilter/nfqueue libs. On my
openSUSE system they are found in these RPM's:

	* libnfnetlink-devel
	* libnfnetlink0
	* libnetfilter_queue-devel
	* libnetfilter_queue1

and if building with `-DUSE_CAP` for the least privilege model:

	* libcap2 or libcap
	* libcap-devel


Setup
-----


Edit `loaded.config` for your virtual IP etc, and run it
before you start `loaded` itself.
The config file is self explaining and needs to be passed via the `-c` command
line switch to Loaded, or it finds it by themself inside the current working
directory if its named `loaded.conf`.

Loaded supports CPU's with multiple cores (or SMP). In the config file you can
edit `FIRST_CORE` and `LAST_CORE` which will handle the load balancing.
By default Loaded will run as root, but you can pass the '-U' switch to drop its
privilges to this user. Loaded will also chroot itself to the __/var/run/empty__
directory for maximum safety, so be sure it exists. If you have a working SSH
setup, its probably already there.

Loaded is currently supporting `weighted` and `rr` balancing strategy. `rr`
(round robin) is less expensive than `weighted`. It is recommended to use `rr`
since for million of balanced clients, it is expensive to choose the least
weighted backend for a new appearing client versus just picking the next
via RR. In the long run, `rr` should be the best balancing strategy anyways.

    balancer# ip addr
    [...]
    balancer# ip route

to see whether the addresses
and routes are set up correctly by the config script. In order for the
returning packets to contain the VIP address, Loaded provides a `private_GW`
which you need to set up as the default GW on the backend systems, so they
traverse the load balancer which takes care to mangle all packets properly.
If you get Direct Server Return working on the backends, you dont need that.


To run loaded for IPv6:

    balancer6# ./loaded.config6
    balancer6# ./loaded -6 -c loaded.config6


Due to some weird kernel behavior which does not do Neighbor Discovery for
IPv6 addresses it mangled into a packet (unlike for IPv4), you need to set
static MAC entries for each backend node on the balancer:


    balancer6# ip -6 neigh add <IP6addr> lladdr <MAC> dev <Private NIC> nud permanent

for each backend node. This will add a static entry in the neighbor table
and the kernel will find which MAC address to use for the modified packet.
Each time you call `./loaded.config6` you need to re-set the neigh addresses
so you probably better write a script for it.
You can do it in a similar way for IPv4 as it would speed up balancing, since
ARP lookups are no longer done.

In particular if you balance IP6, make sure to disable automatic network
configuration on your balancer and backend nodes, as this could mess with
the setup of your routing tables (remember: routes from the backend node
have the default gw of the private load balancer address).

And thats it!

Failover
--------

For IPv4 there is also something implemented which is usually called automatic
failover. If you start Loaded with the `-f` switch, it will start a second thread
which checks in a configured interval which nodes are still reachable. The
nodes must answer to __ICMP_ECHO__ (ping) broadcasts:

    backend# echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

Dead nodes will be removed from the list of available backends and new nodes
are added respectively, so you have some kind of "hotplugging" with the
backends. Failover is experimental.
Ensure that you do not run the service which you are testing (`port_alive`)
on the load balancers private GW address since it will add itself to the list
of backend nodes otherwise.
IPv6 failover is not yet done but would work the same way. I just lack the time
to implement it. (Want to sponsor? :)



Big picture
-----------

```
                            +----+
  [ backend1 ]o>-------     |    |
                        > -o|  s |
  [ backend2 ]o>-------     |  w |
                  ...   > -o|  i |o-------< private GW and NIC -o[ LOADED ]
  [    ...   ]o>------- ... |  t |                                   o
                        > -o|  c |                                   |
  [ backendN ]o>-------     |  h | ...                         < pub NIC / VIP >
                            +----+    ..                             |
                                         .... [ DNS ]o---------------+
                                                                     |
                                                                     |
                                                             [ FW / public GW]


```


Loaded expects that it is only handling sane packets. That means there do not
appear strange fragmentation offsets or header lenghts. Loaded is checking
for sanity, so that no overflows or such happen, but it will not track
fragments. Therefore it is recommended to run a stateful firewall in front of
Loaded, at the __FW__ point. Stateful firewalls will automatically normalize the
TCP/IP traffic in order to track the TCP state engine and as a result no
fragmented packets will leave the inbound interface.

