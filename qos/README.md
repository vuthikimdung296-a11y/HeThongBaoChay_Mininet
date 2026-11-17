# QoS module

`marks.nft` classifies forwarded IPv4 packets at Gateway prerouting and assigns skb
marks. `qos.sh` maps those marks to HTB classes on the server-facing Gateway VLAN
interface, using FQ-CoDel as each leaf queue.

## Mark/class mapping

| Traffic | Match | skb mark | HTB class | Guaranteed rate | Priority |
|---|---|---:|---|---:|---:|
| Fire alarm | ingress `gw-eth0.10`, DSCP 48/CS6 | `0x10` | `1:10` | 10 Mbit/s | 0 |
| Sensor telemetry | ingress `gw-eth0.10`, other DSCP | `0x11` | `1:11` | 5 Mbit/s | 1 |
| Camera | ingress `gw-eth0.20` | `0x12` | `1:12` | 60 Mbit/s | 2 |
| Untrusted | ingress `gw-eth1` and default | `0x13` | `1:13` | 1 Mbit/s | 3 |

Root capacity defaults to 100 Mbit/s. Class guarantees total 76 Mbit/s; `ceil`
allows borrowing unused capacity. These are design values and should be stated in
the experiment report.

## Run inside Gateway namespace

```bash
bash qos/qos.sh start
bash qos/qos.sh check
bash qos/qos.sh show
bash qos/qos.sh stop
```

Optional parameters:

```bash
QOS_IFACE=gw-eth0.30 QOS_ROOT_RATE=100mbit bash qos/qos.sh start
```

`check` validates the nft table, HTB root, all four classes, four fw filters and
four FQ-CoDel leaf qdiscs. `show` displays counters; run it during/after traffic to
confirm that bytes/packets increment in the expected class.

Important: QoS is not DDoS detection or firewall mitigation. The untrusted class
limits/queues traffic but does not discard all attack packets. Detection and
firewall policy belong to the separately owned Edge AI/firewall workstream.
