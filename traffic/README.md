# Traffic module

This module generates the four traffic groups consumed by the Gateway QoS rules:

| Group | Generator | Network identification |
|---|---|---|
| Fire alarm | `normal_mqtt.py` | Sensor VLAN, DSCP 48 (CS6), separate MQTT TCP connection |
| Sensor telemetry | `normal_mqtt.py` | Sensor VLAN, DSCP 0 |
| Camera video | `camera_iperf.py` | Camera VLAN, UDP/iperf3 |
| Untrusted/attack | `attack.py` | Attacker-facing Gateway interface; SYN or UDP load |

`run_scenario.py` is imported from the live Mininet CLI and orchestrates the broker,
iperf3 server, 10 sensor-floor generators, 20 camera streams, RTT probe and optional
bounded attack. It writes CSV/JSON/log artifacts under `traffic/results/`.
Each camera gets its own iperf3 server port (5201–5220) so all 20 streams can run
concurrently without competing for one server session.

## Dependencies

Install on Ubuntu: `sudo apt install python3-paho-mqtt mosquitto iperf3 hping3 iproute2`

## Run from Mininet CLI

The network must already be running with hosts `hs01..hs10`, `cam01..cam20`,
`srv`, `gw`, and `atk`:

```text
mininet> py __import__('sys').path.insert(0, '..')
mininet> py __import__('traffic.run_scenario', fromlist=['run_scenario']).run_scenario(net, scenario='normal', duration=60)
mininet> py __import__('traffic.run_scenario', fromlist=['run_scenario']).run_scenario(net, scenario='attack_no_qos', duration=60, attack_type='syn_flood', attack_rate=500, attack_duration=15)
mininet> py __import__('traffic.run_scenario', fromlist=['run_scenario']).run_scenario(net, scenario='attack_qos', duration=60, attack_type='udp_flood', attack_rate=500, attack_duration=15)
```

For a direct single-floor test inside `hs01`:

```bash
python3 traffic/normal_mqtt.py --floor 1 --duration 60 --telemetry-interval 10 --alarm-after 15
```

Attack generator is intentionally bounded (maximum 5,000 pps and 300 seconds),
requires an explicit target, and disables source spoofing unless explicitly opted in.
Use only against the isolated Mininet lab. Example from the `atk` namespace:

```text
mininet> atk python3 traffic/attack.py --type syn_flood --target 10.0.30.10 --rate 500 --duration 15
```

## Output

- `results/camera_metrics.csv`: per-camera throughput, jitter and UDP loss from iperf3.
- `results/iperf_camXX.json`: raw iperf3 JSON for audit/re-analysis.
- `results/attack_events.csv`: UTC start/end, actual duration, configured rate and hping transmitted count when available.
- `results/scenario_metrics.csv`: scenario, QoS state and RTT summary.
- `results/mqtt_*.log`, `results/cam*.log`, `results/ping_*.txt`: execution logs.

The configured hping rate is a requested send rate, not a substitute for measured
packet rate at the Gateway. For measured ingress pps, correlate the event timestamps
with the Gateway packet counters/PCAP or the Edge AI metadata collector.
