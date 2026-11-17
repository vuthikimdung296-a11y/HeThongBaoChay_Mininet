#!/usr/bin/env bash
# HTB + FQ-CoDel egress scheduler for forwarded traffic to the MQTT/application server.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
IFACE="${QOS_IFACE:-gw-eth0.30}"
ROOT_RATE="${QOS_ROOT_RATE:-100mbit}"
NFT_FILE="${QOS_NFT_FILE:-${SCRIPT_DIR}/marks.nft}"

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then echo "ERROR: run inside Gateway namespace as root" >&2; exit 1; fi
}
need_iface() {
  ip link show dev "$IFACE" >/dev/null 2>&1 || { echo "ERROR: interface $IFACE not found" >&2; exit 1; }
}

start_qos() {
  need_root; need_iface
  command -v tc >/dev/null || { echo "ERROR: tc not installed" >&2; exit 1; }
  command -v nft >/dev/null || { echo "ERROR: nft not installed" >&2; exit 1; }
  [[ -r "$NFT_FILE" ]] || { echo "ERROR: cannot read $NFT_FILE" >&2; exit 1; }

  # Replace only this project's nft table; do not flush unrelated firewall rules.
  nft delete table inet qos 2>/dev/null || true
  nft -f "$NFT_FILE"

  # Remove the previous root qdisc on the VLAN egress sub-interface, if any.
  tc qdisc del dev "$IFACE" root 2>/dev/null || true
  tc qdisc add dev "$IFACE" root handle 1: htb default 13 r2q 100
  tc class add dev "$IFACE" parent 1: classid 1:1 htb rate "$ROOT_RATE" ceil "$ROOT_RATE"

  # Guaranteed rates total 76 Mbit/s, below the 100 Mbit/s root capacity.
  # ceil permits borrowing unused bandwidth; prio 0 is served before prio 3.
  tc class add dev "$IFACE" parent 1:1 classid 1:10 htb rate 10mbit ceil 100mbit prio 0
  tc class add dev "$IFACE" parent 1:1 classid 1:11 htb rate 5mbit  ceil 100mbit prio 1
  tc class add dev "$IFACE" parent 1:1 classid 1:12 htb rate 60mbit ceil 90mbit  prio 2
  tc class add dev "$IFACE" parent 1:1 classid 1:13 htb rate 1mbit  ceil 10mbit  prio 3

  # Active queue management at each leaf reduces persistent queueing delay.
  tc qdisc add dev "$IFACE" parent 1:10 handle 110: fq_codel
  tc qdisc add dev "$IFACE" parent 1:11 handle 111: fq_codel
  tc qdisc add dev "$IFACE" parent 1:12 handle 112: fq_codel
  tc qdisc add dev "$IFACE" parent 1:13 handle 113: fq_codel

  # skb mark is assigned in nft prerouting and matched on the egress device.
  tc filter add dev "$IFACE" parent 1: protocol ip prio 10 handle 0x10 fw flowid 1:10
  tc filter add dev "$IFACE" parent 1: protocol ip prio 11 handle 0x11 fw flowid 1:11
  tc filter add dev "$IFACE" parent 1: protocol ip prio 12 handle 0x12 fw flowid 1:12
  tc filter add dev "$IFACE" parent 1: protocol ip prio 13 handle 0x13 fw flowid 1:13

  echo "QoS started on $IFACE (HTB + FQ-CoDel); marks table inet qos loaded."
  check_qos
}

stop_qos() {
  need_root
  tc qdisc del dev "$IFACE" root 2>/dev/null || true
  nft delete table inet qos 2>/dev/null || true
  echo "QoS stopped on $IFACE; table inet qos removed."
}

show_qos() {
  need_root; need_iface
  echo "=== qdisc ==="; tc -s qdisc show dev "$IFACE"
  echo "=== classes ==="; tc -s class show dev "$IFACE"
  echo "=== filters ==="; tc -s filter show dev "$IFACE" parent 1:
  echo "=== nft marks ==="; nft list table inet qos 2>/dev/null || true
}

check_qos() {
  need_root; need_iface
  tc qdisc show dev "$IFACE" | grep -q 'htb 1:' || { echo "ERROR: HTB root qdisc missing" >&2; return 1; }
  local classes filters
  classes="$(tc class show dev "$IFACE")"
  filters="$(tc filter show dev "$IFACE" parent 1:)"
  for id in 1:10 1:11 1:12 1:13; do
    grep -q "class htb $id" <<<"$classes" || { echo "ERROR: missing HTB class $id" >&2; return 1; }
  done
  for mark in 0x10 0x11 0x12 0x13; do
    grep -qi "$mark" <<<"$filters" || { echo "ERROR: missing fw filter for mark $mark" >&2; return 1; }
  done
  nft list table inet qos >/dev/null 2>&1 || { echo "ERROR: nft table inet qos missing" >&2; return 1; }
  # Confirm each leaf has the intended queue discipline, not just an HTB class.
  local qdiscs
  qdiscs="$(tc qdisc show dev "$IFACE")"
  for handle in 110: 111: 112: 113:; do
    grep -qE "qdisc fq_codel ${handle}([[:space:]]|$)" <<<"$qdiscs" || {
      echo "ERROR: missing FQ-CoDel qdisc $handle" >&2
      return 1
    }
  done
  echo "PASS: HTB root, four classes, four fw filters, four FQ-CoDel leaves and nft mark table are present."
}

case "${1:-}" in
  start) start_qos ;;
  stop) stop_qos ;;
  show) show_qos ;;
  check) check_qos ;;
  *) echo "Usage: $0 {start|stop|show|check}"; exit 2 ;;
esac
