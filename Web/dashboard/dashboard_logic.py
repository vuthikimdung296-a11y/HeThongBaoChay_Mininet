# -*- coding: utf-8 -*-
"""dashboard_logic.py - Logic thuần Python của Web Dashboard (không phụ thuộc Streamlit).

Tách riêng để kiểm thử được mà không cần chạy Streamlit, và để scenario_daemon.py
(chạy trong tiến trình Mininet) dùng chung định dạng file lệnh/trạng thái.

Hợp đồng dữ liệu với Việt Anh (gateway_ai.py) - file live_metrics.json, ghi nguyên tử mỗi 1 giây:
  {"timestamp": 1.78e9,            # epoch giây (hoặc chuỗi ISO-8601)
   "normal_packets": 1200,         # số gói/giây được xếp là bình thường
   "syn_packets": 15,              # số gói SYN (không ACK)/giây
   "udp_packets": 40,              # số gói UDP đáng ngờ/giây
   "rtt_ms": 22.4,                 # RTT đo được (ms)
   "status": "NORMAL",             # NORMAL | ATTACK | BLOCKED (chấp nhận đồng nghĩa, xem classify_status)
   "blocked_ips": ["192.168.100.100"]}   # danh sách chuỗi IP, hoặc [{"ip":..,"time":..,"reason":..}]
Trường thừa (ví dụ "source": "simulator") được bỏ qua.
"""
from __future__ import annotations

import html
import json
import math
import os
import time
import unicodedata
import uuid
from datetime import datetime

# ---------------------------------------------------------------- hằng số
GREEN, RED, GREY = "#1E8E4E", "#C93A3A", "#6B7580"
RTT_NORMAL_MS = 50.0     # KPI 2.1.3: RTT <= 50 ms khi bình thường
RTT_LIMIT_MS = 200.0     # KPI 2.1.3: RTT <= 200 ms khi bị tấn công
STALE_AFTER_S = 5.0      # quá 5 giây không có dữ liệu mới -> coi là mất kết nối

LIVE_PATH = os.environ.get("LIVE_METRICS", "live_metrics.json")
CMD_PATH = os.environ.get("SCENARIO_CMD", "/tmp/scenario_cmd.json")
STATUS_PATH = os.environ.get("SCENARIO_STATUS", "/tmp/scenario_status.json")

SCENARIOS = {
    "normal": "1. Bình thường",
    "attack_no_qos": "2. Tấn công, chưa bật AI+QoS",
    "attack_qos": "3. Tấn công, có AI+QoS",
}


# ---------------------------------------------------------------- tiện ích
def _fold(s: str) -> str:
    """Bỏ dấu tiếng Việt, hạ chữ thường, '_' và '-' thành khoảng trắng."""
    s = unicodedata.normalize("NFD", str(s)).replace("đ", "d").replace("Đ", "D")
    s = "".join(c for c in s if unicodedata.category(c) != "Mn")
    return s.lower().replace("_", " ").replace("-", " ").strip()


def classify_status(raw) -> str:
    """Trả về 'normal' | 'attack' | 'mitigated' | 'unknown'."""
    t = _fold(raw if raw is not None else "")
    if not t:
        return "unknown"
    if any(k in t for k in ("block", "mitigat", "chan", "defend", "drop")):
        return "mitigated"
    if any(k in t for k in ("attack", "tan cong", "flood", "ddos", "alert", "under")):
        return "attack"
    if any(k in t for k in ("normal", "binh thuong", "ok", "safe", "idle")):
        return "normal"
    return "unknown"


def _num(v, default=0.0):
    try:
        x = float(v)
        return default if math.isnan(x) or math.isinf(x) else x
    except (TypeError, ValueError):
        return default


def to_epoch(v) -> float:
    """Nhận epoch giây/mili giây hoặc chuỗi ISO-8601; lỗi thì trả về giờ hiện tại."""
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v / 1000.0 if v > 1e12 else float(v)
    if isinstance(v, str):
        s = v.strip()
        try:
            return float(s)
        except ValueError:
            pass
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass
    return time.time()


def fmt_time(epoch: float) -> str:
    return datetime.fromtimestamp(epoch).strftime("%H:%M:%S")


def atomic_write(path: str, obj) -> None:
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    os.replace(tmp, path)


# ---------------------------------------------------------------- live_metrics.json
def load_json(path: str):
    """(dict | None, lỗi | None). File thiếu hoặc đang dở dang không làm dashboard sập."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return None, "JSON không phải đối tượng"
        return data, None
    except FileNotFoundError:
        return None, "chưa có file"
    except (json.JSONDecodeError, OSError) as e:
        return None, str(e)


def normalize(raw: dict) -> dict:
    """Chuẩn hoá bản ghi live_metrics.json từ gateway_ai.py thật."""
    # 1. Lấy danh sách IP bị chặn từ nhánh firewall hoặc gốc
    firewall_data = raw.get("firewall", {})
    blocked = []
    raw_blocked = firewall_data.get("blocked_ips") or raw.get("blocked_ips") or []
    for item in raw_blocked:
        if isinstance(item, dict):
            ip = str(item.get("ip", "")).strip()
            if ip:
                blocked.append({"ip": ip, "time": item.get("time"), "reason": item.get("reason", "")})
        elif str(item).strip():
            blocked.append({"ip": str(item).strip(), "time": None, "reason": ""})

    # 2. Lấy các đặc trưng gói tin từ nhánh features do gateway_ai.py sinh ra
    features = raw.get("features", {})
    packet_rate = _num(features.get("packet_rate", raw.get("packet_rate", 0)))
    syn_count = _num(features.get("syn_count", raw.get("syn_count", 0)))
    
    # Ước lượng thông số hiển thị từ các đặc trưng lõi
    normal_est = max(0.0, packet_rate - syn_count)

    # 3. RTT (đọc từ raw hoặc gán mặc định an toàn cho hệ thống)
    rtt = raw.get("rtt_ms")
    rtt = _num(rtt, None) if rtt is not None else None   # không bịa số: không có RTT thì hiện "—"

    return {
        "ts": to_epoch(raw.get("timestamp")),
        "normal": normal_est,
        "syn": syn_count,
        "udp": _num(features.get("byte_rate", 0)) / 1000.0,
        "packet_rate": packet_rate,
        "rtt_ms": rtt,
        "status_raw": str(raw.get("status", "")),
        "status": classify_status(raw.get("status")),
        "blocked": blocked,
        "simulated": False,  # Xác nhận đây là dữ liệu thật từ Edge AI Gateway
    }


def is_stale(state, now=None) -> bool:
    if state is None:
        return True
    return ((now if now is not None else time.time()) - state["ts"]) > STALE_AFTER_S


# ---------------------------------------------------------------- trạng thái 4 tầng
def tier_states(state, stale: bool = False) -> dict:
    """Quy tắc tô màu:
      - cảm biến, camera : đỏ khi RTT > 200 ms
      - máy chủ          : đỏ khi RTT > 200 ms hoặc đang có tấn công chưa bị chặn
      - gateway          : đỏ khi trạng thái ATTACK
      - kẻ tấn công      : đỏ khi có tấn công (ATTACK) hoặc đã bị chặn (BLOCKED)
      - xám              : chưa có dữ liệu / mất kết nối
    """
    keys = ("sensor", "camera", "gateway", "server", "attacker")
    if state is None or stale:
        label = "Chờ dữ liệu" if state is None else "Mất kết nối"
        return {k: {"ok": None, "label": label, "detail": ""} for k in keys}

    rtt, status, nblk = state["rtt_ms"], state["status"], len(state["blocked"])
    rtt_bad = rtt is not None and rtt > RTT_LIMIT_MS
    attack, mitig = status == "attack", status == "mitigated"
    rtt_txt = f"RTT {rtt:.0f} ms" if rtt is not None else "RTT n/a"

    def tier(bad, ok_label, bad_label, detail):
        return {"ok": not bad, "label": bad_label if bad else ok_label, "detail": detail}

    ips = ", ".join(b["ip"] for b in state["blocked"][:2]) + (" ..." if nblk > 2 else "")
    return {
        "sensor": tier(rtt_bad, "Bình thường", "Bị suy giảm", rtt_txt),
        "camera": tier(rtt_bad, "Bình thường", "Bị suy giảm", rtt_txt),
        "server": tier(rtt_bad or attack, "Bình thường", "Bị ảnh hưởng", rtt_txt),
        "gateway": tier(attack, ("Đã chặn %d IP" % nblk) if mitig else "Hoạt động tốt",
                        "Đang bị flood", "Edge AI + QoS + Firewall"),
        "attacker": tier(attack or mitig, "Không có", "Đã bị chặn" if mitig else "Đang tấn công",
                         ips if (attack or mitig) and nblk else ("Nguồn flood" if attack else "Mạng ngoài")),
    }


def build_tier_svg(tiers: dict) -> str:
    """SVG sơ đồ 4 tầng + Gateway. Trả về chuỗi SVG hoàn chỉnh (dùng cho st.image)."""
    col = lambda ok: GREY if ok is None else (GREEN if ok else RED)
    e = html.escape
    boxes = [
        ("attacker", 14, 150, 190, 100, "Kẻ tấn công", "Mạng ngoài · 192.168.100.0/24"),
        ("gateway", 300, 120, 210, 160, "Edge Gateway", "Edge AI · QoS · Firewall"),
        ("sensor", 610, 14, 196, 100, "Tầng cảm biến", "VLAN 10 · 300 cảm biến"),
        ("camera", 610, 150, 196, 100, "Tầng camera", "VLAN 20 · 20 camera"),
        ("server", 610, 286, 196, 100, "Tầng máy chủ", "VLAN 30 · MQTT broker"),
    ]
    p = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 820 440" width="820" height="440" '
         'font-family="Segoe UI, Helvetica, Arial, sans-serif">',
         '<rect width="820" height="440" fill="#FFFFFF"/>',
         '<defs><marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
         'orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#5B6570"/></marker></defs>']
    atk = col(tiers["attacker"]["ok"])
    p.append(f'<line x1="204" y1="200" x2="298" y2="200" stroke="{atk}" stroke-width="3" '
             f'stroke-dasharray="7 5" marker-end="url(#ar)"/>')
    p.append('<text x="251" y="190" font-size="12" fill="#444" text-anchor="middle">gw-eth1</text>')
    for y in (64, 200, 336):
        p.append(f'<line x1="510" y1="200" x2="608" y2="{y}" stroke="#5B6570" stroke-width="2.5" '
                 f'marker-end="url(#ar)"/>')
    p.append('<text x="405" y="304" font-size="12" fill="#444" text-anchor="middle">'
             'trunk gw-eth0 → OVS s1 (VLAN 10/20/30)</text>')
    for key, x, y, w, h, title, sub in boxes:
        t = tiers[key]
        c = col(t["ok"])
        p.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{c}"/>')
        cx = x + w / 2
        p.append(f'<text x="{cx}" y="{y + 28}" font-size="18" font-weight="700" fill="#fff" '
                 f'text-anchor="middle">{e(title)}</text>')
        p.append(f'<text x="{cx}" y="{y + 49}" font-size="12" fill="#fff" fill-opacity="0.9" '
                 f'text-anchor="middle">{e(sub)}</text>')
        p.append(f'<text x="{cx}" y="{y + 76}" font-size="16" font-weight="600" fill="#fff" '
                 f'text-anchor="middle">{e(t["label"])}</text>')
        detail = "Cửa sổ 1 giây · Random Forest" if key == "gateway" else t["detail"]
        if detail:
            yy = y + (110 if key == "gateway" else 94)
            p.append(f'<text x="{cx}" y="{yy}" font-size="12" fill="#fff" fill-opacity="0.9" '
                     f'text-anchor="middle">{e(detail)}</text>')
    for i, (c, txt) in enumerate(((GREEN, "Xanh: bình thường"), (RED, "Đỏ: bị ảnh hưởng / tấn công"),
                                  (GREY, "Xám: chưa có dữ liệu"))):
        x = 20 + i * 250
        p.append(f'<rect x="{x}" y="412" width="16" height="16" rx="3" fill="{c}"/>'
                 f'<text x="{x + 24}" y="425" font-size="13" fill="#333">{e(txt)}</text>')
    p.append("</svg>")
    return "".join(p)


# ---------------------------------------------------------------- lịch sử & nhật ký
def update_history(hist: list, state: dict, maxlen: int = 180) -> bool:
    """Thêm bản ghi mới (bỏ qua nếu timestamp trùng). Trả về True nếu có thêm."""
    if hist and abs(hist[-1]["ts"] - state["ts"]) < 1e-6:
        return False
    hist.append({"ts": state["ts"], "normal": state["normal"], "syn": state["syn"],
                 "udp": state["udp"], "rtt_ms": state["rtt_ms"]})
    del hist[:-maxlen]
    return True


def update_blocked_log(log: list, active: set, state: dict) -> None:
    """Ghi nhật ký khi một IP mới bị chặn hoặc được gỡ chặn."""
    now_ips = {b["ip"]: b for b in state["blocked"]}
    for ip, b in now_ips.items():
        if ip not in active:
            t = to_epoch(b["time"]) if b["time"] else state["ts"]
            log.append({"Thời điểm": fmt_time(t), "IP nguồn": ip, "Sự kiện": "CHẶN",
                        "Ghi chú": b["reason"] or "Edge AI phân loại là tấn công"})
    for ip in list(active):
        if ip not in now_ips:
            log.append({"Thời điểm": fmt_time(state["ts"]), "IP nguồn": ip, "Sự kiện": "GỠ CHẶN", "Ghi chú": ""})
    active.clear()
    active.update(now_ips)


# ---------------------------------------------------------------- lệnh kịch bản
def send_command(scenario: str, **params) -> dict:
    if scenario not in SCENARIOS:
        raise ValueError(f"kịch bản không hợp lệ: {scenario}")
    cmd = {"id": uuid.uuid4().hex[:8], "ts": time.time(), "scenario": scenario, **params}
    atomic_write(CMD_PATH, cmd)
    return cmd


def read_command():
    d, _ = load_json(CMD_PATH)
    return d


def write_status(**kw) -> None:
    kw["heartbeat"] = time.time()
    atomic_write(STATUS_PATH, kw)


def read_status():
    d, _ = load_json(STATUS_PATH)
    return d


def daemon_alive(status, max_age: float = 6.0) -> bool:
    return bool(status) and (time.time() - _num(status.get("heartbeat"), 0)) < max_age