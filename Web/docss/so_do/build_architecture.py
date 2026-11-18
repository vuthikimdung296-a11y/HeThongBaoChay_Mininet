# -*- coding: utf-8 -*-
"""Sinh sơ đồ khối luồng xử lý gói tin tại Gateway (Mục 2.2.1) thành SVG, PNG và .drawio.
Chạy:  python3 docs/so_do/build_architecture.py   (PNG cần playwright + chromium, nếu thiếu chỉ ra SVG/drawio)
Sửa nội dung ở danh sách BOXES / ARROWS bên dưới rồi chạy lại."""
import html
import os

W, H = 1600, 800
HERE = os.path.dirname(os.path.abspath(__file__))

# ------------------------------------------------------------ màu
C = {
    "src": ("#EEF1F5", "#5B6570"), "atk": ("#FBE4E4", "#C93A3A"), "ai": ("#FFF1D6", "#D98A00"),
    "fw": ("#FBE4E4", "#C93A3A"), "qos": ("#E2F3E9", "#1E8E4E"), "srv": ("#E3EDFA", "#2B6CB0"),
    "stage": ("#F7F9FC", "#9AA5B1"), "dash": ("#EDE7F6", "#6A4FA3"), "step": ("#FFFFFF", "#D98A00"),
}

# (id, x, y, w, h, kind, title, [lines], font)   -- kind chọn màu ở trên
BOXES = [
    ("sensor", 20, 60, 230, 110, "src", "Cảm biến khói/nhiệt ×300", ["VLAN 10 · MQTT TCP 1883", "Báo cháy: DSCP 48 (CS6), QoS 1", "Telemetry: DSCP 0, 30 s/lần"], 14),
    ("camera", 20, 200, 230, 100, "src", "Camera IP ×20", ["VLAN 20 · RTSP/UDP", "~4 Mbps/camera (≈80 Mbps)"], 14),
    ("ovs", 285, 110, 110, 130, "src", "OVS s1", ["Switch ảo", "VLAN access", "trunk → gw"], 13),
    ("attacker", 20, 430, 230, 110, "atk", "Kẻ tấn công (mạng ngoài)", ["192.168.100.100", "SYN Flood / UDP Flood", "có thể giả mạo IP nguồn"], 14),
    ("gw", 430, 20, 930, 760, "stage", "", [], 14),
    ("h1", 450, 42, 220, 34, "stage", "GIAI ĐOẠN 1 · Tiếp nhận", [], 14),
    ("h2", 700, 42, 270, 34, "ai", "GIAI ĐOẠN 2 · Edge AI phân loại", [], 14),
    ("h3", 1000, 42, 340, 34, "qos", "GIAI ĐOẠN 3 · Tường lửa & QoS", [], 14),
    ("s1", 450, 110, 220, 450, "stage", "Thu thập lưu lượng vào", ["", "gw-eth0: trunk VLAN 10/20/30", "(cảm biến, camera, máy chủ)", "", "gw-eth1: phía mạng ngoài", "(kẻ tấn công)", "", "Chỉ bắt chiều VÀO", "(AF_PACKET), bỏ gói do", "chính Gateway gửi ra", "→ mỗi gói chỉ đếm 1 lần"], 14),
    ("a1", 720, 125, 230, 80, "step", "Trích header metadata", ["IP nguồn, độ dài IP, giao thức,", "cờ SYN/ACK · KHÔNG đọc payload"], 13),
    ("a2", 720, 225, 230, 90, "step", "Cửa sổ thời gian 1 giây", ["packet_rate · byte_rate", "syn_count · ip_dispersion"], 13),
    ("a3", 720, 335, 230, 100, "step", "Random Forest (4 đặc trưng)", ["Xác suất tấn công ≥ 0,5", "làm mượt: 2 cửa sổ bật / 3 tắt,", "giữ nhãn tấn công ≥ 10 s"], 13),
    ("dec", 735, 460, 200, 80, "ai", "Nhãn?", [], 15),
    ("fw", 1000, 110, 340, 185, "fw", "Module Tường lửa (nftables / iptables)", ["", "Nhãn TẤN CÔNG → chặn IP nguồn", "đáng ngờ (hoặc giới hạn tốc độ)", "Phản ứng ≤ 3 giây", "Luật đặt ở prerouting nên chặn", "trước khi gói vào hàng đợi QoS"], 14),
    ("qos", 1000, 325, 340, 265, "qos", "Module điều tiết QoS", ["nft đánh dấu (mark) theo cổng vào + DSCP", "→ HTB trên gw-eth0.30 + FQ-CoDel mỗi lớp", "", "0x10 Báo cháy (DSCP 48): ≥10 Mbit, ưu tiên 0", "0x11 Telemetry cảm biến: ≥5 Mbit, ưu tiên 1", "0x12 Camera: ≥60 Mbit (trần 90), ưu tiên 2", "0x13 Không tin cậy / gw-eth1: 1 Mbit (trần 10)"], 13),
    ("live", 720, 640, 240, 100, "dash", "live_metrics.json (mỗi 1 s)", ["timestamp, normal/syn/udp_packets,", "rtt_ms, status, blocked_ips"], 13),
    ("server", 1400, 400, 190, 130, "srv", "Máy chủ srv · VLAN 30", ["10.0.30.10", "MQTT broker Mosquitto", "Dashboard / cảnh báo"], 14),
    ("drop", 1400, 150, 190, 90, "atk", "Gói tấn công bị loại", ["(DROP)"], 14),
    ("web", 1400, 640, 190, 100, "dash", "Web Dashboard", ["Streamlit · localhost:8501", "sơ đồ 4 tầng, biểu đồ,", "nhật ký IP bị chặn"], 13),
]

# (điểm..., màu, nét đứt, nhãn, (lx, ly))
ARROWS = [
    ([(250, 115), (290, 150)], "#5B6570", False, "", None),
    ([(250, 250), (290, 200)], "#5B6570", False, "", None),
    ([(390, 175), (450, 175)], "#5B6570", False, "trunk", (420, 165)),
    ([(250, 485), (450, 485)], "#C93A3A", False, "gw-eth1", (350, 475)),
    ([(670, 165), (720, 165)], "#5B6570", False, "", None),
    ([(835, 205), (835, 225)], "#D98A00", False, "", None),
    ([(835, 315), (835, 335)], "#D98A00", False, "", None),
    ([(835, 435), (835, 460)], "#D98A00", False, "", None),
    ([(935, 500), (985, 500), (985, 200), (1000, 200)], "#C93A3A", False, "TẤN CÔNG", (962, 482)),
    ([(935, 520), (1000, 520)], "#1E8E4E", False, "BÌNH THƯỜNG", (968, 552)),
    ([(1340, 465), (1400, 465)], "#1E8E4E", False, "chuyển tiếp", (1370, 455)),
    ([(1340, 195), (1400, 195)], "#C93A3A", False, "", None),
    ([(1115, 110), (1115, 92), (560, 92), (560, 110)], "#C93A3A", True, "chèn luật chặn", (840, 88)),
    ([(835, 540), (835, 640)], "#6A4FA3", True, "ghi trạng thái", (870, 600)),
    ([(960, 690), (1400, 690)], "#6A4FA3", True, "Web đọc file mỗi giây", (1180, 680)),
]

LEGEND = [("#5B6570", False, "Đường đi của gói tin"), ("#6A4FA3", True, "Điều khiển / giám sát")]


def esc(s):
    return html.escape(s, quote=False)


def svg():
    p = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
         f'font-family="Segoe UI, Helvetica, Arial, sans-serif">',
         f'<rect width="{W}" height="{H}" fill="#fff"/>',
         '<defs>' + "".join(
             f'<marker id="m{c[1:]}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" '
             f'orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="{c}"/></marker>'
             for c in {a[1] for a in ARROWS}) + '</defs>']
    for bid, x, y, w, h, kind, title, lines, fs in BOXES:
        fill, stroke = C[kind]
        dash = ' stroke-dasharray="8 5"' if bid == "gw" else ""
        sw = 1.6 if bid in ("gw",) else 2
        if bid == "dec":
            cx, cy = x + w / 2, y + h / 2
            p.append(f'<polygon points="{cx},{y} {x + w},{cy} {cx},{y + h} {x},{cy}" fill="{fill}" stroke="{stroke}" stroke-width="2"/>')
        else:
            rx = 16 if bid != "gw" else 20
            p.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{dash}/>')
        if bid == "gw":
            p.append(f'<text x="{x + w - 16}" y="{y + h - 14}" font-size="14" text-anchor="end" fill="#6B7580">'
                     f'EDGE GATEWAY (nút gw trong Mininet · Ubuntu)</text>')
            continue
        cx = x + w / 2
        if bid == "dec":
            p.append(f'<text x="{cx}" y="{y + h / 2 + 6}" font-size="{fs}" font-weight="700" text-anchor="middle" fill="#333">{esc(title)}</text>')
            continue
        if bid.startswith("h"):
            p.append(f'<text x="{cx}" y="{y + 23}" font-size="{fs}" font-weight="700" text-anchor="middle" fill="#222">{esc(title)}</text>')
            continue
        ty = y + 26
        p.append(f'<text x="{cx}" y="{ty}" font-size="{fs + 2}" font-weight="700" text-anchor="middle" fill="#222">{esc(title)}</text>')
        for i, ln in enumerate(lines):
            p.append(f'<text x="{cx}" y="{ty + 22 + i * (fs + 6)}" font-size="{fs}" text-anchor="middle" fill="#333">{esc(ln)}</text>')
    for pts, col, dashed, label, lp in ARROWS:
        d = " ".join(f"{x},{y}" for x, y in pts)
        p.append(f'<polyline points="{d}" fill="none" stroke="{col}" stroke-width="2.4" '
                 f'{"stroke-dasharray=\"7 5\" " if dashed else ""}marker-end="url(#m{col[1:]})"/>')
        if label:
            p.append(f'<text x="{lp[0]}" y="{lp[1]}" font-size="12.5" font-weight="600" text-anchor="middle" fill="{col}" '
                     f'stroke="#fff" stroke-width="4" paint-order="stroke">{esc(label)}</text>')
    for i, (col, dashed, txt) in enumerate(LEGEND):
        y = 640 + i * 30
        p.append(f'<line x1="20" y1="{y}" x2="70" y2="{y}" stroke="{col}" stroke-width="2.4" '
                 f'{"stroke-dasharray=\"7 5\" " if dashed else ""}/><text x="80" y="{y + 5}" font-size="13" fill="#333">{esc(txt)}</text>')
    p.append('<text x="20" y="720" font-size="12.5" fill="#555">Edge AI bắt một bản sao metadata của gói tin vào để phân loại; QoS xử lý gói</text>'
             '<text x="20" y="738" font-size="12.5" fill="#555">trên đường chuyển tiếp thật. Cả hai cùng chạy trên Gateway.</text>')
    p.append("</svg>")
    return "".join(p)


def drawio():
    cells, i = [], 2

    def nid():
        nonlocal i
        i += 1
        return f"c{i}"
    for bid, x, y, w, h, kind, title, lines, fs in BOXES:
        fill, stroke = C[kind]
        val = f"<b>{esc(title)}</b>" + "".join(f"<br>{esc(l)}" for l in lines) if title else ""
        shape = "rhombus;" if bid == "dec" else "rounded=1;arcSize=6;"
        dash = "dashed=1;" if bid == "gw" else ""
        valign = "verticalAlign=top;" if bid not in ("dec", "h1", "h2", "h3") else ""
        cells.append(f'<mxCell id="{nid()}" value="{html.escape(val, quote=True)}" style="{shape}{dash}{valign}whiteSpace=wrap;html=1;'
                     f'fillColor={fill};strokeColor={stroke};fontSize={fs};spacingTop=6;" vertex="1" parent="1">'
                     f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')
    for pts, col, dashed, label, lp in ARROWS:
        mid = "".join(f'<mxPoint x="{x}" y="{y}"/>' for x, y in pts[1:-1])
        arr = f'<Array as="points">{mid}</Array>' if mid else ""
        cells.append(f'<mxCell id="{nid()}" value="{html.escape(label, quote=True)}" style="endArrow=classic;html=1;strokeWidth=2;'
                     f'strokeColor={col};fontColor={col};fontStyle=1;{"dashed=1;" if dashed else ""}" edge="1" parent="1">'
                     f'<mxGeometry relative="1" as="geometry"><mxPoint x="{pts[0][0]}" y="{pts[0][1]}" as="sourcePoint"/>'
                     f'<mxPoint x="{pts[-1][0]}" y="{pts[-1][1]}" as="targetPoint"/>{arr}</mxGeometry></mxCell>')
    return ('<mxfile host="app.diagrams.net"><diagram name="Muc 2.2.1" id="arch"><mxGraphModel dx="1600" dy="800" grid="1" '
            f'gridSize="10" page="1" pageWidth="{W}" pageHeight="{H}"><root><mxCell id="0"/><mxCell id="1" parent="0"/>'
            + "".join(cells) + "</root></mxGraphModel></diagram></mxfile>")


if __name__ == "__main__":
    s = svg()
    open(os.path.join(HERE, "kien_truc_gateway.svg"), "w", encoding="utf-8").write(s)
    open(os.path.join(HERE, "kien_truc_gateway.drawio"), "w", encoding="utf-8").write(drawio())
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            b = pw.chromium.launch()
            pg = b.new_page(viewport={"width": W, "height": H}, device_scale_factor=2)
            pg.set_content(f"<body style='margin:0'>{s}</body>")
            pg.screenshot(path=os.path.join(HERE, "kien_truc_gateway.png"))
            b.close()
    except Exception as e:  # noqa: BLE001
        print("Bỏ qua PNG:", e)
    print("OK")
