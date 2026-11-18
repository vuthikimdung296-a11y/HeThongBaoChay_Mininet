# -*- coding: utf-8 -*-
"""dashboard.py - Web giám sát DDoS tại Gateway (Streamlit).

Chạy:   streamlit run dashboard/dashboard.py        ->  http://localhost:8501
Cần:    pip/apt cài streamlit>=1.37 và pandas.

Đọc live_metrics.json (Việt Anh ghi mỗi giây), hiển thị:
  - sơ đồ trạng thái 4 tầng Xanh/Đỏ,
  - biểu đồ gói tin theo thời gian thực (+ RTT so với KPI),
  - nhật ký IP bị chặn,
  - 3 nút kích hoạt kịch bản của Tổ 3 (gửi lệnh qua file cho experiments/scenario_daemon.py).
"""
import os
import time

import pandas as pd
import streamlit as st

import dashboard_logic as dl

st.set_page_config(page_title="Giám sát DDoS - Gateway báo cháy", page_icon="🔥", layout="wide")

ss = st.session_state
ss.setdefault("history", [])
ss.setdefault("blocked_log", [])
ss.setdefault("active_blocked", set())

# ------------------------------------------------------------------ sidebar
with st.sidebar:
    st.header("Cấu hình")
    live_path = st.text_input("File live_metrics.json", dl.LIVE_PATH)
    refresh = st.slider("Chu kỳ làm mới (giây)", 1, 5, 1)
    window = st.slider("Số điểm hiển thị trên biểu đồ", 30, 180, 90, step=10)
    if st.button("Xóa lịch sử biểu đồ và nhật ký"):
        ss.history.clear()
        ss.blocked_log.clear()
        ss.active_blocked.clear()
    st.caption("Ngưỡng KPI: RTT ≤ 50 ms (bình thường), ≤ 200 ms (khi bị tấn công), "
               "phản ứng của tường lửa ≤ 3 giây.")

st.title("🔥 Giám sát DDoS tại Gateway - Hệ thống cảnh báo cháy thông minh")

# ------------------------------------------------------------------ nút kịch bản
st.subheader("Kích hoạt kịch bản thực nghiệm (Tổ 3)")
with st.expander("Tham số kịch bản", expanded=False):
    c1, c2, c3, c4 = st.columns(4)
    duration = c1.number_input("Thời lượng (s)", 20, 600, 60, step=10)
    attack_type = c2.selectbox("Kiểu tấn công", ["syn_flood", "udp_flood"])
    attack_rate = c3.number_input("Tốc độ (pps)", 100, 5000, 1000, step=100)
    attack_duration = c4.number_input("Thời gian tấn công (s)", 5, 300, 20, step=5)

cols = st.columns(3)
status_file = dl.read_status()
alive = dl.daemon_alive(status_file)
running = bool(status_file) and status_file.get("state") == "running"
for col, (key, label) in zip(cols, dl.SCENARIOS.items()):
    if col.button(label, use_container_width=True, disabled=running or not alive, key=f"btn_{key}"):
        cmd = dl.send_command(key, duration=int(duration), attack_type=attack_type,
                              attack_rate=int(attack_rate), attack_duration=int(attack_duration))
        st.toast(f"Đã gửi lệnh {label} (mã {cmd['id']})")
if not alive:
    st.warning("Chưa thấy scenario_daemon đang chạy nên các nút bị khóa. Tại dấu nhắc `mininet>` chạy:  "
               "`py import sys; sys.path.insert(0,'..')`  rồi  "
               "`py from experiments.scenario_daemon import serve; serve(net)`")


# ------------------------------------------------------------------ phần cập nhật liên tục
def render_live():
    raw, err = dl.load_json(live_path)
    state = dl.normalize(raw) if raw else None
    if state:
        if dl.update_history(ss.history, state):
            dl.update_blocked_log(ss.blocked_log, ss.active_blocked, state)
    stale = dl.is_stale(state)

    # trạng thái kịch bản
    sf = dl.read_status()
    if sf and dl.daemon_alive(sf):
        msg = sf.get("message", "")
        name = dl.SCENARIOS.get(sf.get("scenario"), sf.get("scenario", ""))
        if sf.get("state") == "running":
            st.info(f"Đang chạy kịch bản: {name}. {msg}")
        elif sf.get("state") == "error":
            st.error(f"Kịch bản {name} lỗi: {msg}")
        elif sf.get("state") == "done":
            st.success(f"Kịch bản {name} đã xong. {msg}")

    if state is None:
        st.warning(f"Chưa đọc được {live_path} ({err}). Hãy chạy gateway_ai.py "
                   f"hoặc dashboard/simulate_live_metrics.py (dữ liệu mô phỏng).")
    elif state["simulated"]:
        st.warning("⚠️ DỮ LIỆU MÔ PHỎNG - không dùng ảnh chụp này làm số liệu thực nghiệm trong báo cáo.")
    elif stale:
        st.error("Mất kết nối: không có dữ liệu mới trong hơn %d giây." % dl.STALE_AFTER_S)

    # thẻ số liệu
    m = st.columns(5)
    label = {"normal": "BÌNH THƯỜNG", "attack": "ĐANG BỊ TẤN CÔNG", "mitigated": "ĐÃ CHẶN",
             "unknown": "KHÔNG RÕ"}
    m[0].metric("Trạng thái", label[state["status"]] if state else "—")
    rtt = state["rtt_ms"] if state else None
    m[1].metric("RTT (ms)", f"{rtt:.1f}" if rtt is not None else "—",
                delta=(f"{rtt - dl.RTT_LIMIT_MS:+.0f} so với ngưỡng 200" if rtt is not None else None),
                delta_color="inverse")
    m[2].metric("Gói bình thường/s", f"{state['normal']:.0f}" if state else "—")
    m[3].metric("Gói SYN/s", f"{state['syn']:.0f}" if state else "—")
    m[4].metric("Gói UDP/s", f"{state['udp']:.0f}" if state else "—")

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Sơ đồ trạng thái 4 tầng")
        svg = dl.build_tier_svg(dl.tier_states(state, stale))
        try:
            st.image(svg, use_container_width=True)
        except TypeError:                      # streamlit cũ
            st.image(svg, use_column_width=True)
    with right:
        st.subheader("Nhật ký IP bị chặn")
        if ss.blocked_log:
            st.dataframe(pd.DataFrame(ss.blocked_log[::-1]), hide_index=True, use_container_width=True,
                         height=330)
        else:
            st.caption("Chưa có IP nào bị chặn.")
        st.caption("IP đang bị chặn: " + (", ".join(sorted(ss.active_blocked)) or "không có"))

    hist = ss.history[-window:]
    if len(hist) >= 2:
        df = pd.DataFrame(hist)
        df.index = pd.to_datetime(df["ts"], unit="s")
        pk = df[["normal", "syn", "udp"]].rename(columns={
            "normal": "Gói bình thường", "syn": "Gói SYN", "udp": "Gói UDP"})
        st.subheader("Gói tin theo thời gian thực (gói/giây)")
        try:
            st.line_chart(pk, color=["#1E8E4E", "#C93A3A", "#E08A00"])
        except TypeError:
            st.line_chart(pk)
        st.subheader("RTT so với ngưỡng KPI (ms)")
        rt = pd.DataFrame({"RTT": df["rtt_ms"], "Ngưỡng 200 ms": dl.RTT_LIMIT_MS,
                           "Ngưỡng 50 ms": dl.RTT_NORMAL_MS})
        try:
            st.line_chart(rt, color=["#2B6CB0", "#C93A3A", "#E08A00"])
        except TypeError:
            st.line_chart(rt)
    else:
        st.caption("Đang chờ đủ dữ liệu để vẽ biểu đồ...")


try:
    live = st.fragment(run_every=refresh)(render_live)       # streamlit >= 1.37
    live()
except (AttributeError, TypeError):
    render_live()                                             # phương án dự phòng cho bản cũ
    time.sleep(refresh)
    st.rerun()
