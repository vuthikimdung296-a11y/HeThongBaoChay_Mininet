# -*- coding: utf-8 -*-
"""dashboard.py - Web giám sát DDoS tại Gateway (Streamlit).

Chạy:   streamlit run Web/dashboard/dashboard.py    ->  http://localhost:8501
Cần:    pip/apt cài streamlit>=1.37 và pandas.

Đọc live_metrics.json (Việt Anh ghi mỗi giây), hiển thị:
  - sơ đồ trạng thái 4 tầng Xanh/Đỏ,
  - biểu đồ gói tin theo thời gian thực (+ RTT so với KPI),
  - nhật ký IP bị chặn,
  - 3 nút kích hoạt kịch bản của Tổ 3 (gửi lệnh qua file cho experiments/scenario_daemon.py).
"""
import time
import zipfile
from pathlib import Path

import pandas as pd
import streamlit as st

import dashboard_logic as dl

st.set_page_config(page_title="Giám sát DDoS - Gateway báo cháy", page_icon="🔥", layout="wide")

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RESULTS_ZIP = REPO_ROOT / "ket_qua_kiem_thu.zip"
RESULT_FILES = {
    "scenarios": "scenario_metrics.csv",
    "cameras": "camera_metrics.csv",
    "attacks": "attack_events.csv",
    "matrix": "run_matrix_manifest.csv",
}


@st.cache_data(show_spinner=False)
def load_vm_results(archive_path):
    with zipfile.ZipFile(archive_path) as archive:
        missing = [name for name in RESULT_FILES.values() if name not in archive.namelist()]
        if missing:
            raise ValueError("ZIP thiếu các tệp: " + ", ".join(missing))
        return {
            key: pd.read_csv(archive.open(filename))
            for key, filename in RESULT_FILES.items()
        }


ss = st.session_state
ss.setdefault("history", [])
ss.setdefault("blocked_log", [])
ss.setdefault("active_blocked", set())

# ------------------------------------------------------------------ sidebar
with st.sidebar:
    st.header("Cấu hình")
    live_path = st.text_input("File live_metrics.json", dl.LIVE_PATH)
    results_zip = st.text_input("ZIP kết quả kiểm thử máy ảo", str(DEFAULT_RESULTS_ZIP))
    refresh = st.slider("Chu kỳ làm mới (giây)", 1, 5, 1)
    window = st.slider("Số điểm hiển thị trên biểu đồ", 30, 180, 90, step=10)
    if st.button("Xóa lịch sử biểu đồ và nhật ký"):
        ss.history.clear()
        ss.blocked_log.clear()
        ss.active_blocked.clear()
    st.caption("Ngưỡng KPI: RTT ≤ 50 ms (bình thường), ≤ 200 ms (khi bị tấn công), "
               "phản ứng của tường lửa ≤ 3 giây.")

st.title("🔥 Giám sát DDoS tại Gateway - Hệ thống cảnh báo cháy thông minh")

with st.expander("Kết quả kiểm thử Mininet từ ZIP", expanded=True):
    st.caption("Dữ liệu đo đã lưu từ máy ảo; bảng giữ nguyên cả các lượt lỗi, không tự kết luận đạt.")
    if not Path(results_zip).is_file():
        st.warning(f"Không tìm thấy ZIP kết quả: {results_zip}")
    else:
        try:
            vm_results = load_vm_results(results_zip)
        except (OSError, ValueError, zipfile.BadZipFile, pd.errors.ParserError) as exc:
            st.error(f"Không đọc được ZIP kết quả: {exc}")
        else:
            scenarios = vm_results["scenarios"]
            cameras = vm_results["cameras"]
            attacks = vm_results["attacks"]
            matrix = vm_results["matrix"]
            status = matrix.get("status", pd.Series(dtype=str)).astype(str).str.lower()
            summary = st.columns(4)
            summary[0].metric("Lượt đo kịch bản", len(scenarios))
            summary[1].metric("Lượt ma trận", len(matrix))
            summary[2].metric("Lượt ma trận thành công", int(status.eq("ok").sum()))
            summary[3].metric("Lượt ma trận lỗi", int(status.eq("error").sum()))

            st.subheader("RTT và mất gói theo lượt đo")
            st.dataframe(scenarios, hide_index=True, use_container_width=True)

            if not cameras.empty:
                camera_summary = (
                    cameras.groupby("camera_id", as_index=False)
                    .agg(
                        throughput_mbps=("throughput_mbps", "mean"),
                        packet_loss_percent=("packet_loss_percent", "mean"),
                        samples=("camera_id", "size"),
                    )
                    .round(2)
                )
                camera_summary = camera_summary.rename(columns={
                    "camera_id": "Camera",
                    "throughput_mbps": "Thông lượng TB (Mbps)",
                    "packet_loss_percent": "Mất gói TB (%)",
                    "samples": "Số mẫu",
                })
                st.subheader(f"Camera — {len(cameras)} mẫu (trung bình theo camera)")
                st.dataframe(camera_summary, hide_index=True, use_container_width=True)

            st.subheader(f"Sự kiện tấn công — {len(attacks)}")
            st.dataframe(attacks, hide_index=True, use_container_width=True)

            st.subheader("Ma trận chạy thử")
            st.dataframe(matrix, hide_index=True, use_container_width=True)
            failures = matrix.loc[status.eq("error")]
            if not failures.empty:
                st.warning(f"Có {len(failures)} lượt lỗi trong ma trận; xem cột error ở bảng trên.")

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
               "`py from Web.experiments.scenario_daemon import serve; serve(net)`")


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
        st.warning(
            f"Chưa đọc được {live_path} ({err}). Hãy chạy gateway_ai.py hoặc "
            "dashboard/simulate_live_metrics.py (dữ liệu mô phỏng). "
            "Nếu Edge AI chạy trong VM Linux, Web cũng cần chạy trong VM đó hoặc đọc từ một file được chia sẻ."
        )
    elif state["simulated"]:
        st.warning("⚠️ DỮ LIỆU MÔ PHỎNG - không dùng ảnh chụp này làm số liệu thực nghiệm trong báo cáo.")
    elif stale:
        st.error("Mất kết nối: không có dữ liệu mới trong hơn %d giây." % dl.STALE_AFTER_S)

    # thẻ số liệu
    m = st.columns(4)
    label = {"normal": "BÌNH THƯỜNG", "attack": "ĐANG BỊ TẤN CÔNG", "mitigated": "ĐÃ CHẶN",
             "unknown": "KHÔNG RÕ"}
    m[0].metric("Trạng thái", label[state["status"]] if state else "—")
    prob = state.get("prob_attack", state.get("prob")) if state else None
    m[1].metric("Xác suất tấn công (AI)", f"{prob * 100:.1f}%" if prob is not None else "—")
    rtt = state["rtt_ms"] if state else None
    m[2].metric("Tổng gói IPv4/s", f"{state['packet_rate']:.0f}"
                if state and state["packet_rate"] is not None else "—")
    m[3].metric("RTT (ms)", f"{rtt:.1f}" if rtt is not None else "—",
                delta=(f"{rtt - dl.RTT_LIMIT_MS:+.0f} so với ngưỡng 200" if rtt is not None else None),
                delta_color="inverse")
    m = st.columns(3)
    m[0].metric("Gói bình thường/s", f"{state['normal']:.0f}"
                if state and state["normal"] is not None else "—")
    m[1].metric("Gói SYN/s", f"{state['syn']:.0f}" if state else "—")
    m[2].metric("Gói UDP/s", f"{state['udp']:.0f}" if state else "—")

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
        firewall = state.get("firewall", {}) if state else None
        if firewall and firewall["backend"]:
            mode = "rate-limit đang bật" if firewall["rate_limit_active"] else "rate-limit tắt"
            st.caption(f"Firewall {firewall['backend']}: {mode}; {firewall['active_rules']:.0f} luật")
            if firewall["errors"]:
                st.warning("Firewall báo lỗi: " + "; ".join(str(e) for e in firewall["errors"]))
        else:
            st.caption("Chưa nhận trạng thái firewall từ Edge AI.")

    hist = ss.history[-window:]
    if len(hist) >= 2:
        df = pd.DataFrame(hist)
        df.index = pd.to_datetime(df["ts"], unit="s")
        for _c in ["packet_rate", "normal", "syn", "udp"]:
            if _c not in df.columns:
                df[_c] = 0.0
        pk = df[["packet_rate", "normal", "syn", "udp"]].rename(columns={
            "packet_rate": "Tổng gói IPv4",
            "normal": "Gói bình thường",
            "syn": "Gói SYN",
            "udp": "Gói UDP",
        })
        pk = pk.dropna(axis=1, how="all")
        st.subheader("Gói tin theo thời gian thực (gói/giây)")
        try:
            st.line_chart(pk)
        except TypeError:
            st.line_chart(pk)
        if df["rtt_ms"].notna().any():
            st.subheader("RTT so với ngưỡng KPI (ms)")
            rt = pd.DataFrame({"RTT": df["rtt_ms"], "Ngưỡng 200 ms": dl.RTT_LIMIT_MS,
                               "Ngưỡng 50 ms": dl.RTT_NORMAL_MS})
            try:
                st.line_chart(rt, color=["#2B6CB0", "#C93A3A", "#E08A00"])
            except TypeError:
                st.line_chart(rt)
        else:
            st.caption("Edge AI không đo RTT; chỉ hiển thị RTT khi nguồn live_metrics có trường rtt_ms.")
    else:
        st.caption("Đang chờ đủ dữ liệu để vẽ biểu đồ...")


try:
    live = st.fragment(run_every=refresh)(render_live)       # streamlit >= 1.37
    live()
except (AttributeError, TypeError):
    render_live()                                             # phương án dự phòng cho bản cũ
    time.sleep(refresh)
    st.rerun()
