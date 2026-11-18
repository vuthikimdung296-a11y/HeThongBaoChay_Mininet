import json
import os
import streamlit as st
import pandas as pd
import time
from datetime import datetime

# Cấu hình trang Streamlit
st.set_page_config(
    page_title="Dashboard Giám Sát An Ninh Mạng",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ HỆ THỐNG GIÁM SÁT AN NINH MẠNG & PHÒNG CHỐNG TẤN CÔNG")
st.markdown("---")

METRICS_FILE = "live_metrics.json"

# Khởi tạo bộ nhớ tạm trên session để lưu lịch sử vẽ biểu đồ
if "history_traffic" not in st.session_state:
    st.session_state.history_traffic = []
if "history_logs" not in st.session_state:
    st.session_state.history_logs = []

def load_data():
    if os.path.exists(METRICS_FILE):
        try:
            with open(METRICS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

data = load_data()

# ----------------- 1. SƠ ĐỒ TRẠNG THÁI 4 TẦNG -----------------
st.subheader("1. Sơ đồ trạng thái 4 tầng (Xanh/Đỏ)")
status_str = data.get("status", "NORMAL")
is_attack = (status_str == "ATTACK")

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.markdown(f"**Tầng 1: Cảm biến (IoT)**\n\nTrạng thái: {'<span style=\"color:red\">CẢNH BÁO</span>' if is_attack else 'AN TOÀN'}", unsafe_allow_html=True)
with col2:
    st.markdown(f"**Tầng 2: Gateway**\n\nTrạng thái: {'<span style=\"color:red\">CẢNH BÁO</span>' if is_attack else 'AN TOÀN'}", unsafe_allow_html=True)
with col3:
    st.markdown(f"**Tầng 3: AI Detection**\n\nTrạng thái: {'<span style=\"color:red\">TẤN CÔNG</span>' if is_attack else 'AN TOÀN'}", unsafe_allow_html=True)
with col4:
    st.markdown(f"**Tầng 4: Phản hồi/Chặn**\n\nTrạng thái: {'<span style=\"color:red\">ĐANG CHẶN IP</span>' if is_attack else 'AN TOÀN'}", unsafe_allow_html=True)

st.markdown("---")

# Cập nhật dữ liệu vào lịch sử nếu có packet_rate
features = data.get("features", {})
current_time = data.get("datetime", datetime.now().strftime("%H:%M:%S"))
pkt_rate = features.get("packet_rate", 0)

if pkt_rate > 0:
    # Thêm vào lịch sử (giữ tối đa 30 mốc gần nhất)
    st.session_state.history_traffic.append({"Thời gian": current_time, "Lưu lượng gói (pps)": pkt_rate})
    if len(st.session_state.history_traffic) > 30:
        st.session_state.history_traffic.pop(0)

    # Nếu có IP bị chặn, thêm vào nhật ký
    firewall_info = data.get("firewall", {})
    blocked_ips = firewall_info.get("blocked_ips", [])
    for ip in blocked_ips:
        log_entry = {"Thời gian": current_time, "IP bị chặn": ip, "Lý do": data.get("attack_type", "DDoS Attack")}
        if log_entry not in st.session_state.history_logs:
            st.session_state.history_logs.append(log_entry)

# ----------------- 2. BIỂU ĐỒ LƯU LƯỢNG THỜI GIAN THỰC -----------------
st.subheader("2. Biểu đồ lưu lượng gói tin thời gian thực")
if st.session_state.history_traffic:
    df_chart = pd.DataFrame(st.session_state.history_traffic)
    df_chart.set_index("Thời gian", inplace=True)
    st.line_chart(df_chart)
else:
    st.info("Chưa có dữ liệu lưu lượng gói tin. Hãy chạy kịch bản thử nghiệm từ gateway_ai.py!")

st.markdown("---")

# ----------------- 3. NHẬT KÝ IP BỊ CHẶN -----------------
st.subheader("3. Nhật ký IP bị chặn")
if st.session_state.history_logs:
    df_logs = pd.DataFrame(st.session_state.history_logs)
    st.dataframe(df_logs, use_container_width=True)
else:
    st.success("Không có IP nào bị chặn gần đây.")

st.markdown("---")

# ----------------- 4. BẢNG ĐIỀU KHIỂN KỊCH BẢN -----------------
st.subheader("4. Bảng điều khiển kích hoạt kịch bản")
col_b1, col_b2, col_b3 = st.columns(3)
with col_b1:
    if st.button("🚀 Chạy kịch bản: Bình thường"):
        st.toast("Đã kích hoạt kịch bản bình thường!", icon="✅")
with col_b2:
    if st.button("⚠️ Chạy kịch bản: Tấn công (Chưa bật AI+QoS)"):
        st.toast("Đã kích hoạt tấn công không phòng thủ!", icon="⚠️")
with col_b3:
    if st.button("🛡️ Chạy kịch bản: Tấn công (Có bật AI+QoS)"):
        st.toast("Đã kích hoạt phòng thủ AI+QoS!", icon="🛡️")

# Tự động làm mới giao diện mỗi 2 giây để cập nhật dữ liệu từ file JSON
if st.checkbox("Tự động làm mới (Auto-refresh mỗi 2s)", value=True):
    time.sleep(2)
    st.rerun()
