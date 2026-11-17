# edge_ai – Module Edge AI Phát hiện & Phòng thủ DDoS tại Gateway

**Người phụ trách:** Tổ Edge AI & Gateway Defense  
**Đề tài:** Hệ thống cảnh báo cháy thông minh – Mô phỏng Mininet & Phòng chống DDoS

Module chịu trách nhiệm giám sát lưu lượng ingress tại Gateway `gw`, trích xuất **Header Metadata** theo cửa sổ 1 giây, sử dụng mô hình học máy Random Forest để phân loại trạng thái lưu lượng (**Bình thường / Tấn công**), và tự động kích hoạt luật tường lửa **nftables** (hoặc `iptables`) nhằm bảo vệ mạng nội bộ và máy chủ MQTT.

---

## 1. Cấu trúc thư mục và tệp tin

| Tệp tin | Vai trò và chức năng |
| :--- | :--- |
| `features.py` | Bộ phân tích khung Ethernet/VLAN 802.1Q, trích xuất 4 đặc trưng lõi + 3 đặc trưng mở rộng, gom cửa sổ 1 giây (`WindowAggregator`). Được dùng chung cho toàn bộ quy trình thu thập, huấn luyện và phát hiện trực tiếp. |
| `collect_metadata.py` | Thu thập metadata trực tiếp qua socket `AF_PACKET` (Linux) hoặc đọc file pcap offline; xuất CSV đặc trưng. |
| `build_dataset.py` | Gán nhãn từng cửa sổ dựa trên nhật ký tấn công (`start`/`end` theo epoch hoặc chuỗi UTC ISO 8601), tự động loại bỏ các cửa sổ biên không chắc chắn. |
| `train_model.py` | Huấn luyện mô hình Random Forest (RF-4) và các mô hình so sánh; phân chia theo lượt chạy (`GroupShuffleSplit`, `GroupKFold`); lưu mô hình kèm phiên bản `scikit-learn`. |
| `gateway_ai.py` | Module vận hành phòng thủ trực tiếp tại Gateway: tích hợp AI, bộ làm mượt trạng thái ($k_{on}=2, k_{off}=3, hold \ge 10s$), bảng tường lửa riêng `inet ddos` (nftables), cơ chế Whitelist chống chặn nhầm, xuất `live_metrics.json`. |
| `gateway_detector.py` | Detector dạng hook/command-line linh hoạt gọi script ngoại vi khi đổi trạng thái. |
| `evaluate_realtime.py` | Đánh giá độ trễ phát hiện, tỷ lệ bỏ sót và tỷ lệ báo động nhầm ở cấp độ lượt chạy. |
| `synth_data.py` | Bộ sinh dữ liệu mô phỏng kỹ thuật nhằm kiểm thử đường ống trước khi có số liệu Mininet. |
| `collect_data.py` | Công cụ thu thập / phát lại kịch bản luồng mạng Tổ 3 (Normal + SYN/UDP Flood). |
| `data/README.md` | Hướng dẫn lưu trữ và cấu trúc dữ liệu bắt thực tế từ mạng Mininet. |

---

## 2. 4 đặc trưng lõi (Header Metadata - Cửa sổ 1 giây)

Theo đề cương nghiên cứu, hệ thống chỉ kiểm tra thông tin tiêu đề (không đọc payload), đảm bảo tính riêng tư và tốc độ xử lý:
1. `packet_rate`: Tổng số gói tin IP nhận được mỗi giây (gói/giây).
2. `byte_rate`: Tổng độ dài gói tin IP nhận được mỗi giây (bytes/giây).
3. `syn_count`: Số lượng gói tin TCP có cờ SYN mà không có ACK (dấu hiệu nhận diện SYN Flood).
4. `ip_dispersion`: Số lượng địa chỉ IP nguồn duy nhất trong cửa sổ 1 giây (nhận diện tấn công giả mạo nguồn phân tán).

---

## 3. Cơ chế Tường lửa nftables & Whitelist Bảo vệ Thiết bị Hợp lệ

Để tránh tuyệt đối nguy cơ chặn nhầm cảm biến báo cháy và camera hợp lệ, module áp dụng các nguyên tắc sau:

1. **Bảng nftables riêng biệt (`inet ddos`):**
   - Hook tại `prerouting priority -300` (thực thi trước bảng QoS `inet qos` có `priority -150 mangle`).
   - Gói tin bị drop sẽ bị loại bỏ ngay từ đầu, không đi vào hàng đợi HTB của QoS.
   - Khi tắt hoặc dọn dẹp, chỉ xóa bảng `inet ddos`, **tuyệt đối không dùng `nft flush ruleset`** để không ảnh hưởng bảng QoS.

2. **Whitelist nghiêm ngặt (Hard Whitelist):**
   - `10.0.10.0/23`: Dải IP 300 cảm biến báo cháy MQTT (VLAN 10).
   - `10.0.20.0/24`: Dải IP 20 camera giám sát (VLAN 20).
   - `10.0.30.0/24`: Máy chủ MQTT Server `10.0.30.10` (VLAN 30).
   - `192.168.100.1`: Địa chỉ IP của Gateway trên giao diện ngoại vi `gw-eth1`.
   - Mọi IP thuộc các dải trên **tuyệt đối không bao giờ bị đưa vào danh sách chặn**.

3. **Cơ chế phòng thủ 2 lớp:**
   - **Lớp 1 (Rate-limit cổng ngoài):** Khi AI phát hiện tấn công, tự động áp dụng giới hạn tốc độ trên giao diện `gw-eth1` (phía kẻ tấn công ngoại vi `atk`):
     ```bash
     nft add rule inet ddos prerouting iifname "gw-eth1" tcp flags & (syn | ack) == syn limit rate over 200/second counter drop
     nft add rule inet ddos prerouting iifname "gw-eth1" meta l4proto udp limit rate over 500/second counter drop
     ```
     Cơ chế này chặn đứng tấn công SYN Flood và UDP Flood ngay cả khi kẻ tấn công giả mạo IP nguồn ngẫu nhiên (`--rand-source`).
   - **Lớp 2 (Chặn IP nguồn cụ thể có thời hạn):** Nếu xác định được IP tấn công đơn lẻ từ ngoài `gw-eth1` (không giả mạo và không thuộc whitelist), đưa vào set `blocklist` với `timeout 60s` (tự động giải phóng sau 60 giây).

---

## 4. Hướng dẫn vận hành trong Mininet

### Bước 1: Khởi động mạng ảo Mininet
```bash
cd Network
sudo mn -c
sudo python3 topology.py
```

### Bước 2: Bật dịch vụ Mosquitto trên Server
```bash
mininet> srv mosquitto -d
```

### Bước 3: Áp dụng cấu hình QoS tại Gateway
```bash
mininet> gw bash qos/qos.sh start
```

### Bước 4: Khởi chạy Module Edge AI phòng thủ tự động tại Gateway
```bash
mininet> gw python3 gateway_ai.py --iface gw-eth0 gw-eth1 --firewall nftables --metrics-file /tmp/live_metrics.json &
```

### Bước 5: Bật luồng lưu lượng nền và thử nghiệm tấn công
```bash
# Bật luồng MQTT cảm biến:
mininet> hs01 python3 traffic/normal_mqtt.py &

# Bật đợt tấn công từ host ngoại vi atk:
mininet> atk hping3 -S -p 1883 -i u200 10.0.30.10
```

---

## 5. Quy trình thu thập dữ liệu Mininet thực tế & Huấn luyện lại

Để nộp số liệu đo thực nghiệm chính thức:

1. **Thu thập đặc trưng trong Mininet:**
   ```bash
   mininet> gw python3 edge_ai/collect_metadata.py --iface gw-eth0 gw-eth1 --duration 180 --out edge_ai/data/features_kichban3_lan1.csv &
   ```
2. **Gán nhãn với nhật ký tấn công (`traffic/results/attack_events.csv`):**
   ```bash
   python3 edge_ai/build_dataset.py \
     --features edge_ai/data/features_kichban3_lan1.csv \
     --log traffic/results/attack_events.csv \
     --episode kichban3_lan1 \
     --out edge_ai/data/dataset_mininet.csv
   ```
3. **Huấn luyện mô hình:**
   ```bash
   python3 edge_ai/train_model.py --data edge_ai/data/dataset_mininet.csv --outdir edge_ai/models
   ```

---

## 6. Giới hạn đã biết (Known Limitations)

1. **Nguồn dữ liệu ban đầu:** Bộ dữ liệu kiểm thử đường ống kỹ thuật (`dataset_synth_pipeline.csv`) được sinh mô phỏng để kiểm tra pipeline hoạt động đồng bộ. Các chỉ số đưa vào báo cáo nghiệm thu chính thức phải được đo lại từ các file CSV thu thập trực tiếp trong mạng Mininet.
2. **Mức tấn công thấp (< 1,000 pps):** Khi kẻ tấn công gửi gói tin ở tốc độ thấp (ví dụ UDP 500 pps), lưu lượng tấn công bị lẫn vào nền băng thông lớn của 20 camera giám sát (~80 Mbps), mô hình cần quan sát qua nhiều cửa sổ hoặc có thể bị bỏ sót nếu chỉ xét ngưỡng tức thời.
3. **Đặc tính môi trường ảo hóa:** Mininet chạy trên Open vSwitch và Linux Kernel Namespace, do đó độ trễ và thời gian xử lý gói tin có thể dao động nhẹ tùy thuộc vào tải CPU của máy chủ/máy ảo thực thi.
