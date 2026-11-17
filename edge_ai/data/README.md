# Thư mục Dữ liệu Huấn luyện Edge AI (edge_ai/data)

Thư mục này dùng để lưu trữ dữ liệu đặc trưng **thu thập thực tế từ mạng ảo Mininet**, phục vụ huấn luyện và kiểm thử mô hình phát hiện DDoS tại Gateway.

> [!IMPORTANT]
> Toàn bộ dữ liệu đặt tại đây phải được trích xuất từ các lần chạy thực tế trong mạng Mininet thông qua `collect_metadata.py` và nhật ký tấn công từ `traffic/attack.py`. Không lưu dữ liệu tự sinh ngẫu nhiên vào thư mục này.

## Quy trình thu thập và chuẩn bị dữ liệu thực tế (theo Hướng dẫn Tổ 2):

1. **Khởi động mạng Mininet:**
   ```bash
   cd Network
   sudo mn -c
   sudo python3 topology.py
   ```

2. **Khởi chạy bộ thu thập đặc trưng tại Gateway (`gw`):**
   ```bash
   # Bắt gói qua 2 giao diện gw-eth0 (nội bộ VLAN) và gw-eth1 (kẻ tấn công):
   gw python3 edge_ai/collect_metadata.py --iface gw-eth0 gw-eth1 --duration 150 --out edge_ai/data/features_kichban3_syn_1000_lan1.csv &
   ```

3. **Chạy kịch bản lưu lượng và tấn công:**
   ```bash
   # Phát lưu lượng bình thường (MQTT + Camera) và kích hoạt đợt tấn công từ host atk
   # Nhật ký tấn công được lưu tự động tại traffic/results/attack_events.csv
   ```

4. **Gán nhãn dữ liệu (loại bỏ cửa sổ giao ở biên):**
   ```bash
   python3 edge_ai/build_dataset.py \
     --features edge_ai/data/features_kichban3_syn_1000_lan1.csv \
     --log traffic/results/attack_events.csv \
     --episode kichban3_syn_1000_lan1 \
     --out edge_ai/data/dataset_mininet.csv
   ```

5. **Huấn luyện mô hình:**
   ```bash
   python3 edge_ai/train_model.py --data edge_ai/data/dataset_mininet.csv --outdir edge_ai/models
   ```
