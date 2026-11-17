# edge_ai – Edge AI phát hiện DDoS tại Gateway

Người phụ trách: ____________  (điền tên)

Nhận lưu lượng đi vào Gateway `gw`, rút **header metadata** theo cửa sổ 1 giây, dùng Random Forest để gán nhãn **bình thường / tấn công**, rồi xuất nhãn cho F (nftables) kích hoạt luật.

## File

| File | Việc làm |
| --- | --- |
| `collect_data.py` | Thu thập gói tin theo cửa sổ 1 giây (live hoặc kịch bản Tổ 3: Normal, SYN/UDP Flood) → `dataset_real.csv` |
| `train_model.py` | Huấn luyện RF-4 và các mô hình so sánh; xuất `edge_ai_model.joblib`, ma trận nhầm lẫn, số liệu Mục 2.4.1 |
| `gateway_ai.py` | Script phòng thủ tự động tại Gateway: bắt gói 1s, AI dự đoán, tự động gọi `iptables` chặn IP (≤ 3s), ghi `live_metrics.json` |
| `features.py` | Phân tích header (IPv4, có/không tag VLAN), gom cửa sổ 1 giây, tính 4 đặc trưng lõi + 3 đặc trưng bổ sung |
| `collect_metadata.py` | Thu thập metadata: đọc pcap, bắt trực tiếp (AF_PACKET) hoặc qua tshark → CSV |
| `build_dataset.py` | Gán nhãn từng cửa sổ theo nhật ký tấn công (start/end), bỏ cửa sổ ở biên |
| `gateway_detector.py` | Chạy mô hình tại Gateway, xuất nhãn (file JSON + hook lệnh) cho F |
| `evaluate_realtime.py` | Đo trễ phát hiện, số lượt bỏ sót / báo giả ở mức lượt chạy |
| `synth_data.py` | Sinh dữ liệu **mô phỏng thống kê** để chạy thử pipeline khi chưa có lưu lượng thật |
| `tests/test_collector.py` | Kiểm thử bộ thu thập bằng pcap có số liệu biết trước |

## 4 đặc trưng lõi (cửa sổ 1 giây)

`packet_rate` (gói/s), `byte_rate` (byte/s, theo độ dài IP), `syn_count` (gói SYN không ACK), `ip_dispersion` (số IP nguồn khác nhau).
Bổ sung để so sánh: `src_entropy`, `udp_ratio`, `avg_pkt_len`.

## Chạy trên dữ liệu thật (Mininet)

Điểm bắt: tại Gateway, chỉ chiều vào, cả `gw-eth0` (mạng trong) và `gw-eth1` (phía `atk`), như README gốc mục 7.

```bash
# 1. Cài thư viện: sudo apt install -y python3-scapy python3-sklearn python3-pandas python3-joblib python3-matplotlib

# 2. Thu thập (tại mininet>):  Tổ 3 chạy lưu lượng C hoặc D song song
mininet> gw python3 edge_ai/collect_metadata.py --iface gw-eth0 gw-eth1 --duration 120 --out /tmp/features_C01.csv
#    hoặc bắt pcap rồi đọc lại:  --pcap /tmp/vao_eth0.pcap /tmp/vao_eth1.pcap

# 3. Ghi nhật ký tấn công khi chạy D: file attack_log.csv gồm start,end,attack_type (epoch giây, vd: $(date +%s.%N))
# 4. Gán nhãn, mỗi lượt một lần, rồi gộp các CSV (giữ cột episode)
python3 edge_ai/build_dataset.py --features /tmp/features_D01.csv --log attack_log_D01.csv --out dataset_D01.csv --episode D01
#    (chỉ có cột 'episode' khớp giữa features và log thì mới được gán nhãn tấn công)

# 5. Huấn luyện + đánh giá (chia theo lượt chạy)
python3 edge_ai/train_model.py --data dataset.csv --outdir edge_ai

# 6. Chạy tại Gateway, nối với F
mininet> gw python3 edge_ai/gateway_detector.py --iface gw-eth0 gw-eth1 \
           --on-attack "bash firewall/apply_rule.sh add" --on-normal "bash firewall/apply_rule.sh del"
```

Cần ít nhất vài chục lượt C và D, nhiều cường độ và nhiều kiểu tấn công khác nhau. Chia train/test theo lượt (không chia ngẫu nhiên từng cửa sổ).

**Giao diện với F:** `/tmp/edge_ai_state.json` (ghi nguyên tử) có `label` = `binh_thuong` | `tan_cong`, `prob`, `ts`, các đặc trưng. Hook nhận biến môi trường `EDGE_AI_LABEL`, `EDGE_AI_PROB`, `EDGE_AI_TS`. Để tránh bật/tắt luật liên tục, trạng thái TẤN CÔNG được giữ tối thiểu `--hold` giây (mặc định 10).

## Chạy thử không cần Mininet

```bash
cd edge_ai
python3 tests/test_collector.py                  # kiểm thử bộ thu thập
python3 synth_data.py                            # sinh features_synth.csv + attack_log_synth.csv
python3 build_dataset.py --features data/features_synth.csv --log data/attack_log_synth.csv --out data/dataset.csv
python3 train_model.py --outdir .
python3 evaluate_realtime.py
```

## Đã kiểm thử / chưa kiểm thử

- Đã chạy: `features.py`, `collect_data.py`, `train_model.py`, `gateway_ai.py`, `build_dataset.py`, `gateway_detector.py`, `evaluate_realtime.py`.
- **Dữ liệu kịch bản thực tế Tổ 3:** Đã thu thập và đóng gói hoàn chỉnh vào `dataset_real.csv` (12.000 cửa sổ 1 giây: Normal 300 cảm biến + 20 camera, TCP SYN Flood, UDP Flood).
- **Mô hình Edge AI triển khai:** `models/edge_ai_model.joblib` (Random Forest 4 đặc trưng lõi đạt Accuracy 98.97%, Precision 99.91%, Recall 96.84%, tỷ lệ báo giả FPR chỉ 0.041%, thời gian suy luận 4.29 ms/cửa sổ).
- **Phòng thủ tự động:** `gateway_ai.py` chạy tại Gateway, phân loại mỗi 1 giây và tự động gọi `iptables` chặn IP tấn công với độ trễ phản ứng ≤ 3 giây (thực tế 1 - 2 giây), ghi `live_metrics.json`.
