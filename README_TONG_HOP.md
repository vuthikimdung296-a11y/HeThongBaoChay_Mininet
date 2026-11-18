# README tổng hợp toàn bộ dự án

## 1. Mục tiêu

Dự án mô phỏng hệ thống cảnh báo cháy thông minh trên Mininet, kết hợp mạng VLAN,
lưu lượng MQTT cảm biến, camera, QoS tại Gateway và Edge AI phát hiện/phòng thủ
lưu lượng bất thường. Dashboard Web dùng để xem trạng thái Gateway, dữ liệu đo và
kết quả các lượt thử nghiệm.

Tài liệu này tóm tắt cách các phần ghép với nhau. README chuyên sâu vẫn nằm trong
các thư mục [Edge AI](edge_ai/README.md), [Traffic](traffic/README.md)
và [QoS](qos/README.md). README gốc ở [README.md](README.md).

## 2. Kiến trúc và luồng dữ liệu

```text
hs01..hs10 (MQTT) ─┐
cam01..cam20 (UDP) ├──> OVS s1 ──> Gateway gw ──> srv (MQTT/iperf3)
atk (lab test) ────┘                    │
                                        ├── QoS: nft marks + HTB/FQ-CoDel
                                        ├── Edge AI: metadata -> Random Forest
                                        ├── Firewall: nftables table inet ddos
                                        └── /tmp/live_metrics.json -> Streamlit Web
```

| Thành phần | Vai trò |
|---|---|
| `Network/` | Dựng Mininet, OVS, VLAN, địa chỉ IP và Gateway. |
| `traffic/` | Sinh MQTT/camera traffic và ghi kết quả đo. `run_scenario.py` điều phối các lượt trong Mininet. |
| `qos/` | Phân loại gói bằng nftables marks; `qos.sh` cấu hình/kiểm tra HTB và FQ-CoDel. |
| `edge_ai/` | Trích đặc trưng header theo cửa sổ 1 giây, suy luận Random Forest và quản lý firewall riêng. |
| `Web/dashboard/` | Dashboard Streamlit; đây là thư mục Web chính được dùng trong hướng dẫn này. |
| `Web/experiments/` | Phân tích benchmark và cầu nối dashboard–Mininet (`scenario_daemon.py`). |
| `experiments/` | Các công cụ đo/chạy ma trận bổ sung. |
| `docs/` | Báo cáo, sơ đồ và biên bản kiểm thử. |
| `ket_qua_kiem_thu.zip` | CSV kết quả đã lưu từ máy ảo; dashboard đọc trực tiếp ZIP này nếu có. |

Mạng có 34 node, gồm 10 host cảm biến (`hs01`–`hs10`), 20 host camera
(`cam01`–`cam20`), Gateway `gw`, máy chủ `srv`, switch OVS `s1` và host lab `atk`.
Mỗi host `hs` đại diện cho 30 địa chỉ cảm biến logic của một tầng, tổng cộng 300
cảm biến; mỗi tầng có 2 camera. Đây là mô hình gom nhóm, không phải 300 host Mininet
độc lập.

| Node/interface | Địa chỉ hoặc chức năng |
|---|---|
| `gw-eth0.10` | Gateway VLAN cảm biến: `10.0.10.1/23` |
| `gw-eth0.20` | Gateway VLAN camera: `10.0.20.1/24` |
| `gw-eth0.30` | Gateway VLAN server: `10.0.30.1/24` |
| `gw-eth1` | Mạng ngoài mô phỏng: `192.168.100.1/24` |
| `srv` | MQTT/application server: `10.0.30.10/24` |
| `atk` | Host lab ngoài VLAN: `192.168.100.100/24` |
| `cam01`–`cam20` | Camera: `10.0.20.11`–`10.0.20.30` |
| `hs01`–`hs10` | Mỗi host có 30 IP cảm biến logic trên VLAN 10 |

Mỗi link Mininet mặc định 100 Mbps và 1 ms. `s1` nối server vào mạng VLAN nên
lưu lượng đến server đi qua Gateway; đây cũng là nút cổ chai cần lưu ý khi đọc
RTT/thông lượng. Chi tiết cấu hình tham số nằm trong [Network/config.py](Network/config.py)
và tài liệu/báo cáo trong [docs/bao_cao/](docs/bao_cao/).

| Mạng | Vai trò | Dải địa chỉ |
|---|---|---|
| VLAN 10 | Cảm biến | `10.0.10.0/23` |
| VLAN 20 | Camera | `10.0.20.0/24` |
| VLAN 30 | Server | `10.0.30.0/24` |
| Mạng ngoài mô phỏng | Gateway/host lab | `192.168.100.0/24` |

## 3. Môi trường cần dùng

Mininet, Open vSwitch, raw packet capture và nftables cần Linux. Môi trường Ubuntu
được ghi nhận trong biên bản là Ubuntu 26.04.1 LTS, Mininet 2.3.0, Open vSwitch
3.7.1 và iperf3 3.20. Chạy riêng Streamlit trên Windows chỉ phù hợp xem dữ liệu
đã lưu; để đọc trực tiếp `/tmp/live_metrics.json`, Web và Edge AI cần cùng VM hoặc
có một file được chia sẻ.

Cài công cụ hệ thống trên Ubuntu:

```bash
sudo apt update
sudo apt install -y git mininet openvswitch-switch iproute2 iperf3 \
  mosquitto nftables tcpdump tshark python3-venv python3-openpyxl \
  python3-scapy python3-paho-mqtt python3-sklearn
```

`hping3` chỉ cần cho một số bài kiểm thử traffic trong lab cô lập; không cần để
chạy topology, Web hay dashboard với dữ liệu đã lưu.

Nếu cần môi trường Python riêng cho dashboard và các script:

```bash
cd <REPO>
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
pip install -r requirements.txt -r Web/dashboard/requirements.txt
```

Không dùng `sudo pip install` trực tiếp vào Python hệ thống Ubuntu. Nếu topology
cần chạy bằng Python trong virtualenv, gọi interpreter đó bằng quyền root, ví dụ:
`sudo .venv/bin/python Network/topology.py`.

Hai cách cài trên là lựa chọn môi trường: cài Python package qua `apt` để dùng với
`sudo python3`, hoặc tạo `.venv` để cài bằng `pip`. Tránh trộn package giữa hai
môi trường mà không kiểm tra interpreter được gọi khi chạy dưới `sudo`.

## 4. Khởi động mạng và kiểm tra cơ bản

Trong terminal Ubuntu:

```bash
cd <REPO>/Network
sudo systemctl start openvswitch-switch
sudo modprobe 8021q
sudo mn -c
sudo python3 topology.py --check-env
sudo python3 topology.py --test --no-cli
sudo python3 topology.py
```

`--test --no-cli` dựng mạng, chạy kiểm tra ping/OVS rồi thoát; lệnh cuối mở CLI
Mininet (`mininet>`). Tùy chọn hữu ích khác:

| Tùy chọn | Tác dụng |
|---|---|
| `--test` | Chạy kiểm tra topology rồi giữ CLI mở |
| `--no-cli` | Thoát sau khi dựng/kiểm tra |
| `--bw 200` | Đổi băng thông link mặc định sang 200 Mbps |
| `--delay 2ms` | Đổi độ trễ link mặc định sang 2 ms |
| `--check-plan <file.xlsx>` | Đối chiếu quy hoạch IP với Excel, không dựng Mininet |
| `--reset` | Dọn trạng thái Mininet trước khi dựng, cần root |

Không chạy `mn -c` khi topology đang hoạt động. Thoát CLI bằng `exit`. Nếu OVS chưa
sẵn sàng, khởi động `openvswitch-switch`; nếu sub-interface VLAN không tạo được,
kiểm tra module `8021q`.

Một số kiểm tra không gây tải đáng kể:

```text
mininet> nodes
mininet> links
mininet> gw ip -br addr
mininet> gw ip route
mininet> gw sysctl -n net.ipv4.ip_forward
mininet> gw bash <REPO>/qos/qos.sh check
```

`--check-env` kiểm tra Mininet/Open vSwitch; `--test` kiểm tra kết nối topology.
Biên bản chi tiết và ảnh nằm tại [docs/KET_QUA_TEST.md](docs/KET_QUA_TEST.md).

### Chạy một lượt traffic bình thường

Topology không tự bật broker MQTT. Cách tiện nhất để kiểm tra các thành phần traffic
bình thường là gọi `run_scenario` từ CLI Mininet; hàm này tự khởi động/dọn broker
và iperf3 server trong namespace `srv`, đồng thời chạy lưu lượng cảm biến/camera và
đo RTT:

```text
mininet> py __import__('sys').path.insert(0, '..')
mininet> py __import__('traffic.run_scenario', fromlist=['run_scenario']).run_scenario(net, scenario='normal', duration=60)
```

Kết thúc lượt, kiểm tra thư mục `traffic/results/` và các tiến trình nếu có lỗi.
Lượt bình thường không bật QoS; QoS được áp dụng riêng bởi module `qos/` hoặc luồng
kịch bản tương ứng. Tham khảo [traffic/README.md](traffic/README.md).

## 5. Kết nối Edge AI với Web

Dashboard và detector trao đổi qua file JSON, mặc định là
`/tmp/live_metrics.json`. Node Mininet dùng network namespace nhưng cùng filesystem
với Ubuntu host; do đó Streamlit chạy trong cùng VM có thể đọc file do `gw` ghi.

### 5.1 Chạy dashboard

Trong một terminal Ubuntu khác, tại thư mục gốc repo:

```bash
cd <REPO>
streamlit run Web/dashboard/dashboard.py
```

Mở `http://localhost:8501` trong trình duyệt của VM. Dashboard tự đọc
`ket_qua_kiem_thu.zip` ở thư mục gốc nếu file tồn tại. Có thể đổi đường dẫn ZIP
trong sidebar. Mặc định Streamlit chỉ phục vụ trên máy local của VM; không mở cổng
ra mạng ngoài nếu chưa cấu hình kiểm soát truy cập phù hợp.

### 5.2 Chạy detector trên Gateway

Trước tiên dừng `simulate_live_metrics.py` nếu đang chạy; simulator và detector
không được cùng ghi một file live. Tại CLI Mininet, dùng đường dẫn tuyệt đối đến repo:

```text
mininet> gw python3 <REPO>/edge_ai/gateway_detector.py --iface gw-eth0 gw-eth1 --state-file /tmp/live_metrics.json --firewall nftables &
```

Detector đọc model trong `edge_ai/models/` theo mặc định. File live chứa trạng thái
AI, xác suất, đặc trưng packet/SYN/UDP và thông tin firewall. Dashboard nhận cả
schema live cũ và schema Edge AI.

Kiểm tra nội dung file từ Ubuntu host:

```bash
cat /tmp/live_metrics.json
```

Kỳ vọng bản ghi có `source: "edge_ai"`, `timestamp`, `status`, `prob_attack`,
`features` và `firewall`. Kiểm tra trong dashboard:

1. Banner mô phỏng không xuất hiện và trạng thái live không bị báo cũ.
2. Số packet/SYN/UDP và xác suất AI được cập nhật theo thời gian.
3. Trạng thái firewall hiển thị backend/lỗi nếu detector có gửi các trường đó.
4. RTT có thể vẫn là `—`; detector hiện không tự đo RTT.

Nếu thấy banner **DỮ LIỆU MÔ PHỎNG**, dashboard đang đọc simulator chứ không phải
detector. Nếu không có dữ liệu, kiểm tra detector còn chạy, đường dẫn file có trùng
với ô sidebar hay không và xem lỗi khởi động/model. Không chạy simulator đồng thời
với detector vì cả hai có thể ghi đè cùng file.

**Lưu ý:** Edge AI hiện không đo RTT; dashboard để RTT là `—` khi nguồn live không
cung cấp trường này. RTT từ lượt benchmark được ghi riêng trong kết quả scenario.

## 6. QoS, firewall và điều khiển kịch bản

- QoS được cấu hình bởi `qos/marks.nft` và `qos/qos.sh`. Các lệnh `start`, `check`,
  `show`, `stop` chạy trong namespace Gateway; `show` cho xem bộ đếm lớp HTB.
- QoS gắn mark ở prerouting rồi áp dụng HTB/FQ-CoDel trên đường ra server (`gw-eth0.30`):

  | Nhóm traffic | Mark | Class | Tốc độ đảm bảo |
  |---|---:|---|---:|
  | Báo cháy (DSCP 48) | `0x10` | `1:10` | 10 Mbit/s |
  | Telemetry cảm biến | `0x11` | `1:11` | 5 Mbit/s |
  | Camera | `0x12` | `1:12` | 60 Mbit/s |
  | Mặc định/không tin cậy | `0x13` | `1:13` | 1 Mbit/s |

  Tốc độ đảm bảo cộng thành 76 Mbit/s trong tổng 100 Mbit/s; class có thể mượn
  phần dung lượng chưa dùng. QoS phân phối/giới hạn hàng đợi, **không đồng nghĩa
  với phát hiện hoặc chặn toàn bộ traffic tấn công**.
- Edge AI quản lý bảng firewall riêng `inet ddos`; QoS dùng bảng `inet qos`.
  Không dùng `nft flush ruleset`, vì có thể xóa cả cấu hình không thuộc module đang
  kiểm tra.
- `traffic/run_scenario.py` và `Web/experiments/scenario_daemon.py` nối các lượt
  đo với dashboard. Daemon trao đổi bằng `/tmp/scenario_cmd.json` và
  `/tmp/scenario_status.json`; nút kịch bản bị khóa khi daemon chưa hoạt động.
- Các nút điều khiển có thể khởi chạy traffic test trong Mininet. Chỉ sử dụng trong
  mạng lab cô lập, có quyền kiểm soát; không trỏ traffic test ra mạng/thiết bị bên
  ngoài.

## 7. Dữ liệu, huấn luyện và đánh giá Edge AI

Luồng xử lý dữ liệu:

```text
PCAP hoặc capture tại Gateway
        -> collect_metadata.py
        -> build_dataset.py + nhật ký sự kiện
        -> train_model.py
        -> gateway_detector.py
```

Đặc trưng lõi là `packet_rate`, `byte_rate`, `syn_count`, `ip_dispersion`; đặc
trưng mở rộng gồm `src_entropy`, `udp_ratio`, `avg_pkt_len`. Dữ liệu sinh bởi
`synth_data.py` phù hợp kiểm tra pipeline, nhưng không thay thế dữ liệu Mininet
thực tế cho báo cáo nghiệm thu. Xem các tham số/đầu ra chi tiết trong
[edge_ai/README.md](edge_ai/README.md).

### Ý nghĩa từng bước

1. `collect_metadata.py` đọc PCAP hoặc bắt ingress tại Gateway; mỗi dòng CSV là
   một cửa sổ 1 giây. Chỉ đọc header metadata, không phân tích payload.
2. `build_dataset.py` ghép thời gian cửa sổ với nhật ký sự kiện; các cửa sổ chỉ
   giao một phần với ranh giới sự kiện bị bỏ để tránh nhãn không chắc chắn.
3. `train_model.py` so sánh RF-4/RF-7 với các mô hình cơ sở, chia tập theo `episode`
   để giảm rò rỉ giữa các cửa sổ thời gian liên tiếp.
4. `gateway_detector.py` đọc model, suy luận định kỳ, làm mượt trạng thái rồi ghi
   JSON cho dashboard. Firewall có whitelist các dải thiết bị hợp lệ; không nên
   dùng model chưa đánh giá trên dữ liệu thật để kết luận hiệu năng.

Kết quả huấn luyện cần xem không chỉ accuracy mà cả precision, recall, F1, FPR,
confusion matrix và độ trễ suy luận. Giữ các lượt dùng để nghiệm thu ở ngoài tập
huấn luyện/validation.

## 8. File kết quả được tạo

Các lượt đo thường ghi vào `traffic/results/`:

| File | Nội dung |
|---|---|
| `scenario_metrics.csv` | Kịch bản, trạng thái QoS, RTT trung bình/P95/P99, mất gói và lỗi tiến trình |
| `camera_metrics.csv` | Thông lượng, jitter và packet loss của từng camera |
| `iperf_camXX.json` | Kết quả iperf3 thô để phân tích lại |
| `attack_events.csv` | Mốc thời gian sự kiện; dùng đối chiếu dữ liệu và tạo nhãn |
| `mqtt_*.log`, `cam*.log`, `ping_*.txt` | Log tiến trình của lượt đo |

Dashboard cũng đọc 4 CSV trong ZIP kết quả VM: `scenario_metrics.csv`,
`camera_metrics.csv`, `attack_events.csv` và `run_matrix_manifest.csv`. Bảng giữ
cả các dòng lỗi; cần kiểm tra cột `error` trong manifest thay vì chỉ dựa trên số
lượt thành công.

## 9. Kiểm thử và bằng chứng hiện có

Các lệnh kiểm thử mã Python:

```bash
python edge_ai/tests/test_collector.py
python Web/dashboard/tests/test_dashboard_logic.py
python Web/experiments/tests/test_benchmark_analyze.py
```

Theo kết quả được kiểm tra khi lập tài liệu:

- Biên bản topology ghi 9 mục đạt, 1 mục không áp dụng, không ghi mục thất bại.
- ZIP kiểm thử có 16 dòng `scenario_metrics`, 554 mẫu camera, 36 sự kiện và 22 lượt
  trong manifest; trong đó 13 lượt `ok`, 9 lượt `error`. Xem lỗi từng lượt trong
  `run_matrix_manifest.csv` bên trong [ZIP kết quả](ket_qua_kiem_thu.zip).
- Dashboard logic đạt 12/12 test; benchmark analysis đạt 4/4 test trên môi trường
  Python đã kiểm tra.
- Video dashboard đã chia sẻ có banner **DỮ LIỆU MÔ PHỎNG** và daemon chưa chạy.
  Video xác nhận giao diện hoạt động với simulator, không phải bằng chứng detector
  Edge AI live đã hoạt động trên VM.

Không diễn giải 13 lượt thành công là toàn bộ ma trận đạt; cần xem và xử lý 9 dòng
lỗi trước khi chốt báo cáo.

## 10. Giới hạn và xử lý sự cố

| Hiện tượng | Hướng kiểm tra |
|---|---|
| Dashboard báo chưa có live JSON | Dừng simulator; kiểm tra detector trong `gw`, đường dẫn `/tmp/live_metrics.json` và lỗi model. |
| Dashboard vẫn báo dữ liệu mô phỏng | Tìm tiến trình simulator còn chạy; chỉ để một tiến trình ghi file live. |
| Xác suất/trạng thái không hiện | Đồng bộ phiên bản `gateway_detector.py`, `dashboard_logic.py` và Web sang cùng VM; xem cấu trúc JSON. |
| RTT hiện `—` | Detector không phát RTT; dùng số đo scenario/benchmark hoặc bổ sung nguồn RTT riêng. |
| Nút kịch bản bị khóa | Daemon chưa gửi heartbeat; đây là phần điều khiển riêng với luồng Edge AI live. |
| QoS không qua `check` | Xem `qos.sh show`, kiểm tra interface `gw-eth0.30`, `tc` và bảng `inet qos`. |
| Model không nạp được | Kiểm tra model file và phiên bản `scikit-learn` trong môi trường tạo model so với VM chạy detector. |

Topology Mininet chạy trong môi trường ảo hóa nên RTT/throughput có thể thay đổi
theo tải máy chủ. Mọi kết quả chính thức cần ghi lại phiên bản môi trường, cấu hình
QoS, trạng thái Edge AI và nguồn dữ liệu (thực hay mô phỏng).
