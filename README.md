# Hệ thống cảnh báo cháy thông minh – mô phỏng Mininet

Đề tài: Thiết kế và triển khai cơ chế kết hợp QoS và Edge AI nhằm phòng chống tấn công DDoS tại Gateway cho hệ thống cảnh báo cháy thông minh.

Repo này chứa toàn bộ mã nguồn và tài liệu của nhóm. Mạng ảo (Tổ 2) dựng bằng Mininet theo sơ đồ `docs/so_do/so_do_4_tang_v4.drawio` và quy hoạch IP `docs/quy_hoach_IP_VLAN_v2.xlsx`. Mạng này là nền để Tổ 3 chạy lưu lượng bình thường và tấn công, rồi cả nhóm làm QoS, Edge AI và tường lửa tại Gateway.

**Môi trường đã kiểm thử:** Ubuntu 26.04.1 LTS, Mininet 2.3.0, Open vSwitch 3.7.1, iperf3 3.20.

## 1. Cấu trúc repo

```
HeThongBaoChay_Mininet/
├── README.md              # file này
├── requirements.txt
├── .gitignore
├── Network/               # Tổ 2: dựng mạng ảo (7 file Python)
├── traffic/               # Tổ 3: sinh lưu lượng bình thường và tấn công
├── qos/                   # QoS (HTB), script đo RTT/mất gói
├── firewall/              # nftables, script thêm/gỡ luật
├── edge_ai/               # trích đặc trưng, huấn luyện, detector
├── experiments/           # chạy 3 kịch bản, kết quả CSV (experiments/results/)
└── docs/
    ├── quy_hoach_IP_VLAN_v2.xlsx
    ├── so_do/             # sơ đồ .drawio và ảnh
    ├── bao_cao/           # báo cáo, slide
    └── test/              # KET_QUA_TEST.md và screenshots/
```

Mỗi thư mục (trừ `Network/` và `docs/`) có `README.md` riêng ghi: script nào làm gì, cách chạy, đầu vào, đầu ra, người phụ trách.

## 2. Mạng gồm những gì

| Nút | Số lượng | Vai trò | IP | VLAN |
|---|---|---|---|---|
| `hs01` … `hs10` | 10 | Mỗi host đại diện 30 cảm biến của một tầng (1 IP chính, 29 IP phụ) | 10.0.10.0/23 (tầng 1: .33–.62, tầng 2: .65–.94, …) | 10 |
| `cam01` … `cam20` | 20 | Camera, 2 camera mỗi tầng | 10.0.20.11 … 10.0.20.30 (/24) | 20 |
| `srv` | 1 | Máy chủ (MQTT broker, dashboard) | 10.0.30.10/24 | 30 |
| `gw` | 1 | Edge Gateway, định tuyến liên VLAN | 10.0.10.1/23, 10.0.20.1/24, 10.0.30.1/24 (`gw-eth0.10/.20/.30`); 192.168.100.1/24 (`gw-eth1`) | trunk 10,20,30 |
| `atk` | 1 | Kẻ tấn công ở mạng ngoài | 192.168.100.100/24 | không |
| `s1` | 1 | Switch Open vSwitch | không cần IP | cổng truy cập gắn tag, cổng lên `gw` là trunk |

Tổng cộng 34 nút và 33 liên kết. Mọi liên kết: 100 Mbps, trễ 1 ms (sửa trong `Network/config.py`). Máy chủ nối vào OVS (không nối thẳng Gateway), nên lưu lượng tới `srv` đi qua trunk Gateway–OVS hai lần (router-on-a-stick). Đoạn Gateway → OVS là nút cổ chai; lưu lượng tấn công từ `atk` cũng đi qua `gw` rồi qua cùng nút cổ chai này.

## 3. Các file trong `Network/`

| File | Nội dung | Sửa khi |
|---|---|---|
| `topology.py` | Điểm vào duy nhất, đọc tùy chọn dòng lệnh | Thêm tùy chọn chạy |
| `config.py` | Tham số: số tầng, băng thông, độ trễ, VLAN, IP Gateway | Đổi số liệu |
| `ip_plan.py` | Sinh IP cảm biến, camera; đối chiếu Excel | Đổi quy hoạch IP |
| `nodes.py` | Lớp `LinuxRouter` (Gateway bật `ip_forward`) | Gateway cần thêm chức năng |
| `builder.py` | Dựng host, switch, liên kết | Đổi sơ đồ |
| `configure.py` | VLAN trên OVS, sub-interface Gateway, IP phụ, tùy chọn SYN | Lỗi VLAN, định tuyến, IP |
| `verify.py` | Ping kiểm tra tự động (Test 1, 1b, 2, 2b, 3, 3b, 5 và kiểm tra OVS ở Test 4) | Thêm phép thử |

Bảy file này phải nằm chung thư mục `Network/`. Chỉ Tổ 2 sửa các file này; nhóm khác cần đổi tham số mạng thì báo Tổ 2.

## 4. Yêu cầu và cài đặt

Máy ảo Ubuntu (đã thử trên 26.04.1 LTS; 4 vCPU, 4–8 GB RAM):

```
sudo apt update
sudo apt install -y git nano mininet openvswitch-switch tcpdump tshark iperf3 hping3 mosquitto nftables iproute2 python3-openpyxl
```

Thư viện Python cho giai đoạn sau (Tổ 3, Edge AI), cài bằng `apt` để dùng chung Python với `sudo python3`:

```
sudo apt install -y python3-scapy python3-paho-mqtt python3-sklearn
```

Không dùng `sudo pip3 install -r requirements.txt` trên Ubuntu đời mới vì thường báo `externally-managed-environment`. Nếu cần môi trường ảo: `python3 -m venv --system-site-packages venv`, và khi chạy phải gọi `sudo venv/bin/python Network/topology.py`.

Kiểm tra: `mn --version` hiện số phiên bản, hoặc `sudo python3 Network/topology.py --check-env` hiện `Environment OK`.

## 5. Cách chạy mạng ảo

Chạy trong thư mục `Network/`:

```
cd Network
sudo mn -c                       # dọn lần chạy trước (nên chạy trước mỗi lần)
sudo python3 topology.py         # dựng mạng, vào dấu nhắc mininet>
sudo python3 topology.py --test  # tự ping kiểm tra, in bảng kết quả, rồi vào mininet>
```

| Tùy chọn | Tác dụng |
|---|---|
| `--test` | Chạy bộ kiểm tra tự động sau khi dựng mạng |
| `--no-cli` | Không vào dấu nhắc `mininet>`, thoát sau khi chạy xong |
| `--no-syncookies` | Tắt SYN cookies trên `srv` (dùng khi thử SYN Flood) |
| `--bw 200` | Đổi băng thông mỗi liên kết (Mbps) |
| `--delay 2ms` | Đổi độ trễ mỗi liên kết |
| `--check-plan file.xlsx` | Đối chiếu IP với file Excel rồi thoát (không cần Mininet, không cần root) |
| `--check-env` | Kiểm tra môi trường Mininet/Open vSwitch rồi thoát |
| `--reset` | Chạy `mn -c` dọn trạng thái cũ trước khi dựng mạng (cần root) |

Đối chiếu IP với Excel (từ thư mục `Network/`):

```
python3 topology.py --check-plan ../docs/quy_hoach_IP_VLAN_v2.xlsx
```

Thoát Mininet: gõ `exit` tại `mininet>`. Không chạy `mn -c` khi mạng đang hoạt động.

## 6. Nghiệm thu

Cách nhanh: `sudo python3 topology.py --test --no-cli 2>&1 | tee ket_qua_test.txt`, kết luận mong đợi `TAT CA DAT`. Biên bản kiểm thử chi tiết (kèm ảnh) nằm ở `docs/test/KET_QUA_TEST.md`.

Gõ tay tại `mininet>`:

| Test | Lệnh | Kỳ vọng |
|---|---|---|
| 1. Cảm biến | `hs01 ping -c 3 srv` | 0% packet loss |
| 2. Camera | `cam01 ping -c 3 10.0.20.1` | 0% packet loss |
| 3. Kẻ tấn công | `atk ping -c 3 192.168.100.1` | 0% packet loss |
| 4. OVS | `sh ovs-vsctl show` | Cổng cảm biến, camera, máy chủ có tag 10, 20, 30; `s1-gw` trunk 10, 20, 30 |

Tên host là `hs01`, `cam01` (có số 0). Lệnh hữu ích khi gỡ lỗi: `gw ip -br addr`, `gw ip route`, `gw sysctl -n net.ipv4.ip_forward` (phải bằng 1), `hs01 ip -4 addr show hs01-eth0 | grep -c inet` (phải ra 30), `nodes`, `links`, `gw tc qdisc show dev gw-eth0`.

## 6b. Lỗi thường gặp

| Triệu chứng | Cách xử lý |
|---|---|
| `database connection failed` hoặc lỗi `ovs-vsctl` | `sudo systemctl start openvswitch-switch` |
| Lần chạy sau báo giao diện đã tồn tại | `sudo mn -c` |
| Không tạo được `gw-eth0.10` | `sudo modprobe 8021q` |
| Ping `atk` → `srv` không thông | `gw ip route` và `gw sysctl -n net.ipv4.ip_forward` (phải bằng 1) |
| `Can chay bang root` | Chạy bằng `sudo` |
| Báo thiếu Mininet | `sudo apt install mininet openvswitch-switch` |
| `externally-managed-environment` khi dùng `pip` | Dùng `apt install python3-...` như mục 4 |

## 7. Lưu ý cho các tổ làm tiếp

- Cổng MQTT là 1883 (8883 nếu bật TLS). `topology.py` chưa khởi động Mosquitto; Tổ 3 tự chạy trên `srv`.
- Mỗi client MQTT cảm biến nên gắn đúng IP bằng `bind_address`; danh sách IP lấy từ `Network/ip_plan.py` (`sensor_ips(tầng)`) hoặc sheet "Danh sách cảm biến".
- `TCLink` đã gắn sẵn hàng đợi `tc` (`htb` và `netem`) lên các giao diện. Trước khi dựng HTB riêng trên `gw-eth0`: `gw tc qdisc del dev gw-eth0 root` (nhớ tạo lại độ trễ 1 ms nếu muốn giữ). Kích thước hàng đợi mặc định có thể ảnh hưởng RTT khi bị tấn công; ghi lại cấu hình khi báo cáo số đo.
- Chiều lên (OVS → Gateway) cũng giới hạn 100 Mbps; nếu video gây nghẽn chiều này thì cần hàng đợi ở cổng `s1-gw`.
- Gateway đã tắt `rp_filter` nên tấn công giả mạo IP nguồn đi qua được; nftables cần tính đến việc IP nguồn không đáng tin.
- Bắt gói: không dùng `tshark -i any` ngoài mạng ảo vì một gói bị bắt nhiều lần. Bắt tại Gateway, chỉ chiều vào, tại `mininet>`:
  ```
  gw tcpdump -i gw-eth0 -Q in -nn -w /tmp/vao_eth0.pcap &
  gw tcpdump -i gw-eth1 -Q in -nn -w /tmp/vao_eth1.pcap &
  ```
  Dừng bằng `sh pkill tcpdump`. Điểm bắt gói cuối cùng do nhóm Edge AI quyết định.
- Ghi thời điểm bắt đầu và kết thúc mỗi đợt tấn công vào CSV để gán nhãn; không gán một nhãn cho cả file PCAP.
- Đặc trưng theo đề cương, cửa sổ 1 giây: packet rate, byte rate, SYN count, IP dispersion.
- **Import file của Tổ 2 từ thư mục khác** (ví dụ dùng `ip_plan` trong `traffic/` hoặc `edge_ai/`): thêm vào đầu file
  ```python
  import sys, os
  sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'network'))
  from ip_plan import sensor_ips
  ```
  Kiểm tra lại khi dùng.

## 8. Quy tắc làm việc nhóm

1. Mỗi người chỉ sửa trong thư mục của mình; `Network/` chỉ Tổ 2 sửa.
2. `git pull` trước khi `git push`; commit ngắn gọn, nói rõ đã đổi gì.
3. Tên file và thư mục không dấu, không khoảng trắng.
4. Không đưa lên GitHub: file `.pcap`, ID và mật khẩu máy ảo, thông tin nhạy cảm. CSV kết quả nhỏ đặt trong `experiments/results/`.
5. Mỗi người một máy ảo riêng; không chạy `sudo mn -c` trên máy người khác khi họ đang chạy.
6. Điền `README.md` của thư mục mình: script nào làm gì, cách chạy, đầu vào, đầu ra.

## 9. Hạn chế đã biết

- Cảm biến thật dùng Wi-Fi (ESP32), mô phỏng coi mạng truy cập là có dây theo VLAN.
- 300 cảm biến là 10 host × 30 IP dùng chung một giao diện và một hàng đợi; không mô phỏng riêng lẻ từng thiết bị.
- Tải bình thường khoảng 80% liên kết (20 camera × khoảng 4 Mbps; 4 Mbps là lựa chọn thiết kế của nhóm), nên sai khác nhỏ về băng thông có thể làm kết quả đo thay đổi.
- Ping trong `--test` chỉ xác nhận thông mạng, không thay thế phép đo RTT của Chương 2.
- Mạng chạy trong namespace của Mininet, không có NAT ra ngoài; không bật NAT cho `atk`.
