# Mạng ảo 4 tầng – Tổ 2

Đề tài: Thiết kế và triển khai cơ chế kết hợp QoS và Edge AI nhằm phòng chống tấn công DDoS tại Gateway cho hệ thống cảnh báo cháy thông minh.

Thư mục này dựng bằng Mininet mạng ảo theo sơ đồ `so_do_4_tang_chinh_sua.drawio` và quy hoạch IP `quy_hoach_IP_VLAN_v2.xlsx`. Mạng này là nền để Tổ 3 chạy lưu lượng bình thường và tấn công, rồi cả nhóm làm Edge AI, QoS.

## 1. Mạng gồm những gì

| Nút | Số lượng | Vai trò | IP | VLAN |
|---|---|---|---|---|
| `hs01` … `hs10` | 10 | Mỗi host đại diện 30 cảm biến của một tầng (1 IP chính, 29 IP phụ) | 10.0.10.0/23 (tầng 1: .33–.62, tầng 2: .65–.94, …) | 10 |
| `cam01` … `cam20` | 20 | Camera, 2 camera mỗi tầng | 10.0.20.11 … 10.0.20.30 (/24) | 20 |
| `srv` | 1 | Máy chủ (MQTT broker, dashboard) | 10.0.30.10/24 | 30 |
| `gw` | 1 | Edge Gateway, định tuyến liên VLAN | 10.0.10.1/23, 10.0.20.1/24, 10.0.30.1/24 (eth0.10/.20/.30); 192.168.100.1/24 (eth1) | trunk 10,20,30 |
| `atk` | 1 | Kẻ tấn công ở mạng ngoài | 192.168.100.100/24 | không |
| `s1` | 1 | Switch Open vSwitch | không cần IP | cổng truy cập gắn tag, cổng lên `gw` là trunk |

Mọi liên kết: 100 Mbps, trễ 1 ms (sửa trong `config.py`). Máy chủ nối vào OVS (không nối thẳng Gateway), nên lưu lượng tới `srv` đi qua trunk Gateway–OVS hai lần (router-on-a-stick). Đoạn Gateway → OVS là nút cổ chai.

## 2. Cấu trúc file

| File | Nội dung | Sửa khi |
|---|---|---|
| `topology.py` | Điểm vào duy nhất, đọc tùy chọn dòng lệnh | Thêm tùy chọn chạy |
| `config.py` | Tham số: số tầng, băng thông, độ trễ, VLAN, IP Gateway | Đổi số liệu |
| `ip_plan.py` | Sinh IP cảm biến, camera; đối chiếu Excel | Đổi quy hoạch IP |
| `nodes.py` | Lớp `LinuxRouter` (Gateway bật `ip_forward`) | Gateway cần thêm chức năng |
| `builder.py` | Dựng host, switch, liên kết | Đổi sơ đồ |
| `configure.py` | VLAN trên OVS, sub-interface Gateway, IP phụ, tùy chọn SYN | Lỗi VLAN, định tuyến, IP |
| `verify.py` | Ping kiểm tra tự động (Test 1–4) | Thêm phép thử |

Tất cả file phải nằm chung một thư mục.

## 3. Yêu cầu

Máy ảo Ubuntu 22.04 LTS (4 vCPU, 4–8 GB RAM) đã cài:

```
sudo apt update
sudo apt install -y git nano python3-pip mininet openvswitch-switch tshark iperf3 hping3 mosquitto nftables iproute2
sudo pip3 install -r requirements.txt
```

Kiểm tra: `mn --version` hiện số phiên bản. `openpyxl` chỉ cần cho tùy chọn `--check-plan`.

## 4. Cách chạy

Chạy trong thư mục chứa các file:

```
sudo mn -c                       # dọn lần chạy trước (nên chạy trước mỗi lần)
sudo python3 topology.py         # dựng mạng, vào dấu nhắc mininet>
sudo python3 topology.py --test  # tự ping kiểm tra, in bảng kết quả, rồi vào mininet>
```

Tùy chọn:

| Tùy chọn | Tác dụng |
|---|---|
| `--test` | Chạy bộ kiểm tra tự động sau khi dựng mạng |
| `--no-cli` | Không vào dấu nhắc `mininet>`, thoát sau khi chạy xong |
| `--no-syncookies` | Tắt SYN cookies trên `srv` (dùng khi thử SYN Flood) |
| `--bw 200` | Đổi băng thông mỗi liên kết (Mbps) |
| `--delay 2ms` | Đổi độ trễ mỗi liên kết |
| `--check-plan file.xlsx` | Đối chiếu IP với file Excel rồi thoát (không cần Mininet, không cần root) |
| `--check-env` | Kiểm tra môi trường Mininet/Open vSwitch trước khi chạy |
| `--reset` | Reset lại Open vSwitch / Mininet state trước khi build lại |

Để reset Mininet rồi dựng mạng lại trong cùng một lệnh:

```
sudo python3 topology.py --reset --test
```

Để tạo dữ liệu cho Edge AI, trước tiên capture lưu lượng trong môi trường Mininet được phép thử nghiệm, sau đó trích xuất đặc trưng từ PCAP:

```
sudo tshark -i any -w traffic.pcap
python3 traffic_features.py --pcap traffic.pcap --label normal --csv ai_features.csv
```

Chạy lại với `--label attack` cho PCAP của kịch bản tấn công tương ứng. CSV gồm thời điểm, IP/port, protocol, số packet, tổng byte, kích thước packet trung bình và nhãn. Chỉ gán nhãn đúng với kịch bản thực tế đã capture; script này phân tích PCAP có sẵn, không phát lưu lượng.

Thoát Mininet: gõ `exit` tại dấu nhắc `mininet>`.

## 5. Nghiệm thu (bằng chứng cho báo cáo)

Cách nhanh: `sudo python3 topology.py --test`, chụp bảng kết quả. Nếu muốn gõ tay tại dấu nhắc `mininet>`:

| Test | Lệnh | Kỳ vọng |
|---|---|---|
| 1. Cảm biến | `hs01 ping -c 3 srv` | 0% packet loss |
| 2. Camera | `cam01 ping -c 3 10.0.20.1` | 0% packet loss |
| 3. Kẻ tấn công | `atk ping -c 3 192.168.100.1` | 0% packet loss |
| 4. OVS | `sh ovs-vsctl show` | Cổng cảm biến, camera, máy chủ có đúng tag 10, 20, 30; cổng `s1-gw` có trunk 10, 20, 30 |

Lưu ý: tên host là `hs01`, `cam01` (có số 0), không phải `hs1`.

Lệnh hữu ích khi gỡ lỗi:

```
gw ip addr                 # xem các giao diện eth0.10, eth0.20, eth0.30, eth1
gw ip route                # xem bảng định tuyến
gw sysctl net.ipv4.ip_forward   # phải bằng 1
hs01 ip addr show hs01-eth0     # phải thấy 30 IP
nodes                      # liệt kê nút
links                      # liệt kê liên kết
```

Soi gói tin có tag VLAN: `gw tcpdump -i gw-eth0 -c 10 -e vlan` (mở trong terminal thứ hai nếu cần).

## 6. Lỗi thường gặp

| Triệu chứng | Cách xử lý |
|---|---|
| `database connection failed` hoặc lỗi `ovs-vsctl` | `sudo systemctl start openvswitch-switch` |
| Lần chạy sau báo giao diện đã tồn tại | `sudo mn -c` |
| Không tạo được `gw-eth0.10` | `sudo modprobe 8021q` |
| Ping `atk` → `srv` không thông | `gw ip route` và `gw sysctl net.ipv4.ip_forward` (phải bằng 1) |
| `Can chay bang root` | Chạy bằng `sudo` |
| Báo thiếu Mininet | `sudo apt install mininet openvswitch-switch` |

## 7. Lưu ý cho Tổ 3 và người làm QoS

- Cổng MQTT là 1883 (8883 nếu bật TLS). Chưa khởi động Mosquitto trong `topology.py`, Tổ 3 tự chạy trên `srv`.
- Cảm biến mô phỏng: mỗi client MQTT nên gắn đúng IP cảm biến bằng `bind_address`; danh sách IP phụ nằm trong `ip_plan.sensor_ips(tầng)` hoặc sheet "Danh sách cảm biến".
- Mininet (`TCLink`) đã gắn sẵn hàng đợi `tc` lên các giao diện. Muốn dựng HTB riêng trên `gw-eth0`, phải xóa cấu hình cũ trước: `gw tc qdisc del dev gw-eth0 root`, rồi tự tạo HTB (nhớ tính lại độ trễ 1 ms nếu muốn giữ).
- Chiều lên (OVS → Gateway) cũng có giới hạn 100 Mbps; nếu video gây nghẽn chiều này thì cần hàng đợi ở cổng `s1-gw`.
- Tấn công giả mạo IP nguồn: Gateway đã tắt `rp_filter`, nhưng người dựng tường lửa (nftables) cần tính đến việc IP nguồn không đáng tin.
- Ghi lại thời điểm bắt đầu và kết thúc mỗi đợt tấn công vào tệp CSV để gán nhãn dữ liệu cho Edge AI.

## 8. Hạn chế đã biết

- Cảm biến thật dùng Wi-Fi (ESP32), mô phỏng coi mạng truy cập là có dây theo VLAN.
- Mỗi host cảm biến dùng chung một giao diện và một hàng đợi cho 30 IP; đủ để tạo tải, nhưng không mô phỏng riêng lẻ từng thiết bị.
- Tải bình thường đã khoảng 80% liên kết (20 camera × 4 Mbps), vì vậy sai khác nhỏ về băng thông có thể làm kết quả đo thay đổi.
