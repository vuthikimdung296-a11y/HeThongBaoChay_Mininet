# Mạng ảo 4 tầng – Tổ 2

Đề tài: Thiết kế và triển khai cơ chế kết hợp QoS và Edge AI nhằm phòng chống tấn công DDoS tại Gateway cho hệ thống cảnh báo cháy thông minh.

Thư mục này dựng bằng Mininet mạng ảo theo sơ đồ `so_do_4_tang_chinh_sua.drawio` và quy hoạch IP `quy_hoach_IP_VLAN_v2.xlsx`. Mạng này là nền để Tổ 3 chạy lưu lượng bình thường và tấn công, rồi cả nhóm làm Edge AI, QoS.

**Môi trường đã kiểm thử:** Ubuntu 26.04.1 LTS, Mininet 2.3.0, Open vSwitch 3.7.1, iperf3 3.20. Kết quả kiểm thử chi tiết (kèm ảnh) nằm trong `KET_QUA_TEST.md`.

## 1. Mạng gồm những gì

| Nút | Số lượng | Vai trò | IP | VLAN |
|---|---|---|---|---|
| `hs01` … `hs10` | 10 | Mỗi host đại diện 30 cảm biến của một tầng (1 IP chính, 29 IP phụ) | 10.0.10.0/23 (tầng 1: .33–.62, tầng 2: .65–.94, …) | 10 |
| `cam01` … `cam20` | 20 | Camera, 2 camera mỗi tầng | 10.0.20.11 … 10.0.20.30 (/24) | 20 |
| `srv` | 1 | Máy chủ (MQTT broker, dashboard) | 10.0.30.10/24 | 30 |
| `gw` | 1 | Edge Gateway, định tuyến liên VLAN | 10.0.10.1/23, 10.0.20.1/24, 10.0.30.1/24 (`gw-eth0.10/.20/.30`); 192.168.100.1/24 (`gw-eth1`) | trunk 10,20,30 |
| `atk` | 1 | Kẻ tấn công ở mạng ngoài | 192.168.100.100/24 | không |
| `s1` | 1 | Switch Open vSwitch | không cần IP | cổng truy cập gắn tag, cổng lên `gw` là trunk |

Tổng cộng 34 nút (33 host + 1 switch) và 33 liên kết.

Mọi liên kết: 100 Mbps, trễ 1 ms (sửa trong `config.py`). Máy chủ nối vào OVS (không nối thẳng Gateway), nên lưu lượng tới `srv` đi qua trunk Gateway–OVS hai lần (router-on-a-stick). Đoạn Gateway → OVS là nút cổ chai. Lưu lượng tấn công từ `atk` cũng đi qua `gw` rồi qua cùng nút cổ chai này.

## 2. Cấu trúc file

| File | Nội dung | Sửa khi |
|---|---|---|
| `topology.py` | Điểm vào duy nhất, đọc tùy chọn dòng lệnh | Thêm tùy chọn chạy |
| `config.py` | Tham số: số tầng, băng thông, độ trễ, VLAN, IP Gateway | Đổi số liệu |
| `ip_plan.py` | Sinh IP cảm biến, camera; đối chiếu Excel | Đổi quy hoạch IP |
| `nodes.py` | Lớp `LinuxRouter` (Gateway bật `ip_forward`) | Gateway cần thêm chức năng |
| `builder.py` | Dựng host, switch, liên kết | Đổi sơ đồ |
| `configure.py` | VLAN trên OVS, sub-interface Gateway, IP phụ, tùy chọn SYN | Lỗi VLAN, định tuyến, IP |
| `verify.py` | Ping kiểm tra tự động (Test 1, 1b, 2, 2b, 3, 3b, 5 và kiểm tra OVS ở Test 4) | Thêm phép thử |
| `requirements.txt` | Danh sách thư viện Python (tham khảo; cách cài khuyến nghị ở mục 3) | Thêm thư viện |
| `KET_QUA_TEST.md` | Biên bản kiểm thử kèm ảnh minh chứng | Sau mỗi lần kiểm thử |

Tất cả file `.py` phải nằm chung một thư mục.

## 3. Yêu cầu và cài đặt

Máy ảo Ubuntu (đã thử trên 26.04.1 LTS; 4 vCPU, 4–8 GB RAM) cần cài:

```
sudo apt update
sudo apt install -y git nano mininet openvswitch-switch tcpdump tshark iperf3 hping3 mosquitto nftables iproute2 python3-openpyxl
```

Các thư viện Python cho giai đoạn sau (Tổ 3, nhóm Edge AI) nên cài bằng `apt` để dùng chung Python của hệ thống với `sudo python3`:

```
sudo apt install -y python3-scapy python3-paho-mqtt python3-sklearn
```

Không dùng `sudo pip3 install -r requirements.txt` trên Ubuntu đời mới: lệnh này thường báo lỗi `externally-managed-environment`. Nếu bắt buộc dùng môi trường ảo, tạo bằng `python3 -m venv --system-site-packages venv`, và khi chạy phải gọi `sudo venv/bin/python topology.py` (nếu gọi `sudo python3` sẽ không thấy thư viện trong venv).

Phần Tổ 2 chỉ cần `python3-openpyxl` (cho tùy chọn `--check-plan`); các thư viện còn lại dành cho giai đoạn sau.

Kiểm tra: `mn --version` hiện số phiên bản; hoặc chạy `sudo python3 topology.py --check-env`, kết quả mong đợi là `Environment OK`.

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
| `--check-env` | Kiểm tra môi trường Mininet/Open vSwitch rồi thoát |
| `--reset` | Chạy `mn -c` dọn trạng thái cũ trước khi dựng mạng (cần root) |

Ví dụ dọn và dựng lại trong một lệnh:

```
sudo python3 topology.py --reset --test
```

Đối chiếu IP với Excel (không cần root):

```
python3 topology.py --check-plan quy_hoach_IP_VLAN_v2.xlsx
```

Kết quả mong đợi: đối chiếu 300 cảm biến và 20 camera, 0 lệch.

Thoát Mininet: gõ `exit` tại dấu nhắc `mininet>`. Không chạy `mn -c` khi mạng đang hoạt động.

## 5. Nghiệm thu (bằng chứng cho báo cáo)

Cách nhanh: `sudo python3 topology.py --test --no-cli 2>&1 | tee ket_qua_test.txt`, rồi chụp bảng kết quả. Dòng kết luận mong đợi: `TAT CA DAT`. Nếu có dòng `KHONG DAT`, giữ nguyên kết quả để xử lý, không ghi là đạt.

Bộ kiểm tra tự động gồm: Test 1 và 1b (cảm biến → `srv`, kể cả IP phụ cuối của `hs10`), Test 2 và 2b (camera), Test 3 và 3b (`atk` → gateway, `atk` → `srv`), Test 5 (`srv` → gateway), ping từ cả 30 host tới `srv`, và Test 4 (tag access và trunk trên OVS).

Nếu muốn gõ tay tại dấu nhắc `mininet>`:

| Test | Lệnh | Kỳ vọng |
|---|---|---|
| 1. Cảm biến | `hs01 ping -c 3 srv` | 0% packet loss |
| 2. Camera | `cam01 ping -c 3 10.0.20.1` | 0% packet loss |
| 3. Kẻ tấn công | `atk ping -c 3 192.168.100.1` | 0% packet loss |
| 4. OVS | `sh ovs-vsctl show` | Cổng cảm biến, camera, máy chủ có đúng tag 10, 20, 30; cổng `s1-gw` có trunk 10, 20, 30 |

Lưu ý: tên host là `hs01`, `cam01` (có số 0), không phải `hs1`.

Lệnh hữu ích khi gỡ lỗi:

```
gw ip -br addr                  # các giao diện gw-eth0.10, gw-eth0.20, gw-eth0.30, gw-eth1
gw ip route                     # bảng định tuyến
gw sysctl net.ipv4.ip_forward   # phải bằng 1
hs01 ip -4 addr show hs01-eth0 | grep -c inet   # phải ra 30
nodes                           # liệt kê nút (34)
links                           # liệt kê liên kết (33)
gw tc qdisc show dev gw-eth0    # xem hàng đợi hiện có
```

Soi gói tin có tag VLAN (chạy tại `mininet>`):

```
gw timeout 5 tcpdump -i gw-eth0 -e -n vlan -c 10 > /tmp/vlan.txt 2>&1 &
hs01 ping -c 3 srv
sh cat /tmp/vlan.txt
```

Chỉ dùng kết quả này để chứng minh gói có VLAN tag (ví dụ VLAN 10 và VLAN 30), không dùng để đếm tổng số gói.

## 6. Lỗi thường gặp

| Triệu chứng | Cách xử lý |
|---|---|
| `database connection failed` hoặc lỗi `ovs-vsctl` | `sudo systemctl start openvswitch-switch` |
| Lần chạy sau báo giao diện đã tồn tại | `sudo mn -c` |
| Không tạo được `gw-eth0.10` | `sudo modprobe 8021q` |
| Ping `atk` → `srv` không thông | `gw ip route` và `gw sysctl net.ipv4.ip_forward` (phải bằng 1) |
| `Can chay bang root` | Chạy bằng `sudo` |
| Báo thiếu Mininet | `sudo apt install mininet openvswitch-switch` |
| `externally-managed-environment` khi dùng `pip` | Dùng `apt install python3-...` như mục 3 |

## 7. Lưu ý cho Tổ 3 và người làm QoS

- Cổng MQTT là 1883 (8883 nếu bật TLS). `topology.py` chưa khởi động Mosquitto; Tổ 3 tự chạy trên `srv`.
- Cảm biến mô phỏng: mỗi client MQTT nên gắn đúng IP cảm biến bằng `bind_address`; danh sách IP nằm trong `ip_plan.sensor_ips(tầng)` hoặc sheet "Danh sách cảm biến".
- Mininet (`TCLink`) đã gắn sẵn hàng đợi `tc` (`htb` và `netem`) lên các giao diện. Muốn dựng HTB riêng trên `gw-eth0`, phải xóa cấu hình cũ trước: `gw tc qdisc del dev gw-eth0 root`, rồi tự tạo HTB (nhớ tính lại độ trễ 1 ms nếu muốn giữ).
- Kích thước hàng đợi mặc định của `TCLink` có thể ảnh hưởng RTT khi mạng bị tấn công; cần ghi lại cấu hình này khi báo cáo số đo.
- Chiều lên (OVS → Gateway) cũng giới hạn 100 Mbps; nếu video gây nghẽn chiều này thì cần hàng đợi ở cổng `s1-gw`.
- Tấn công giả mạo IP nguồn: Gateway đã tắt `rp_filter`, nên người dựng tường lửa (nftables) cần tính đến việc IP nguồn không đáng tin.
- Bắt gói để lấy dữ liệu cho Edge AI: không dùng `tshark -i any` ngoài mạng ảo vì một gói sẽ bị bắt nhiều lần trên các cổng của `s1`. Nên bắt tại Gateway, chỉ chiều vào, để mỗi gói được đếm một lần. Tại `mininet>`:

  ```
  gw tcpdump -i gw-eth0 -Q in -nn -w /tmp/vao_eth0.pcap &
  gw tcpdump -i gw-eth1 -Q in -nn -w /tmp/vao_eth1.pcap &
  ```

  Dừng bằng `sh pkill tcpdump`. Điểm bắt gói cuối cùng do nhóm Edge AI quyết định.
- Ghi lại thời điểm bắt đầu và kết thúc mỗi đợt tấn công vào tệp CSV để gán nhãn dữ liệu cho Edge AI (không gán một nhãn cho cả file PCAP, vì file tấn công vẫn chứa lưu lượng bình thường).
- Đặc trưng theo đề cương, tính trong mỗi cửa sổ 1 giây: packet rate, byte rate, SYN count, IP dispersion. Việc trích xuất đặc trưng thuộc nhóm Edge AI, không nằm trong phần Tổ 2.

## 8. Hạn chế đã biết

- Cảm biến thật dùng Wi-Fi (ESP32), mô phỏng coi mạng truy cập là có dây theo VLAN.
- 300 cảm biến được mô phỏng bằng 10 host × 30 IP (1 chính, 29 phụ); các IP dùng chung một giao diện và một hàng đợi. Đủ để tạo tải, nhưng không mô phỏng riêng lẻ từng thiết bị.
- Tải bình thường đã khoảng 80% liên kết (20 camera × 4 Mbps; 4 Mbps là lựa chọn thiết kế của nhóm), nên sai khác nhỏ về băng thông có thể làm kết quả đo thay đổi.
- Các phép ping trong `--test` chỉ kiểm tra thông mạng, không phải số đo RTT của Chương 2 (số đo thật dùng lưu lượng do Tổ 3 sinh).
- Mạng chạy trong namespace của Mininet, không có NAT ra ngoài; không bật NAT cho `atk` để tấn công mô phỏng không ra khỏi máy ảo.