# Thư mục Dữ liệu Huấn luyện Edge AI (edge_ai/data)

Thư mục này dùng để lưu trữ dữ liệu đặc trưng **thu thập thực tế từ mạng ảo Mininet**, phục vụ huấn luyện và kiểm thử mô hình phát hiện DDoS tại Gateway.

> [!IMPORTANT]
> Toàn bộ dữ liệu đặt tại đây phải được trích xuất từ các lần chạy thực tế trong mạng Mininet thông qua `collect_metadata.py` và nhật ký tấn công từ `traffic/attack.py`. Không lưu dữ liệu tự sinh ngẫu nhiên vào thư mục này.

## Quy trình thu thập và chuẩn bị dữ liệu thực tế

Các lệnh đầy đủ (mạng, broker, QoS, thu thập, tấn công, gán nhãn, gộp, huấn luyện) nằm ở **`edge_ai/README.md`, mục 4 và 5**, để chỉ có một nơi duy nhất cần cập nhật. Ba điểm bắt buộc khi thu dữ liệu:

1. **Đường dẫn tuyệt đối.** Lệnh chạy trong node Mininet (`gw python3 ...`) phải dùng đường dẫn tuyệt đối (`<REPO>/edge_ai/...`), vì các node chạy trong thư mục `Network/`.
2. **Tên lượt duy nhất**, ví dụ `kichban3_syn_1000_lan1`, dùng thống nhất ở tên file đặc trưng, `attack.py --episode` và `build_dataset.py --episode`.
3. **Tấn công phải chạy bằng `traffic/attack.py`** (hoặc `traffic/run_scenario.py`) để thời điểm bắt đầu và kết thúc được ghi vào `traffic/results/attack_events.csv`. Chạy `hping3` trực tiếp thì không có nhật ký, không gán nhãn được.

Sau khi gán nhãn, kiểm tra dòng kết quả của `build_dataset.py`: lượt có tấn công phải có số cửa sổ tấn công lớn hơn 0.
