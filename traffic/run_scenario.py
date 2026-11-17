import time
import csv
import os

EVENTS_FILE = "events.csv"

def log_event(episode, start_time, end_time, attack_type, rate_pps):
    """
    Ghi nhật ký sự kiện chuẩn Form hợp đồng dữ liệu Tổ 3
    Các cột: episode, start, end, attack_type, rate_pps
    """
    file_exists = os.path.isfile(EVENTS_FILE)
    with open(EVENTS_FILE, mode='a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['episode', 'start', 'end', 'attack_type', 'rate_pps'])
        writer.writerow([episode, start_time, end_time, attack_type, rate_pps])
    print(f"Đã ghi log sự kiện vào {EVENTS_FILE}")

# Mẫu điều phối thử nghiệm (Sẽ được gọi tự động bởi kịch bản ma trận)
if __name__ == "__main__":
    print("--- KHỞI ĐỘNG KỊCH BẢN THỬ NGHIỆM ---")
    start_ts = int(time.time())
    
    # ... (Quá trình máy ảo chạy MQTT và Camera sẽ diễn ra ở đây) ...
    
    end_ts = int(time.time()) + 60  # Mô phỏng đợt chạy 60 giây
    # Log sự kiện mẫu để Edge AI đọc
    log_event("KichBan_3", start_ts, end_ts, "syn_flood_spoof", 5000)