import subprocess
import time

def start_camera(target_ip="10.0.30.10", bandwidth="4M", duration=120):
    """
    Giả lập luồng camera bằng iperf3 (Giao thức UDP)
    """
    print(f"Bắt đầu stream video camera tới {target_ip} với băng thông {bandwidth}...")
    # Lệnh iperf3 gửi UDP (-u), băng thông (-b), thời gian (-t)
    cmd = f"iperf3 -c {target_ip} -u -b {bandwidth} -t {duration}"
    
    try:
        subprocess.run(cmd, shell=True)
    except KeyboardInterrupt:
        print("\nĐã dừng stream camera.")

if __name__ == "__main__":
    start_camera()