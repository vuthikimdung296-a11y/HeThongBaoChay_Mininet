#!/bin/bash
# Script cấu hình Quality of Service (HTB) tại Gateway mặt trong (hướng về máy chủ)
IFACE="gw-eth0.30"

case "$1" in
    start)
        echo "=== BẬT CƠ CHẾ QoS (HTB) TRÊN $IFACE ==="
        tc qdisc del dev $IFACE root 2>/dev/null
        
        # Tạo gốc hàng đợi
        tc qdisc add dev $IFACE root handle 1: htb default 13
        tc class add dev $IFACE parent 1: classid 1:1 htb rate 100mbit ceil 100mbit

        # LỚP 10 (Mark 0 - BÁO CHÁY): Mức ưu tiên cao nhất (0), băng thông 10Mbps bảo đảm tuyệt đối
        tc class add dev $IFACE parent 1:1 classid 1:10 htb rate 10mbit ceil 100mbit prio 0
        
        # LỚP 11 (Mark 1 - TELEMETRY): Ưu tiên 1, băng thông 5Mbps
        tc class add dev $IFACE parent 1:1 classid 1:11 htb rate 5mbit ceil 100mbit prio 1
        
        # LỚP 12 (Mark 2 - CAMERA): Ưu tiên 2, bảo đảm 60Mbps, trần 90Mbps (Tránh chiếm hết đường truyền)
        tc class add dev $IFACE parent 1:1 classid 1:12 htb rate 60mbit ceil 90mbit prio 2
        
        # LỚP 13 (Mark 3 - TẤN CÔNG/RÁC): Ưu tiên 3 (Đáy xã hội), bóp nghẹt 1Mbps, trần 10Mbps
        tc class add dev $IFACE parent 1:1 classid 1:13 htb rate 1mbit ceil 10mbit prio 3

        # Gắn Rule: Đọc nhãn Mark từ Nftables để tống vào các ngăn HTB tương ứng
        tc filter add dev $IFACE parent 1: protocol ip handle 0 fw classid 1:10
        tc filter add dev $IFACE parent 1: protocol ip handle 1 fw classid 1:11
        tc filter add dev $IFACE parent 1: protocol ip handle 2 fw classid 1:12
        tc filter add dev $IFACE parent 1: protocol ip handle 3 fw classid 1:13
        
        echo "Thành công: Đã bọc thép luồng Báo cháy!"
        ;;
    stop)
        echo "Tắt QoS HTB trên $IFACE..."
        tc qdisc del dev $IFACE root 2>/dev/null
        ;;
    show)
        tc -s class show dev $IFACE
        ;;
    *)
        echo "Cách dùng: $0 {start|stop|show}"
        exit 1
esac