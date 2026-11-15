# -*- coding: utf-8 -*-
"""ip_plan.py - Quy hoach IP (thuan Python, KHONG can Mininet). Doi chieu duoc voi file Excel."""
import ipaddress
import re

from config import N_FLOORS, SENSORS_PER_FLOOR, CAMS_PER_FLOOR


def sensor_ips(floor):
    """30 IP cam bien cua tang `floor` (1..10).
    Moi tang chiem mot khoi 32 dia chi bat dau tu 10.0.10.0 + 32*floor; cam bien dung .1 ... .30 cua khoi.
    Tang 1: 10.0.10.33-62.  Tang 8: 10.0.11.1-30."""
    base = int(ipaddress.ip_address('10.0.10.0')) + 32 * floor
    return [str(ipaddress.ip_address(base + i)) for i in range(1, SENSORS_PER_FLOOR + 1)]


def camera_ip(n):
    """IP camera thu n (1..20): 10.0.20.(10+n)."""
    return '10.0.20.%d' % (10 + n)


def check_plan(xlsx_path):
    """Doi chieu IP sinh bang code voi sheet 'Danh sach cam bien' / 'Danh sach camera' trong Excel."""
    from openpyxl import load_workbook
    wb = load_workbook(xlsx_path, data_only=True)
    bad = n = m = 0
    for row in wb['Danh sách cảm biến'].iter_rows(min_row=5, values_only=True):
        if not (isinstance(row[0], int) and row[1] and re.match(r's\d\d-\d\d$', str(row[1]))):
            continue
        floor, idx = int(row[1][1:3]), int(row[1][4:6])
        want = sensor_ips(floor)[idx - 1]
        n += 1
        if row[4] != want:
            bad += 1
            print('LECH cam bien', row[1], 'Excel:', row[4], 'code:', want)
    print('Cam bien da doi chieu: %d, lech: %d' % (n, bad))
    for row in wb['Danh sách camera'].iter_rows(min_row=5, values_only=True):
        if row[1] and re.match(r'cam\d\d$', str(row[1])):
            m += 1
            want = camera_ip(int(row[1][3:5]))
            if row[4] != want:
                bad += 1
                print('LECH camera', row[1], 'Excel:', row[4], 'code:', want)
    print('Camera da doi chieu: %d, tong so lech: %d' % (m, bad))
    return bad == 0 and n == N_FLOORS * SENSORS_PER_FLOOR and m == N_FLOORS * CAMS_PER_FLOOR
