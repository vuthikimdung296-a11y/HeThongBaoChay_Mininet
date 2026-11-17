# -*- coding: utf-8 -*-
"""verify.py - KIEM TRA TU DONG (Test 1-4 trong file phan cong). Them phep thu moi thi them vao danh sach `cases`."""
import re

from config import SRV_IP, VLAN_SENSOR, VLAN_CAM, VLAN_SRV


def ping(node, target, count=3, src=None):
    opt = '-I %s ' % src if src else ''
    out = node.cmd('ping -c %d -W 1 %s%s' % (count, opt, target))
    loss = re.search(r'([\d.]+)% packet loss', out)
    rtt = re.search(r'= [\d.]+/([\d.]+)/', out)
    return (float(loss.group(1)) if loss else 100.0,
            float(rtt.group(1)) if rtt else None)


def run_tests(net, sensors, cams, aliases):
    srv_ip = SRV_IP.split('/')[0]
    cases = [
        ('Test 1  Cam bien hs01 -> srv (qua gw)',           'hs01',  srv_ip, None),
        ('Test 1b Cam bien hs10, IP phu cuoi -> srv',        'hs10',  srv_ip, aliases['hs10'][-1]),
        ('Test 2  Camera cam01 -> gw VLAN 20 (10.0.20.1)',   'cam01', '10.0.20.1', None),
        ('Test 2b Camera cam20 -> srv (qua gw)',             'cam20', srv_ip, None),
        ('Test 3  Ke tan cong atk -> gw eth1',               'atk',   '192.168.100.1', None),
        ('Test 3b atk -> srv (dinh tuyen qua gw)',           'atk',   srv_ip, None),
        ('Test 5  srv -> gw VLAN 30 (10.0.30.1)',            'srv',   '10.0.30.1', None),
    ]
    print('\n%-52s %8s %10s %s' % ('Phep thu', 'Mat goi', 'RTT TB(ms)', 'Ket qua'))
    ok_all = True
    for title, src, dst, srcip in cases:
        loss, rtt = ping(net.get(src), dst, 3, srcip)
        ok = loss == 0.0
        ok_all &= ok
        print('%-52s %7.0f%% %10s %s' % (title, loss, '-' if rtt is None else '%.2f' % rtt,
                                         'DAT' if ok else 'KHONG DAT'))
    bad = [h for h in sensors + cams if ping(net.get(h), srv_ip, 1)[0] > 0]
    print('Tat ca 30 host (hs + cam) ping duoc srv: %s' % ('DAT' if not bad else 'KHONG DAT: ' + ', '.join(bad)))
    ok_all &= not bad

    # Test 4: kiem tra tag/trunk tren OVS
    s1 = net.get('s1')
    want = [('s1-' + h, VLAN_SENSOR) for h in sensors] + [('s1-' + h, VLAN_CAM) for h in cams] \
        + [('s1-srv', VLAN_SRV)]
    wrong = [p for p, t in want if s1.cmd('ovs-vsctl get port %s tag' % p).strip() != str(t)]
    trunk = s1.cmd('ovs-vsctl get port s1-gw trunks').strip()
    print('Test 4  OVS: %d cong access dung tag: %s; trunk s1-gw = %s'
          % (len(want), 'DAT' if not wrong else 'SAI ' + ', '.join(wrong), trunk))
    ok_all &= (not wrong) and trunk.replace(' ', '') == '[10,20,30]'
    print('\nKET LUAN: %s\n' % ('TAT CA DAT' if ok_all else 'CO PHEP THU KHONG DAT - xem log phia tren'))
    return ok_all
