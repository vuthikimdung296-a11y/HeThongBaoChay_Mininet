# -*- coding: utf-8 -*-
"""nodes.py - Cac loai nut tu dinh nghia. Hien co: LinuxRouter (Gateway)."""
from mininet.node import Node


class LinuxRouter(Node):
    """Host bat ip_forward de dinh tuyen giua cac mang (nhu mau linuxrouter.py cua Mininet)."""
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()
