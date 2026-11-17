#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gateway_ai.py - Alias cho gateway_detector.py (Đảm bảo tính tương thích và không bị phân mảnh code)."""
import os
import sys

_CUR = os.path.dirname(os.path.abspath(__file__))
if _CUR not in sys.path:
    sys.path.insert(0, _CUR)

from gateway_detector import Detector, FirewallManager, is_whitelisted, main  # noqa: F401

if __name__ == '__main__':
    main()
