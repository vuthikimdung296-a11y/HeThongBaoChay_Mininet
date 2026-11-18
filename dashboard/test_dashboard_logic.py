import os, sys, time, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import dashboard_logic as dl

def rec(**kw):
    base = dict(timestamp=time.time(), normal_packets=1000, syn_packets=0, udp_packets=0, rtt_ms=20,
                status="NORMAL", blocked_ips=[])
    base.update(kw); return dl.normalize(base)

def test_classify():
    for s, e in [("NORMAL","normal"),("Bình thường","normal"),("ATTACK","attack"),("tấn công","attack"),
                 ("BLOCKED","mitigated"),("Đã chặn","mitigated"),("attack_blocked","mitigated"),
                 ("","unknown"),(None,"unknown"),("???","unknown")]:
        assert dl.classify_status(s) == e, s

def test_tiers_normal():
    t = dl.tier_states(rec())
    assert all(v["ok"] for v in t.values())

def test_tiers_attack():
    t = dl.tier_states(rec(status="ATTACK", rtt_ms=300, syn_packets=1000))
    assert not t["sensor"]["ok"] and not t["camera"]["ok"] and not t["server"]["ok"]
    assert not t["gateway"]["ok"] and not t["attacker"]["ok"]

def test_tiers_blocked():
    t = dl.tier_states(rec(status="BLOCKED", blocked_ips=["1.2.3.4"]))
    assert t["sensor"]["ok"] and t["server"]["ok"] and t["gateway"]["ok"] and not t["attacker"]["ok"]
    assert "1" in t["gateway"]["label"]

def test_tiers_qos_protects_sensors():
    t = dl.tier_states(rec(status="ATTACK", rtt_ms=40))
    assert t["sensor"]["ok"] and not t["server"]["ok"]

def test_stale_and_missing():
    assert dl.tier_states(None)["sensor"]["ok"] is None
    old = rec(timestamp=time.time() - 60)
    assert dl.is_stale(old) and dl.tier_states(old, True)["gateway"]["label"] == "Mất kết nối"

def test_normalize_robust():
    s = dl.normalize({"timestamp": "2026-11-18T10:00:00Z", "rtt_ms": "abc", "normal_packets": None,
                      "blocked_ips": [{"ip": "9.9.9.9", "reason": "syn"}, "", "8.8.8.8"], "status": "BLOCKED"})
    assert s["rtt_ms"] is None and s["normal"] == 0 and [b["ip"] for b in s["blocked"]] == ["9.9.9.9", "8.8.8.8"]
    assert dl.normalize({"timestamp": 1.78e12})["ts"] == 1.78e9

def test_history_dedupe_and_cap():
    h = []; s = rec()
    assert dl.update_history(h, s) and not dl.update_history(h, s)
    for i in range(300):
        dl.update_history(h, rec(timestamp=1000 + i), maxlen=100)
    assert len(h) == 100

def test_blocked_log():
    log, act = [], set()
    dl.update_blocked_log(log, act, rec(blocked_ips=["1.1.1.1"]))
    dl.update_blocked_log(log, act, rec(blocked_ips=["1.1.1.1"]))   # không ghi trùng
    assert len(log) == 1 and log[0]["Sự kiện"] == "CHẶN"
    dl.update_blocked_log(log, act, rec(blocked_ips=[]))
    assert log[-1]["Sự kiện"] == "GỠ CHẶN" and not act

def test_json_loader_and_ipc(tmp_path=None):
    d = tempfile.mkdtemp()
    dl.CMD_PATH = os.path.join(d, "c.json"); dl.STATUS_PATH = os.path.join(d, "s.json")
    assert dl.load_json(os.path.join(d, "none.json"))[0] is None
    open(os.path.join(d, "bad.json"), "w").write("{oops")
    assert dl.load_json(os.path.join(d, "bad.json"))[0] is None
    c = dl.send_command("attack_qos", duration=30)
    assert dl.read_command()["id"] == c["id"]
    dl.write_status(state="idle"); assert dl.daemon_alive(dl.read_status())
    try: dl.send_command("xyz"); assert False
    except ValueError: pass

def test_svg_wellformed():
    import xml.dom.minidom as m
    for st in (None, rec(), rec(status="ATTACK", rtt_ms=300), rec(status="BLOCKED", blocked_ips=["a"])):
        m.parseString(dl.build_tier_svg(dl.tier_states(st)))

if __name__ == "__main__":
    n = 0
    for k, v in list(globals().items()):
        if k.startswith("test_"): v(); n += 1; print("ok", k)
    print(n, "tests passed")
