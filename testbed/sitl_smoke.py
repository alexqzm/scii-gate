# -*- coding: utf-8 -*-
"""Дымовое испытание ArduCopter в SITL: взлёт на 10 м в режиме GUIDED и посадка в режиме LAND.

  python sitl_smoke.py --binary build-sitl/bin/arducopter --defaults Tools/autotest/default_params/copter.parm \
                       --out tests.json [--workdir DIR] [--speedup 10]

Результат PASSED, если все шаги выполнены в отведённое время. Файл результата содержит шаги, времена
и параметры запуска; из него конвейер стенда делает аттестацию test-result (свидетельство s43).
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time

from pymavlink import mavutil

PREARM_BIT = mavutil.mavlink.MAV_SYS_STATUS_PREARM_CHECK
GUIDED, LAND = 4, 9


def now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


class Smoke:
    def __init__(self, a):
        self.a, self.steps, self.t0 = a, [], time.monotonic()
        self.max_alt = 0.0

    def step(self, name, ok, **kw):
        rec = {"step": name, "ok": bool(ok), "t_s": round(time.monotonic() - self.t0, 2)}
        rec.update(kw)
        self.steps.append(rec)
        print(json.dumps(rec, ensure_ascii=False), flush=True)
        if not ok:
            raise RuntimeError(name)

    def wait(self, m, pred, timeout, types=None):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            msg = m.recv_match(type=types, blocking=True, timeout=1)
            if msg is None:
                continue
            if msg.get_type() == "GLOBAL_POSITION_INT":
                self.max_alt = max(self.max_alt, msg.relative_alt / 1000.0)
            if pred(msg):
                return msg
        return None

    def command(self, m, cmd, *params):
        p = list(params) + [0] * (7 - len(params))
        m.mav.command_long_send(m.target_system, m.target_component, cmd, 0, *p)
        ack = self.wait(m, lambda x: x.get_type() == "COMMAND_ACK" and x.command == cmd, 10, ["COMMAND_ACK"])
        return ack is not None and ack.result == mavutil.mavlink.MAV_RESULT_ACCEPTED

    def run(self):
        a = self.a
        work = a.workdir or tempfile.mkdtemp(prefix="sitl-")
        log = open(os.path.join(work, "sitl.log"), "w")
        cmd = [a.binary, "--model", "+", "--speedup", str(a.speedup), "--defaults", a.defaults,
               "--home", "-35.363261,149.165230,584,353", "-I0"]
        proc = subprocess.Popen(cmd, cwd=work, stdout=log, stderr=subprocess.STDOUT)
        try:
            m = None
            for _ in range(60):
                try:
                    m = mavutil.mavlink_connection("tcp:127.0.0.1:5760", source_system=255)
                    break
                except OSError:
                    time.sleep(0.5)
            hb = m and m.wait_heartbeat(timeout=60)
            self.step("heartbeat", hb is not None)
            m.mav.request_data_stream_send(m.target_system, m.target_component,
                                           mavutil.mavlink.MAV_DATA_STREAM_ALL, 10, 1)
            ok = self.wait(m, lambda x: x.get_type() == "SYS_STATUS"
                           and x.onboard_control_sensors_health & PREARM_BIT, a.timeout_prearm, ["SYS_STATUS"])
            self.step("prearm_checks_pass", ok is not None)
            m.set_mode(GUIDED)
            ok = self.wait(m, lambda x: x.get_type() == "HEARTBEAT" and x.custom_mode == GUIDED, 15, ["HEARTBEAT"])
            self.step("mode_guided", ok is not None)
            armed = False
            for _ in range(5):                   # после прохождения проверок постановка на охрану может
                if self.command(m, mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM, 1):   # потребовать повтора
                    armed = True
                    break
                time.sleep(2)
            self.step("arm", armed)
            self.step("takeoff_cmd", self.command(m, mavutil.mavlink.MAV_CMD_NAV_TAKEOFF, 0, 0, 0, 0, 0, 0,
                                                  a.alt))
            ok = self.wait(m, lambda x: x.get_type() == "GLOBAL_POSITION_INT"
                           and x.relative_alt / 1000.0 >= a.alt * 0.95, 60, ["GLOBAL_POSITION_INT"])
            self.step("reach_altitude", ok is not None, alt_m=round(self.max_alt, 2))
            m.set_mode(LAND)
            ok = self.wait(m, lambda x: x.get_type() == "HEARTBEAT" and x.custom_mode == LAND, 15, ["HEARTBEAT"])
            self.step("mode_land", ok is not None)
            ok = self.wait(m, lambda x: x.get_type() == "HEARTBEAT" and x.custom_mode == LAND and
                           not x.base_mode & mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED, 120,
                           ["HEARTBEAT", "GLOBAL_POSITION_INT"])
            self.step("landed_disarmed", ok is not None, max_alt_m=round(self.max_alt, 2))
            return "PASSED"
        except RuntimeError:
            return "FAILED"
        finally:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
            log.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--defaults", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workdir")
    ap.add_argument("--speedup", type=int, default=10)
    ap.add_argument("--alt", type=float, default=10.0)
    ap.add_argument("--timeout-prearm", dest="timeout_prearm", type=float, default=180)
    a = ap.parse_args()
    s = Smoke(a)
    started = now()
    result = s.run()
    rep = {"result": result, "startedOn": started, "finishedOn": now(), "steps": s.steps,
           "wall_s": round(time.monotonic() - s.t0, 2),
           "configuration": {"binary": os.path.basename(a.binary), "binary_sha256": sha256(a.binary),
                             "defaults": a.defaults, "defaults_sha256": sha256(a.defaults),
                             "model": "+", "speedup": a.speedup, "takeoff_alt_m": a.alt}}
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=1)
    print("result:", result)
    return 0 if result == "PASSED" else 1


if __name__ == "__main__":
    sys.exit(main())
