#!/usr/bin/env python3
"""Guide fresh Goodix 5503 enrollment through the standard fprintd D-Bus API.

No access to old templates, image dumps, private libfprint APIs, or root files.
The driver collects 40 training samples, saves 24 representatives, and requires
six of eight subsequent, withheld checks before enrollment can complete.
"""
from __future__ import annotations

import argparse
import getpass
import math
import os
import shutil
import signal
import subprocess
import sys
import time

TRAINING = 40
CHECKS = 8
TOTAL = TRAINING + CHECKS
INTERFACE = "net.reactivated.Fprint.Device"
FINGERS = tuple(f"{hand}-{finger}-finger" for hand in ("left", "right")
                for finger in ("index", "middle", "ring", "little")) + ("left-thumb", "right-thumb")


def guidance(completed: int, chinese: bool) -> str:
    if not 0 <= completed <= TOTAL:
        raise ValueError("Invalid enrollment progress")
    if completed == TOTAL:
        return "采样检查结束，请抬起手指。" if chinese else "Done. Lift your finger."
    phase = min(completed // 10, 4)
    zh = (
        "整只手从键盘或鼠标处重新抬起，用同一根手指按平时解锁的位置和力度按一次。",
        "先换一下整只手在键盘或鼠标处的位置，再重新抬手，用同一根手指按平时解锁的力度按一次。",
        "整只手重新抬起，仍以平时解锁力度为主，偶尔略轻或略重；保持大部分指腹接触。",
        "整只手重新抬起，仍以平时解锁位置为主，偶尔稍变手腕角度；保持大部分指腹接触。",
        "新按压检查：整只手从键盘或鼠标处重新抬起，像平时解锁一样按一次，不刻意复现训练位置。",
    )
    en = (
        "Normal position and pressure.",
        "Reposition your hand, then press normally.",
        "Usual pressure; occasionally lighter or firmer.",
        "Usual position; occasionally change the angle.",
        "Use your normal unlock motion.",
    )
    prefix = (f"采样 {completed + 1}/{TRAINING}" if completed < TRAINING else
              f"检查 {completed - TRAINING + 1}/{CHECKS}") if chinese else (
              f"Press {completed + 1}/{TRAINING}" if completed < TRAINING else
              f"Check {completed - TRAINING + 1}/{CHECKS}")
    return prefix + " — " + (zh if chinese else en)[phase]


class ReadyPrompts:
    """Pace guidance while respecting device readiness and cancellation.

    This delays prompts, not the sensor: a touch before a prompt can still be
    collected by fprintd. Moving the whole hand away is part of the guidance.
    """
    def __init__(self, emit, schedule, remove, clock=time.monotonic):
        self.emit = emit
        self.schedule = schedule
        self.remove = remove
        self.clock = clock
        self.active = False
        self.needed = False
        self.source = 0
        self.not_before = 0.0

    def _cancel(self):
        if self.source:
            self.remove(self.source)
            self.source = 0

    def _schedule(self):
        self._cancel()
        if self.active and self.needed:
            delay = max(1, math.ceil((self.not_before - self.clock()) * 1000))
            self.source = self.schedule(delay, self._ready)

    def _ready(self):
        self.source = 0
        if self.active and self.needed:
            if self.clock() < self.not_before:
                self._schedule()
            else:
                self.emit()
        return False

    def start(self):
        self.active = True
        self._schedule()

    def set_needed(self, needed):
        if self.needed != needed:
            self.needed = needed
            self._schedule()

    def pause(self, completed, stage_passed):
        seconds = 6.0 if stage_passed and completed in (10, 20, 30, 40) else 2.5
        self.not_before = max(self.not_before, self.clock() + seconds)
        self._schedule()

    def stop(self):
        self.active = False
        self._cancel()


class Progress:
    """Map fprintd's precheck + 47 progress signals + completion to 48 stages."""
    def __init__(self) -> None:
        self.precheck_done = False
        self.completed = 0
        self.terminal = False
        self.success = False

    def receive(self, status: str, done: bool) -> None:
        if self.terminal:
            raise ValueError("Enrollment status arrived after completion")
        if status == "enroll-stage-passed":
            if done or self.completed >= TOTAL - 1:
                raise ValueError("Unexpected enrollment stage count")
            if not self.precheck_done:
                self.precheck_done = True
            else:
                self.completed += 1
        if done:
            self.terminal = True
            self.success = (status == "enroll-completed" and self.precheck_done
                            and self.completed == TOTAL - 1)
            if self.success:
                self.completed = TOTAL

    def prompt(self, chinese: bool) -> str:
        if not self.precheck_done:
            return ("录入前查重：请用将要录入的手指自然按一次，再完全抬起；这次不计入 40 次采样。"
                    if chinese else
                    "Precheck — Press once, then lift.")
        return guidance(self.completed, chinese)


def check_replacement(enrolled: list[str], finger: str, replace: bool) -> None:
    if finger in enrolled and not replace:
        raise ValueError(
            "Already enrolled. Use --replace to replace it. Starting removes the old print, even if cancelled.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--finger", choices=FINGERS, default="right-index-finger")
    parser.add_argument("--user", default=getpass.getuser())
    parser.add_argument("--language", choices=("auto", "zh", "en"), default="en")
    parser.add_argument("--no-notify", action="store_true", help="Use terminal prompts only")
    parser.add_argument("--replace", action="store_true",
                        help="Allow fprintd to delete this finger's existing template when starting")
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()
    if not 60 <= args.timeout <= 1800:
        parser.error("timeout must be between 60 and 1800 seconds")
    chinese = args.language == "zh" or (args.language == "auto" and
               os.environ.get("LC_ALL", os.environ.get("LANG", "")).startswith("zh"))
    import gi
    gi.require_version("GLibUnix", "2.0")
    from gi.repository import Gio, GLib, GLibUnix

    def say(message: str) -> None:
        print(message, flush=True)
        if not args.no_notify and shutil.which("notify-send"):
            try:
                subprocess.run(["notify-send", "-a", "Goodix", "-t", "10000",
                                "-h", "string:x-canonical-private-synchronous:goodix-enroll",
                                "Goodix 指纹录入" if chinese else "Goodix enrollment", message],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=3, check=False)
            except (OSError, subprocess.TimeoutExpired):
                pass  # The terminal remains a usable prompt channel.

    bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    manager = Gio.DBusProxy.new_sync(bus, Gio.DBusProxyFlags.NONE, None,
        "net.reactivated.Fprint", "/net/reactivated/Fprint/Manager",
        "net.reactivated.Fprint.Manager", None)
    devices = manager.call_sync("GetDevices", None, Gio.DBusCallFlags.NONE, 10000, None).unpack()[0]
    candidates = []
    for path in devices:
        proxy = Gio.DBusProxy.new_sync(bus, Gio.DBusProxyFlags.NONE, None,
            "net.reactivated.Fprint", path, INTERFACE, None)
        name = proxy.get_cached_property("name")
        stages = proxy.get_cached_property("num-enroll-stages")
        # fprintd exposes one extra stage for its initial duplicate check.
        if name and "5503" in name.unpack() and stages and stages.unpack() == TOTAL + 1:
            candidates.append(proxy)
    if len(candidates) != 1:
        parser.error("Exactly one Goodix 5503 device with the 40+8 enrollment driver is required")
    device = candidates[0]
    progress = Progress()
    loop = GLib.MainLoop()
    failure: list[str] = []
    started = False
    claimed = False
    deadline = time.monotonic() + args.timeout

    def prompt_ready() -> None:
        needed = device.get_cached_property("finger-needed")
        if started and not progress.terminal and needed and needed.unpack():
            say(progress.prompt(chinese))

    prompts = ReadyPrompts(prompt_ready, GLib.timeout_add, GLib.source_remove)

    def properties_changed(_proxy, changed, _invalidated) -> None:
        values = changed.unpack()
        if "finger-needed" in values:
            prompts.set_needed(values["finger-needed"])

    def status_changed(_proxy, _sender, name, parameters) -> None:
        if name != "EnrollStatus":
            return
        status, done = parameters.unpack()
        try:
            progress.receive(status, done)
        except ValueError as error:
            failure.append(str(error))
            loop.quit()
            return
        if done:
            prompts.stop()
            if not progress.success:
                failure.append({"enroll-failed": "Checks failed.",
                                "enroll-disconnected": "Device disconnected."}.get(status, "Enrollment failed."))
            loop.quit()
        else:
            passed = status == "enroll-stage-passed"
            prompts.pause(progress.completed, passed)
            group_done = passed and progress.completed in (10, 20, 30, 40)
            if not chinese:
                say("Group done. Rest your hand for 6s." if group_done else
                    "Hand away. Wait." if passed else "Retry. Lift and wait.")
                return
            if passed:
                message = ("本次已完成。" if chinese else "Press completed. ")
            else:
                message = ("这次未计入采样。" if chinese else "Sample not added. ")
            if group_done:
                message += ("这一组结束，休息约 6 秒。" if chinese else "Group finished; pause for about 6 seconds. ")
            message += ("请完全抬指，把整只手放回键盘或鼠标处，等下一条采样或检查提示再按。" if chinese else
                        "Lift fully and return your whole hand to the keyboard or mouse. Wait for the next sample or check prompt before pressing.")
            say(message)

    def timeout() -> bool:
        if time.monotonic() >= deadline:
            failure.append("Enrollment timed out")
            loop.quit()
            return GLib.SOURCE_REMOVE
        return GLib.SOURCE_CONTINUE

    def interrupt() -> bool:
        failure.append("Enrollment cancelled")
        loop.quit()
        return GLib.SOURCE_REMOVE

    device.connect("g-properties-changed", properties_changed)
    device.connect("g-signal", status_changed)
    timer = GLib.timeout_add_seconds(1, timeout)
    handlers = [GLibUnix.signal_add(GLib.PRIORITY_DEFAULT, sig, interrupt)
                for sig in (signal.SIGINT, signal.SIGTERM)]
    try:
        device.call_sync("Claim", GLib.Variant("(s)", (args.user,)), Gio.DBusCallFlags.NONE, 120000, None)
        claimed = True
        try:
            enrolled = device.call_sync("ListEnrolledFingers", GLib.Variant("(s)", (args.user,)),
                                        Gio.DBusCallFlags.NONE, 10000, None).unpack()[0]
        except GLib.Error as error:
            if Gio.DBusError.get_remote_error(error) != "net.reactivated.Fprint.Error.NoEnrolledPrints":
                raise
            enrolled = []
        check_replacement(enrolled, args.finger, args.replace)
        say(("请先把整只手放回键盘或鼠标处。全程使用同一根手指和平时解锁的力度；每次重新抬起整只手，等就绪提示再按，不连续点按。先查重一次，再采样 40 次，最后检查 8 次，约 3–5 分钟。" if chinese else
             f"{args.finger.replace('-', ' ').capitalize()}. Rest your whole hand between presses. Follow prompts (~4 min)."))
        device.call_sync("EnrollStart", GLib.Variant("(s)", (args.finger,)), Gio.DBusCallFlags.NONE, 30000, None)
        started = True
        needed = device.get_cached_property("finger-needed")
        prompts.set_needed(bool(needed and needed.unpack()))
        prompts.start()
        loop.run()
    finally:
        prompts.stop()
        if GLib.MainContext.default().find_source_by_id(timer):
            GLib.source_remove(timer)
        for handler in handlers:
            if GLib.MainContext.default().find_source_by_id(handler):
                GLib.source_remove(handler)
        if started:
            try:
                device.call_sync("EnrollStop", None, Gio.DBusCallFlags.NONE, 10000, None)
            except GLib.Error as error:
                print(f"EnrollStop: {error.message}", file=sys.stderr)
        if claimed:
            device.call_sync("Release", None, Gio.DBusCallFlags.NONE, 10000, None)
    if progress.success and not failure:
        say("录入完成：已保存 24 张样本，独立新按压检查通过。" if chinese else
            "Saved. Enrollment complete.")
        return 0
    say(("录入未完成，未通过新按压检查或操作已中止。请重新采集更多自然位置。" if chinese else
         "Not saved.") +
        " " + "; ".join(failure))
    return 1


if __name__ == "__main__":
    exit_code = 1
    try:
        from gi.repository import GLib
        exit_code = main()
    except (ImportError, OSError, ValueError) as error:
        print(f"Goodix enrollment: {error}", file=sys.stderr)
    except KeyboardInterrupt:
        print("Goodix enrollment: cancelled", file=sys.stderr)
        exit_code = 130
    except GLib.Error as error:
        print(f"Goodix enrollment: {error.message}", file=sys.stderr)
    raise SystemExit(exit_code)
