from contextlib import redirect_stdout
import ctypes
import io
import json
import os
import select
import subprocess
import sys
import time
from threading import Event
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import run
import serial_gateway as serial


def subreaper():
    current = ctypes.c_int()
    assert serial._LIBC.prctl(37, ctypes.byref(current), 0, 0, 0) == 0
    return current.value


class SerialCleanupTests(unittest.TestCase):
    def gateway(self, script="import time; time.sleep(60)", seconds=30):
        command = [sys.executable, "-c", script]
        config = SimpleNamespace(absolute_deadline=time.monotonic() + seconds)
        with patch.object(serial, "ssh_command", return_value=command):
            return serial.SerialGateway(config).__enter__()

    def assert_closed(self, gateway, original):
        for stream in (gateway._child.stdin, gateway._child.stdout, gateway._child.stderr):
            self.assertTrue(stream.closed)
        self.assertFalse(gateway._buffer)
        self.assertEqual(subreaper(), original)
        next_gateway = self.gateway()
        next_gateway.close()
        with self.assertRaises(ChildProcessError):
            os.waitpid(gateway._child.pid, os.WNOHANG)

    def test_failed_join_still_reaps_and_closes(self):
        original = subreaper()
        resume = Event()

        def late_watchdog(owner):
            if resume.wait(5):
                owner._kill_group(time.monotonic() + 1)

        with patch.object(serial.SerialGateway, "_watchdog", late_watchdog):
            gateway = self.gateway()
        gateway._buffer.extend(b"fixture")
        try:
            with patch.object(serial, "_WATCHDOG_JOIN_SECONDS", .04):
                start = time.monotonic()
                with self.assertRaisesRegex(serial.GatewayError, "watchdog_join_timeout"):
                    gateway.close()
                self.assertLess(time.monotonic() - start, 1)
            self.assertTrue(gateway._thread.is_alive())
            self.assert_closed(gateway, original)
            with patch.object(os, "killpg") as signal_group:
                resume.set()
                gateway._thread.join(timeout=1)
                self.assertFalse(gateway._thread.is_alive())
                signal_group.assert_not_called()
        finally:
            resume.set()
            gateway._thread.join(timeout=1)
            gateway.close()

    def test_cleanup_error_after_completed_transport_reports_export(self):
        gateway = self.gateway()
        def finish(*, outcome):
            with patch.object(gateway._thread, "join", side_effect=RuntimeError("failed join")):
                try:
                    outcome.protected_export_available = True
                    outcome.transport_completed = True
                finally:
                    gateway.close()
        stdout = io.StringIO()
        with redirect_stdout(stdout), self.assertRaisesRegex(serial.GatewayError, "watchdog_join_failed"):
            run.controller_attempt(finish)
        self.assertEqual(json.loads(stdout.getvalue()), {
            "protected_export_available": True, "transport_completed": True, "retirement": "external"})
        self.assertTrue(gateway._child.stdin.closed)
        self.assertIsNotNone(gateway._exit)

    def test_watchdog_kills_group_and_owner_reaps_descendant(self):
        script = ("import os,time; child=os.fork(); "
                  "print(child, flush=True) if child else None; time.sleep(60)")
        original = subreaper()
        gateway = self.gateway(script, seconds=.5)
        try:
            self.assertTrue(select.select([gateway._child.stdout], [], [], 1)[0])
            descendant = int(gateway._child.stdout.readline())
            gateway._thread.join(timeout=2)
            self.assertFalse(gateway._thread.is_alive())
            self.assertEqual(gateway._failure, "absolute_deadline")
        finally:
            gateway.close()
        self.assert_closed(gateway, original)
        with self.assertRaises(ChildProcessError):
            os.waitpid(descendant, os.WNOHANG)
        self.assertFalse(os.path.exists(f"/proc/{descendant}"))

    def test_wait_timeout_is_bounded_and_next_attempt_reaps(self):
        original = subreaper()
        gateway = self.gateway()
        try:
            expired = subprocess.TimeoutExpired("ssh", 2)
            with patch.object(gateway._child, "wait", side_effect=expired) as wait:
                start = time.monotonic()
                with self.assertRaisesRegex(serial.GatewayError, "child_reap_timeout"):
                    gateway.close()
                self.assertLess(time.monotonic() - start, 3)
                self.assertLessEqual(wait.call_args.kwargs["timeout"], 2)
            self.assert_closed(gateway, original)
        finally:
            gateway.close()
