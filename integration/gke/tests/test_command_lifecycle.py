"""Bounded controller command I/O across real subprocess pipes."""

import os
import subprocess
import sys
import time
import unittest
from unittest import mock

import run


class CommandTests(unittest.TestCase):
    def test_excess_output_rejected_before_child_exit(self):
        cap = 4096
        script = "import os,time; os.write(1,b'x'*8192); time.sleep(10)"
        read = os.read
        received = 0

        def measured(fd, size):
            nonlocal received
            chunk = read(fd, size)
            received += len(chunk)
            return chunk

        with mock.patch.object(os, "read", side_effect=measured):
            with self.assertRaisesRegex(run.kube.AttemptError, "operator_command_failed"):
                run.run([sys.executable, "-c", script], time.monotonic() + 3, cap=cap)
        self.assertEqual(received, cap + 1)

    def test_full_pipes_and_exact_cap(self):
        payload = b"x" * 131072
        script = ("import sys; sys.stdout.buffer.write(b'y'*131072); sys.stdout.flush(); "
                  "sys.stdout.buffer.write(sys.stdin.buffer.read())")
        result = run.run([sys.executable, "-c", script], time.monotonic() + 3,
                         stdin=payload, cap=2 * len(payload))
        self.assertEqual(result, b"y" * len(payload) + payload)

    def test_partial_stdout_survives_timeout(self):
        script = "import os,time; os.write(1,b'prefix'); os.close(1); time.sleep(5)"
        with self.assertRaises(subprocess.TimeoutExpired) as expired:
            run._command([sys.executable, "-c", script], time.monotonic() + .5)
        self.assertEqual(expired.exception.stdout, b"prefix")
