from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from attempt_driver import AttemptError
from launch_queue import LaunchQueue
import run


class LaunchQueueTests(unittest.TestCase):
    def setUp(self):
        temp = self.enterContext(tempfile.TemporaryDirectory())
        self.state = Path(temp)
        self.queue = LaunchQueue(self.state)
        self.receipt = dict(pod_uid="uid", pod_name="proof", cluster_id="cluster", attempt_id="attempt",
                            validity={"expires": int(time.time()) + 600})
        self.queue.publish(self.receipt)

    def test_duplicate_workers_commit_one_claim(self):
        barrier = threading.Barrier(2)

        def claim():
            barrier.wait(timeout=5)
            try:
                LaunchQueue(self.state).claim(self.receipt)
            except AttemptError as error:
                return str(error)
            return "claimed"

        with ThreadPoolExecutor(2) as workers:
            outcomes = list(workers.map(lambda _: claim(), range(2)))
        self.assertCountEqual(outcomes, ["claimed", "launch_already_claimed"])
        self.queue.publish(self.receipt)
        with self.assertRaisesRegex(AttemptError, "launch_already_claimed"):
            LaunchQueue(self.state).claim(self.receipt)
        other = dict(self.receipt, pod_uid="new", attempt_id="other")
        self.queue.publish(other)
        with self.assertRaisesRegex(AttemptError, "launch_capacity"):
            self.queue.claim(other)
        self.queue.finish("attempt", "exported")
        self.queue.claim(other)

    def test_expiry_and_claim_conflict(self):
        with self.assertRaisesRegex(AttemptError, "launch_receipt_conflict"):
            self.queue.publish(dict(self.receipt, attempt_id="another"))
        with patch("time.time", return_value=self.receipt["validity"]["expires"]):
            with self.assertRaisesRegex(AttemptError, "tenant_intent_window"):
                self.queue.claim(self.receipt)
        with closing(self.queue.connect()) as db:
            self.assertEqual(db.execute("SELECT phase,reason FROM launches").fetchone(),
                             ("expired", "tenant_intent_window"))

    def test_uncertain_launch_is_not_repeated(self):
        config = {"intent_cluster_id": "cluster", "launch_queue": str(self.state)}
        with patch.object(run, "reconcile_pod_intent"), patch.object(run, "wait_for_peer"), patch.object(
                run, "document", return_value=self.receipt), patch.object(
                run, "controller_attempt", side_effect=AttemptError("serial_timeout")) as drive:
            with self.assertRaisesRegex(AttemptError, "serial_timeout"):
                run.queued_launch(None, config, None, None, 0, name="proof", uid="uid")
            with self.assertRaisesRegex(AttemptError, "launch_already_claimed"):
                run.queued_launch(None, config, None, None, 0, name="proof", uid="uid")
            drive.assert_called_once()
        with closing(self.queue.connect()) as db:
            self.assertEqual(db.execute("SELECT phase,reason FROM launches").fetchone(),
                             ("recovery_required", "serial_timeout"))
