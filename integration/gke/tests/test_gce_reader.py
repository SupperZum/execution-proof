import json
import time
import unittest
from unittest.mock import patch

from attempt_driver import AttemptError
import gce_reader


class GceReaderTests(unittest.TestCase):
    def setUp(self):
        self.project = "onboarding-example"
        self.zone = "us-central1-a"
        self.email = "controller@" + self.project + ".iam.gserviceaccount.com"
        self.values = {"project/project-id": self.project, "instance/zone": "projects/1/zones/" + self.zone,
                       "instance/service-accounts/default/email": self.email,
                       "instance/service-accounts/default/token": json.dumps(
                           {"access_token": "test-only", "token_type": "Bearer", "expires_in": 60})}
        self.deadline = time.monotonic() + 10

    def test_reads_are_bound_to_identity_and_google_endpoint(self):
        with patch.object(gce_reader.GceReader, "metadata", side_effect=lambda k, _: self.values[k].encode()):
            reader = gce_reader.GceReader(self.project, self.zone, self.email, self.deadline)
            with patch.object(gce_reader.http.client, "HTTPSConnection") as connect:
                response = connect.return_value.getresponse.return_value.__enter__.return_value
                response.status = 200
                response.read.return_value = b'{"projectNumber":"17"}'
                self.assertEqual(reader.project_number(self.deadline), "17")
                self.assertEqual(connect.call_args.args[0], "cloudresourcemanager.googleapis.com")
                response.status = 302
                with self.assertRaisesRegex(AttemptError, "gce_read_http_302"):
                    reader.image("proof-image", self.deadline)
                with self.assertRaisesRegex(AttemptError, "gce_read_endpoint"):
                    reader._get("foreign.example", "/", self.deadline)
                with self.assertRaisesRegex(AttemptError, "compute_name"):
                    reader.zonal("instances", "../other", self.deadline)
                self.assertEqual(connect.call_count, 2)
            self.values["instance/service-accounts/default/email"] = "other@" + self.project + ".iam.gserviceaccount.com"
            with self.assertRaisesRegex(AttemptError, "gce_read_identity"):
                gce_reader.GceReader(self.project, self.zone, self.email, self.deadline)
