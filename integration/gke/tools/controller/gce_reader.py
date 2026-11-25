"""Read the selected GCP resources using the private controller's attached identity."""
from contextlib import closing
import http.client
import json
import re
import time

from attempt_driver import require

COMPUTE = "compute.googleapis.com"
PROJECTS = "cloudresourcemanager.googleapis.com"
LABEL = re.compile(r"[a-z][a-z0-9-]{0,61}[a-z0-9]|[a-z]")


def read(connection, path, headers, limit):
    with closing(connection):
        connection.request("GET", path, headers=headers)
        with connection.getresponse() as response:
            require(response.status == 200, f"gce_read_http_{response.status}")
            raw = response.read(limit + 1)
            require(0 < len(raw) <= limit, "gce_read_size")
            return raw


def timeout(deadline):
    remaining = min(8, deadline - time.monotonic())
    require(remaining > 0, "controller_deadline")
    return remaining


class GceReader:
    def __init__(self, project, zone, email, deadline):
        require(LABEL.fullmatch(project) and LABEL.fullmatch(zone)
                and isinstance(email, str) and re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]@"
                     + re.escape(project) + r"\.iam\.gserviceaccount\.com", email), "gce_read_identity")
        self.project, self.zone = project, zone
        self._token = None
        self._expires = 0
        require(self.metadata("project/project-id", deadline).decode() == project
                and self.metadata("instance/zone", deadline).decode().rsplit("/", 1)[-1] == zone
                and self.metadata("instance/service-accounts/default/email", deadline).decode() == email,
                "gce_read_identity")

    @staticmethod
    def metadata(key, deadline):
        require(key in ("project/project-id", "instance/zone", "instance/service-accounts/default/email",
                        "instance/service-accounts/default/token"), "gce_read_metadata")
        return read(http.client.HTTPConnection("169.254.169.254", timeout=timeout(deadline)),
                    "/computeMetadata/v1/" + key, {"Metadata-Flavor": "Google"}, 8192)

    def authorization(self, deadline):
        if time.monotonic() >= self._expires:
            credential = json.loads(self.metadata("instance/service-accounts/default/token", deadline))
            require(credential.get("token_type") == "Bearer" and type(credential.get("expires_in")) is int
                    and credential["expires_in"] > 0 and isinstance(credential.get("access_token"), str)
                    and bool(credential["access_token"]), "gce_read_credential")
            self._token = credential["access_token"]
            self._expires = time.monotonic() + max(0, credential["expires_in"] - 30)
        return {"Authorization": "Bearer " + self._token}

    def _get(self, host, path, deadline):
        require(host in (COMPUTE, PROJECTS), "gce_read_endpoint")
        headers = self.authorization(deadline)
        # These two Google hosts and the metadata server are fixed. http.client
        # never follows redirects or takes proxy settings from the environment.
        return json.loads(read(http.client.HTTPSConnection(host, timeout=timeout(deadline)), path,
                               headers, 4 << 20))

    def project_number(self, deadline):
        return self._get(PROJECTS, "/v1/projects/" + self.project, deadline)["projectNumber"]

    def image(self, name, deadline):
        require(LABEL.fullmatch(name), "compute_name")
        return self._get(COMPUTE, f"/compute/v1/projects/{self.project}/global/images/{name}", deadline)

    def zonal(self, resource, name, deadline):
        require(resource in ("instances", "disks") and LABEL.fullmatch(name), "compute_name")
        return self._get(COMPUTE, f"/compute/v1/projects/{self.project}/zones/{self.zone}/{resource}/{name}", deadline)

    def serial_output(self, instance, deadline):
        require(LABEL.fullmatch(instance), "compute_name")
        return self._get(COMPUTE,
            f"/compute/v1/projects/{self.project}/zones/{self.zone}/instances/{instance}/serialPort?port=1",
            deadline)["contents"]
