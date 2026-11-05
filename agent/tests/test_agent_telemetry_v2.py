import json
from agent.patchbot_agent import AGENT_VERSION, collect_host_inventory

INSPECT = [{
    "Id": "c1", "Name": "/mdb-app", "Image": "sha256:img1", "State": {"Status": "running"},
    "Config": {
        "Image": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/materialdatenbank:main",
        "Labels": {
            "org.opencontainers.image.revision": "abc123",
            "org.opencontainers.image.source": "https://github.com/westcoder/materialdatenbank",
            "com.docker.compose.project.working_dir": "/opt/mdb",
            "com.docker.compose.service": "app",
        },
    },
}]
IMAGE = [{
    "RepoDigests": ["123456789012.dkr.ecr.eu-central-1.amazonaws.com/materialdatenbank@sha256:d1"],
    "Created": "2026-11-04T09:15:00.123456789Z",
}]
APT = "Inst openssl [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-security [amd64])\n"
DPKG = "openssl\t3.0.13-0ubuntu3.4\nlibc6\t2.39-0ubuntu8.3\n"

READ_ONLY_PREFIXES = [
    ["uname", "-r"],
    ["dpkg-query", "-W"],
    ["apt-get", "-s", "dist-upgrade"],
    ["docker", "ps"],
    ["docker", "inspect"],
    ["docker", "image", "inspect"],
]


class FakeRunner:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, cwd=None):
        self.calls.append(list(argv))
        if argv[0] == "git":
            return (0, "" if "status" in argv else "f00dfeed\n", "")
        table = [
            (["uname", "-r"], "6.8.0-48-generic\n"),
            (["dpkg-query"], DPKG),
            (["apt-get"], APT),
            (["docker", "ps"], "c1\n"),
            (["docker", "inspect"], json.dumps(INSPECT)),
            (["docker", "image", "inspect"], json.dumps(IMAGE)),
        ]
        for prefix, out in table:
            if list(argv[: len(prefix)]) == prefix:
                return (0, out, "")
        return (1, "", "unexpected command")


def _collect(tmp_path, runner):
    os_release = tmp_path / "os-release"
    os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
    stamp = tmp_path / "update-success-stamp"
    stamp.write_text("")
    return collect_host_inventory(
        runner=runner,
        os_release_path=os_release,
        reboot_required_path=tmp_path / "no-reboot",
        apt_stamp_paths=(stamp,),
    )


def test_collects_v2_host_fields(tmp_path):
    inv = _collect(tmp_path, FakeRunner())
    assert inv["kernel_version"] == "6.8.0-48-generic"
    assert inv["agent_version"] == AGENT_VERSION
    assert inv["apt_lists_updated_at"].endswith("+00:00")
    by_name = {p["name"]: p for p in inv["packages"]}
    assert by_name["openssl"] == {
        "name": "openssl",
        "installed_version": "3.0.13-0ubuntu3.4",
        "candidate_version": "3.0.13-0ubuntu3.5",
        "is_security_update": True,
        "source_pocket": "noble-security",
    }
    assert by_name["libc6"]["candidate_version"] == ""
    assert by_name["libc6"]["is_security_update"] is False


def test_missing_apt_stamp_reports_empty_timestamp(tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
    inv = collect_host_inventory(
        runner=FakeRunner(),
        os_release_path=os_release,
        reboot_required_path=tmp_path / "no-reboot",
        apt_stamp_paths=(tmp_path / "missing",),
    )
    assert inv["apt_lists_updated_at"] == ""


def test_collects_v2_container_fields(tmp_path):
    runner = FakeRunner()
    container = _collect(tmp_path, runner)["containers"][0]
    assert container["oci_source"] == "https://github.com/westcoder/materialdatenbank"
    assert container["oci_revision"] == "abc123"
    assert container["image_created_at"] == "2026-11-04T09:15:00.123456789Z"
    assert container["git_head_sha"] == "f00dfeed"
    assert container["git_clean"] is True
    assert ["git", "-c", "safe.directory=/opt/mdb", "rev-parse", "HEAD"] in runner.calls


def _is_read_only(argv):
    if argv[0] == "git":
        return (
            argv[1] == "-c"
            and argv[2].startswith("safe.directory=")
            and argv[3:] in (["rev-parse", "HEAD"], ["status", "--porcelain"])
        )
    return any(argv[: len(p)] == p for p in READ_ONLY_PREFIXES)


def test_every_subprocess_call_is_read_only(tmp_path):
    runner = FakeRunner()
    _collect(tmp_path, runner)
    assert runner.calls
    assert all(_is_read_only(c) for c in runner.calls), runner.calls
