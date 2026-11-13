import json
import os

import pytest

import agent.patchbot_agent as agent_mod
from agent.patchbot_agent import AGENT_VERSION, collect_host_inventory, read_git_head

SHA = "f00dfeed" * 5
_REAL_DIR_OWNER = agent_mod._dir_owner

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
DPKG = (
    "openssl\t3.0.13-0ubuntu3.4\tinstalled\n"
    "libc6\t2.39-0ubuntu8.3\tinstalled\n"
    # removed without --purge ("rc"): only config files are left, the package is not installed
    "nginx\t1.24.0-2ubuntu7\tconfig-files\n"
)

READ_ONLY_PREFIXES = [
    ["uname", "-r"],
    ["dpkg-query", "-W"],
    ["apt-get", "-s", "dist-upgrade"],
    ["docker", "ps"],
    ["docker", "inspect"],
    ["docker", "image", "inspect"],
]


GIT_STATUS_AS_OWNER = [
    "runuser", "-u", "deploy", "--",
    # Neutral, empty environment: under ProtectHome=true the owner's $HOME is masked, and the root-only
    # agent environment (PATCHBOT_TOKEN) must never reach a process that runs the owner's repo config.
    "env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/nonexistent", "XDG_CONFIG_HOME=/nonexistent",
    "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "LC_ALL=C",
    "git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "--no-optional-locks",
    "status", "--porcelain",
]


class FakeRunner:
    def __init__(self, working_dir):
        self.calls = []
        self.working_dir = str(working_dir)

    def __call__(self, argv, cwd=None):
        self.calls.append(list(argv))
        if argv[0] in ("git", "runuser", "setpriv"):
            return (0, "", "")
        table = [
            (["uname", "-r"], "6.8.0-48-generic\n"),
            (["dpkg-query"], DPKG),
            (["apt-get"], APT),
            (["docker", "ps"], "c1\n"),
            (["docker", "inspect"], json.dumps(_inspect(self.working_dir))),
            (["docker", "image", "inspect"], json.dumps(IMAGE)),
        ]
        for prefix, out in table:
            if list(argv[: len(prefix)]) == prefix:
                return (0, out, "")
        return (1, "", "unexpected command")


def _inspect(working_dir):
    data = json.loads(json.dumps(INSPECT))
    data[0]["Config"]["Labels"]["com.docker.compose.project.working_dir"] = working_dir
    return data


def _checkout(tmp_path, head="ref: refs/heads/main\n"):
    root = tmp_path / "opt-mdb"
    (root / ".git" / "refs" / "heads").mkdir(parents=True)
    (root / ".git" / "HEAD").write_text(head)
    (root / ".git" / "refs" / "heads" / "main").write_text(SHA + "\n")
    return root


@pytest.fixture(autouse=True)
def deploy_owner(monkeypatch):
    """Checkouts under /opt belong to a deploy user; the agent itself runs as root."""
    monkeypatch.setattr(agent_mod, "_dir_owner", lambda path: (1000, 1000, "deploy"))


@pytest.fixture(autouse=True)
def checkout_root(tmp_path, monkeypatch):
    """Production only inspects compose checkouts below /opt; tests place them below tmp_path instead."""
    root = os.path.realpath(str(tmp_path))
    monkeypatch.setattr(agent_mod, "CHECKOUT_ROOT", root)
    return root


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
    inv = _collect(tmp_path, FakeRunner(_checkout(tmp_path)))
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
    assert "nginx" not in by_name  # dpkg status "config-files" (rc) is not installed


def test_dpkg_query_asks_for_the_package_status():
    calls = []

    def runner(argv, cwd=None):
        calls.append(argv)
        return (0, DPKG + "half\t1.0\thalf-installed\nbroken-line\n", "")

    assert agent_mod._installed_packages(runner) == {"openssl": "3.0.13-0ubuntu3.4", "libc6": "2.39-0ubuntu8.3"}
    assert calls == [["dpkg-query", "-W", "-f=${Package}\t${Version}\t${db:Status-Status}\n"]]


def test_missing_apt_stamp_reports_empty_timestamp(tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
    inv = collect_host_inventory(
        runner=FakeRunner(_checkout(tmp_path)),
        os_release_path=os_release,
        reboot_required_path=tmp_path / "no-reboot",
        apt_stamp_paths=(tmp_path / "missing",),
    )
    assert inv["apt_lists_updated_at"] == ""


def test_collects_v2_container_fields(tmp_path):
    runner = FakeRunner(_checkout(tmp_path))
    container = _collect(tmp_path, runner)["containers"][0]
    assert container["oci_source"] == "https://github.com/westcoder/materialdatenbank"
    assert container["oci_revision"] == "abc123"
    assert container["image_created_at"] == "2026-11-04T09:15:00.123456789Z"
    assert container["git_head_sha"] == SHA  # read from .git/HEAD + refs, git is not executed for it
    assert container["git_clean"] is True
    assert GIT_STATUS_AS_OWNER in runner.calls


def _is_read_only(argv):
    # git only ever runs as the checkout owner, with fsmonitor/hooks disabled and without index writes.
    if argv[0] in ("git", "runuser", "setpriv"):
        return argv == GIT_STATUS_AS_OWNER
    return any(argv[: len(p)] == p for p in READ_ONLY_PREFIXES)


def test_every_subprocess_call_is_read_only(tmp_path):
    runner = FakeRunner(_checkout(tmp_path))
    _collect(tmp_path, runner)
    assert runner.calls
    assert all(_is_read_only(c) for c in runner.calls), runner.calls


def test_git_is_never_run_as_root_in_a_root_owned_checkout(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_mod, "_dir_owner", lambda path: (0, 0, "root"))
    runner = FakeRunner(_checkout(tmp_path))
    container = _collect(tmp_path, runner)["containers"][0]
    assert container["git_clean"] is None
    assert container["git_head_sha"] == SHA
    assert not [c for c in runner.calls if "git" in c]


@pytest.mark.parametrize("working_dir", ["/", "/etc", "/home/deploy/app", "relative/app"])
def test_working_dir_outside_checkout_root_is_not_inspected(tmp_path, working_dir):
    runner = FakeRunner(working_dir)
    container = _collect(tmp_path, runner)["containers"][0]
    assert container["working_dir"] == working_dir  # still reported for asset matching
    assert container["git_clean"] is None
    assert container["git_head_sha"] == ""
    assert not [c for c in runner.calls if "runuser" in c or "git" in c]


def test_working_dir_escaping_checkout_root_via_symlink_or_dotdot_is_not_inspected(tmp_path, checkout_root):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    (outside / ".git" / "refs" / "heads").mkdir(parents=True)
    (outside / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (outside / ".git" / "refs" / "heads" / "main").write_text(SHA + "\n")
    link = tmp_path / "app"
    link.symlink_to(outside)
    for working_dir in (str(link), os.path.join(checkout_root, "..", outside.name), checkout_root):
        runner = FakeRunner(working_dir)
        container = _collect(tmp_path, runner)["containers"][0]
        assert container["git_head_sha"] == "", working_dir
        assert container["git_clean"] is None, working_dir
        assert not [c for c in runner.calls if "runuser" in c], working_dir


def test_unknown_owner_skips_git_clean(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_mod, "_dir_owner", lambda path: None)
    runner = FakeRunner(_checkout(tmp_path))
    assert _collect(tmp_path, runner)["containers"][0]["git_clean"] is None
    assert not [c for c in runner.calls if "git" in c]


def test_dir_owner_reports_uid_gid_and_name(tmp_path):
    import pwd

    st = os.stat(tmp_path)
    assert _REAL_DIR_OWNER(str(tmp_path)) == (st.st_uid, st.st_gid, pwd.getpwuid(st.st_uid).pw_name)
    assert _REAL_DIR_OWNER(str(tmp_path / "missing")) is None


# --- read_git_head: parse HEAD without executing git as root ---------------------------------------------


def test_head_follows_loose_ref(tmp_path):
    assert read_git_head(str(_checkout(tmp_path))) == SHA


def test_head_detached(tmp_path):
    root = _checkout(tmp_path, head=SHA + "\n")
    assert read_git_head(str(root)) == SHA


def test_head_follows_packed_refs(tmp_path):
    root = _checkout(tmp_path, head="ref: refs/heads/release\n")
    other = "ab" * 20
    (root / ".git" / "packed-refs").write_text(
        f"# pack-refs with: peeled fully-peeled sorted\n{SHA} refs/heads/main\n{other} refs/heads/release\n^{SHA}\n"
    )
    assert read_git_head(str(root)) == other


def test_head_missing_ref_or_garbage_is_empty(tmp_path):
    assert read_git_head(str(_checkout(tmp_path, head="ref: refs/heads/nope\n"))) == ""
    assert read_git_head(str(tmp_path / "no-checkout")) == ""


def test_head_rejects_ref_path_traversal(tmp_path):
    root = _checkout(tmp_path, head="ref: refs/../../../outside\n")
    (tmp_path / "outside").write_text(SHA + "\n")
    assert read_git_head(str(root)) == ""


def test_head_via_gitdir_file_inside_checkout(tmp_path):
    root = tmp_path / "app"
    real = root / ".gitstore"
    (real / "refs" / "heads").mkdir(parents=True)
    (real / "HEAD").write_text("ref: refs/heads/main\n")
    (real / "refs" / "heads" / "main").write_text(SHA + "\n")
    (root / ".git").write_text("gitdir: .gitstore\n")
    assert read_git_head(str(root)) == SHA


def test_head_via_gitdir_file_pointing_outside_checkout_is_ignored(tmp_path):
    outside = tmp_path / "elsewhere.git"
    (outside / "refs" / "heads").mkdir(parents=True)
    (outside / "HEAD").write_text("ref: refs/heads/main\n")
    (outside / "refs" / "heads" / "main").write_text(SHA + "\n")
    root = tmp_path / "app"
    root.mkdir()
    (root / ".git").write_text(f"gitdir: {outside}\n")
    assert read_git_head(str(root)) == ""


def test_head_symlink_escaping_checkout_is_ignored(tmp_path):
    secret = tmp_path / "root-only"
    secret.write_text(SHA + "\n")
    root = _checkout(tmp_path)
    (root / ".git" / "refs" / "heads" / "main").unlink()
    (root / ".git" / "refs" / "heads" / "main").symlink_to(secret)
    assert read_git_head(str(root)) == ""


def test_head_fifo_does_not_block(tmp_path):
    root = _checkout(tmp_path)
    (root / ".git" / "HEAD").unlink()
    os.mkfifo(root / ".git" / "HEAD")
    assert read_git_head(str(root)) == ""
