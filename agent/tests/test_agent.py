import json
from agent.patchbot_agent import (
    collect_host_inventory,
    parse_apt_simulation,
)


def test_parse_apt_simulation_distinguishes_security_pocket():
    sample = (
        "Inst libssl3t64 [3.0.11-1] (3.0.14-1~deb12u1 Debian-Security:12/stable-security [amd64])\n"
        "Inst curl [7.88.1-10] (7.88.1-10+deb12u5 Debian:12.6/stable [amd64])\n"
    )
    pkgs = parse_apt_simulation(sample)
    assert pkgs == [
        {
            "name": "libssl3t64",
            "installed_version": "3.0.11-1",
            "candidate_version": "3.0.14-1~deb12u1",
            "is_security_update": True,
            "source_pocket": "stable-security",
        },
        {
            "name": "curl",
            "installed_version": "7.88.1-10",
            "candidate_version": "7.88.1-10+deb12u5",
            "is_security_update": False,
            "source_pocket": "stable",
        },
    ]


def test_collect_host_inventory_gathers_os_packages_and_containers(tmp_path, monkeypatch):
    import agent.patchbot_agent as agent_mod

    checkout = tmp_path / "plausible"
    checkout.mkdir()
    # git status runs as the checkout's owner, never as root
    monkeypatch.setattr(agent_mod, "_dir_owner", lambda path: (1000, 1000, "deploy"))
    os_release = tmp_path / "os-release"
    os_release.write_text('ID=debian\nVERSION_ID="12"\n')
    reboot_flag = tmp_path / "reboot-required"
    reboot_flag.write_text("*** System restart required ***\n")

    inspect_payload = [
        {
            "Id": "abc123def456",
            "Name": "/plausible-1",
            "Image": "sha256:img999",
            "State": {"Status": "running"},
            "Config": {
                "Image": "ghcr.io/plausible/community-edition:v2.1.0",
                "Labels": {
                    "org.opencontainers.image.title": "Plausible CE",
                    "org.opencontainers.image.revision": "deadbeef",
                    "com.docker.compose.project.working_dir": str(checkout),
                    "com.docker.compose.service": "plausible",
                },
            },
        }
    ]
    image_inspect_payload = [
        {
            "Id": "sha256:img999",
            "RepoDigests": ["ghcr.io/plausible/community-edition@sha256:111222"],
        }
    ]

    def fake_runner(cmd, cwd=None):
        if cmd[:2] == ["apt-get", "-s"]:
            return (
                0,
                "Inst openssl [3.0.11-1] (3.0.14-1~deb12u1 Debian-Security:12/stable-security [amd64])\n",
                "",
            )
        if cmd[:2] == ["docker", "ps"]:
            return (0, "abc123def456\n", "")
        if cmd[:3] == ["docker", "inspect", "abc123def456"]:
            return (0, json.dumps(inspect_payload), "")
        if cmd[:3] == ["docker", "image", "inspect"]:
            return (0, json.dumps(image_inspect_payload), "")
        if cmd[:4] == ["runuser", "-u", "deploy", "--"] and "status" in cmd:
            return (0, "", "")
        return (0, "", "")

    inv = collect_host_inventory(
        runner=fake_runner,
        os_release_path=os_release,
        reboot_required_path=reboot_flag,
    )
    assert inv["os_distro"] == "debian"
    assert inv["os_version"] == "12"
    assert inv["reboot_required"] is True
    assert len(inv["packages"]) == 1
    assert inv["packages"][0]["name"] == "openssl"
    assert inv["packages"][0]["is_security_update"] is True
    assert len(inv["containers"]) == 1
    c = inv["containers"][0]
    assert c["name"] == "plausible-1"
    assert c["image_tag"] == "ghcr.io/plausible/community-edition:v2.1.0"
    assert c["repo_digests"] == ["ghcr.io/plausible/community-edition@sha256:111222"]
    assert c["working_dir"] == str(checkout)
    assert c["compose_service"] == "plausible"
    assert c["git_clean"] is True


def test_default_runner_catches_os_error_and_returns_127():
    from agent.patchbot_agent import default_runner

    rc, out, err = default_runner(["/nonexistent-patchbot-binary-xyz"])
    assert rc == 127
    assert out == ""
    assert err != ""


