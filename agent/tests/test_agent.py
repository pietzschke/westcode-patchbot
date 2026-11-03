import json
from pathlib import Path
import pytest
from agent.patchbot_agent import (
    collect_host_inventory,
    dispatch_agent_job,
    execute_compose_update,
    main,
    parse_apt_simulation,
    run_precheck,
    validate_opt_workdir,
)


def test_validate_opt_workdir_rejects_traversal(tmp_path):
    opt = tmp_path / "opt"
    (opt / "plausible").mkdir(parents=True)
    assert validate_opt_workdir(str(opt / "plausible"), allowed_root=opt) == (opt / "plausible").resolve()

    with pytest.raises(ValueError, match="outside allowed root"):
        validate_opt_workdir(str(opt / "../etc"), allowed_root=opt)


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
        },
        {
            "name": "curl",
            "installed_version": "7.88.1-10",
            "candidate_version": "7.88.1-10+deb12u5",
            "is_security_update": False,
        },
    ]


def test_run_precheck_blocks_dirty_git_tree(tmp_path):
    opt = tmp_path / "opt"
    svc = opt / "plausible"
    svc.mkdir(parents=True)
    (svc / "compose.yaml").write_text("services:\n  plausible:\n    image: plausible/analytics:v2.1.0\n")

    def dirty_runner(cmd, cwd=None):
        if cmd[:2] == ["git", "status"]:
            return (0, " M compose.yaml\n", "")
        return (0, "", "")

    res = run_precheck(str(svc), "plausible/analytics:v2.1.2", runner=dirty_runner, allowed_root=opt)
    assert res["ok"] is False
    assert res["git_clean"] is False
    assert "uncommitted" in res["reason"]


def test_execute_compose_update_refuses_dirty_git_tree_before_docker(tmp_path):
    opt = tmp_path / "opt"
    svc = opt / "plausible"
    svc.mkdir(parents=True)
    compose_file = svc / "compose.yaml"
    original = "services:\n  plausible:\n    image: plausible/analytics:v2.1.0\n"
    compose_file.write_text(original)
    docker_calls = []

    def dirty_runner(cmd, cwd=None):
        if cmd[0] == "docker":
            docker_calls.append(cmd)
        if cmd[:2] == ["git", "status"]:
            return (0, " M compose.yaml\n", "")
        return (0, "", "")

    result = execute_compose_update(
        working_dir=str(svc),
        service="plausible",
        target_image="plausible/analytics:v2.1.2",
        healthcheck_url=None,
        runner=dirty_runner,
        allowed_root=opt,
        timeout_sec=1,
    )
    assert result["status"] == "failed"
    assert "uncommitted" in result["logs"]
    assert docker_calls == []
    assert compose_file.read_text() == original



def test_execute_compose_update_rolls_back_on_failed_healthcheck(tmp_path):
    opt = tmp_path / "opt"
    svc = opt / "plausible"
    svc.mkdir(parents=True)
    compose_file = svc / "compose.yaml"
    compose_file.write_text("services:\n  plausible:\n    image: plausible/analytics:v2.1.0\n")
    calls = []

    def fake_runner(cmd, cwd=None):
        calls.append(cmd)
        if cmd[:3] == ["docker", "compose", "images"]:
            return (0, "sha256:old111\n", "")
        if cmd[:3] == ["docker", "compose", "logs"]:
            return (0, "DB migration failed\n", "")
        return (0, "", "")

    result = execute_compose_update(
        working_dir=str(svc),
        service="plausible",
        target_image="plausible/analytics:v2.1.2",
        healthcheck_url="http://127.0.0.1:59999/api/health",
        runner=fake_runner,
        allowed_root=opt,
        timeout_sec=1,
    )
    assert result["status"] == "rolled_back"
    assert result["prev_image_id"] == "sha256:old111"
    assert "plausible/analytics:v2.1.0" in compose_file.read_text()
    assert "DB migration failed" in result["logs"]


def test_execute_compose_update_succeeds_when_container_healthy(tmp_path):
    opt = tmp_path / "opt"
    svc = opt / "plausible"
    svc.mkdir(parents=True)
    compose_file = svc / "compose.yaml"
    compose_file.write_text("services:\n  plausible:\n    image: plausible/analytics:v2.1.0\n")
    image_calls = 0

    def fake_runner(cmd, cwd=None):
        nonlocal image_calls
        if cmd[:3] == ["docker", "compose", "images"]:
            image_calls += 1
            return (0, "sha256:old111\n" if image_calls == 1 else "sha256:new222\n", "")
        if cmd[:3] == ["docker", "compose", "ps"]:
            return (0, json.dumps({"State": "running", "Health": "healthy"}) + "\n", "")
        return (0, "", "")

    result = execute_compose_update(
        working_dir=str(svc),
        service="plausible",
        target_image="plausible/analytics:v2.1.2",
        healthcheck_url=None,
        runner=fake_runner,
        allowed_root=opt,
        timeout_sec=2,
    )
    assert result["status"] == "succeeded"
    assert result["prev_image_id"] == "sha256:old111"
    assert result["new_image_id"] == "sha256:new222"
    assert "plausible/analytics:v2.1.2" in compose_file.read_text()


def test_collect_host_inventory_gathers_os_packages_and_containers(tmp_path):
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
                    "com.docker.compose.project.working_dir": "/opt/plausible",
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
        if cmd[:2] == ["git", "status"]:
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
    assert c["working_dir"] == "/opt/plausible"
    assert c["compose_service"] == "plausible"
    assert c["git_clean"] is True


def test_dispatch_agent_job_enforces_action_enum(tmp_path):
    opt = tmp_path / "opt"
    svc = opt / "plausible"
    svc.mkdir(parents=True)
    (svc / "compose.yaml").write_text("services:\n  plausible:\n    image: plausible/analytics:v2.1.0\n")

    def fake_runner(cmd, cwd=None):
        return (0, "", "")

    res = dispatch_agent_job(
        {
            "action_type": "precheck",
            "payload": {"working_dir": str(svc), "target_image": "plausible/analytics:v2.1.2"},
        },
        runner=fake_runner,
        allowed_root=opt,
    )
    assert res["ok"] is True

    with pytest.raises(ValueError, match="Unsupported action_type"):
        dispatch_agent_job({"action_type": "shell_exec", "payload": {"cmd": "id"}}, runner=fake_runner, allowed_root=opt)


def test_main_cli_reports_inventory_polls_next_job_and_posts_result(monkeypatch, tmp_path):
    opt = tmp_path / "opt"
    svc = opt / "plausible"
    svc.mkdir(parents=True)
    (svc / "compose.yaml").write_text("services:\n  plausible:\n    image: plausible/analytics:v2.1.0\n")

    monkeypatch.setenv("PATCHBOT_URL", "https://patch.westcode.de")
    monkeypatch.setenv("PATCHBOT_TOKEN", "secret-host-token")
    monkeypatch.setenv("PATCHBOT_HOSTNAME", "c2.westcode.de")
    monkeypatch.setenv("PATCHBOT_ALLOWED_ROOT", str(opt))

    monkeypatch.setattr(
        "agent.patchbot_agent.collect_host_inventory",
        lambda **kwargs: {
            "os_distro": "debian",
            "os_version": "13",
            "reboot_required": False,
            "packages": [],
            "containers": [],
        },
    )
    monkeypatch.setattr("agent.patchbot_agent.default_runner", lambda cmd, cwd=None: (0, "", ""))

    http_calls = []

    def fake_http_json(url, method="GET", token="", payload=None):
        http_calls.append({"url": url, "method": method, "token": token, "payload": payload})
        if url.endswith("/api/agent/report/"):
            return {"status": "ok", "hostname": "c2.westcode.de"}
        if url.endswith("/api/agent/jobs/next/"):
            return {
                "id": "11111111-2222-3333-4444-555555555555",
                "action_type": "precheck",
                "payload": {"working_dir": str(svc), "target_image": "plausible/analytics:v2.1.2"},
            }
        if url.endswith("/api/agent/jobs/11111111-2222-3333-4444-555555555555/result/"):
            return {"status": "SUCCEEDED"}
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr("agent.patchbot_agent._http_json", fake_http_json)

    rc = main([])
    assert rc == 0
    assert len(http_calls) == 3
    assert http_calls[0]["url"] == "https://patch.westcode.de/api/agent/report/"
    assert http_calls[0]["method"] == "POST"
    assert http_calls[0]["token"] == "secret-host-token"
    assert http_calls[0]["payload"]["hostname"] == "c2.westcode.de"

    assert http_calls[1]["url"] == "https://patch.westcode.de/api/agent/jobs/next/"
    assert http_calls[1]["method"] == "GET"

    assert (
        http_calls[2]["url"]
        == "https://patch.westcode.de/api/agent/jobs/11111111-2222-3333-4444-555555555555/result/"
    )
    assert http_calls[2]["method"] == "POST"
    assert http_calls[2]["payload"]["ok"] is True


def test_execute_compose_update_rolls_back_when_docker_compose_ps_is_empty(tmp_path):
    opt = tmp_path / "opt"
    svc = opt / "plausible"
    svc.mkdir(parents=True)
    compose_file = svc / "compose.yaml"
    compose_file.write_text("services:\n  plausible:\n    image: plausible/analytics:v2.1.0\n")

    def empty_ps_runner(cmd, cwd=None):
        if cmd[:3] == ["docker", "compose", "images"]:
            return (0, "sha256:old111\n", "")
        if cmd[:3] == ["docker", "compose", "ps"]:
            return (0, "", "")
        if cmd[:3] == ["docker", "compose", "logs"]:
            return (0, "container exited immediately\n", "")
        return (0, "", "")

    result = execute_compose_update(
        working_dir=str(svc),
        service="plausible",
        target_image="2.1.2",
        healthcheck_url=None,
        runner=empty_ps_runner,
        allowed_root=opt,
        timeout_sec=0,
    )
    assert result["status"] == "rolled_back"
    assert "plausible/analytics:v2.1.0" in compose_file.read_text()
    assert "container exited immediately" in result["logs"]


def test_default_runner_catches_os_error_and_returns_127():
    from agent.patchbot_agent import default_runner

    rc, out, err = default_runner(["/nonexistent-patchbot-binary-xyz"])
    assert rc == 127
    assert out == ""
    assert err != ""


def test_main_catches_dispatch_exception_and_posts_failed_result(monkeypatch, tmp_path):
    opt = tmp_path / "opt"
    opt.mkdir(parents=True)

    monkeypatch.setenv("PATCHBOT_URL", "https://patch.westcode.de")
    monkeypatch.setenv("PATCHBOT_TOKEN", "secret-host-token")
    monkeypatch.setenv("PATCHBOT_HOSTNAME", "c2.westcode.de")
    monkeypatch.setenv("PATCHBOT_ALLOWED_ROOT", str(opt))

    monkeypatch.setattr(
        "agent.patchbot_agent.collect_host_inventory",
        lambda **kwargs: {
            "os_distro": "debian",
            "os_version": "13",
            "reboot_required": False,
            "packages": [],
            "containers": [],
        },
    )

    http_calls = []

    def fake_http_json(url, method="GET", token="", payload=None):
        http_calls.append({"url": url, "method": method, "token": token, "payload": payload})
        if url.endswith("/api/agent/report/"):
            return {"status": "ok"}
        if url.endswith("/api/agent/jobs/next/"):
            return {
                "id": "99999999-2222-3333-4444-555555555555",
                "action_type": "compose_update",
                "payload": {"working_dir": "/etc/passwd", "service": "web", "target_version": "1.0.0"},
            }
        if url.endswith("/api/agent/jobs/99999999-2222-3333-4444-555555555555/result/"):
            return {"status": "FAILED"}
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr("agent.patchbot_agent._http_json", fake_http_json)

    rc = main([])
    assert rc == 0
    assert len(http_calls) == 3
    assert http_calls[2]["payload"]["status"] == "FAILED"
    assert "outside allowed root" in http_calls[2]["payload"]["logs"]


