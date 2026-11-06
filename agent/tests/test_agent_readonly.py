import agent.patchbot_agent as agent_mod


def test_agent_has_no_mutating_entrypoints():
    for name in (
        "ALLOWED_ACTION_TYPES",
        "dispatch_agent_job",
        "execute_compose_update",
        "run_precheck",
        "validate_opt_workdir",
    ):
        assert not hasattr(agent_mod, name), name


def test_main_only_posts_report_and_ignores_response(monkeypatch):
    calls = []

    def fake_http_json(url, method="GET", token="", payload=None):
        calls.append((method, url))
        # A compromised or legacy server answering with a job must be ignored.
        return {"id": "job-1", "action_type": "host_reboot", "payload": {}}

    monkeypatch.setattr(agent_mod, "_http_json", fake_http_json)
    monkeypatch.setattr(agent_mod, "collect_host_inventory", lambda runner=None: {"packages": [], "containers": []})

    rc = agent_mod.main(["--server-url", "https://patchbot.example", "--token", "t", "--hostname", "h1"])

    assert rc == 0
    assert calls == [("POST", "https://patchbot.example/api/agent/report/")]
