from pathlib import Path
from types import SimpleNamespace

import pytest

from research.sandbox import TOOLS, SandboxTools, ToolRejected, build_sandbox_command, run_patch_loop
from testing.factories import make_finding


def test_sandbox_command_has_no_secrets_and_restricted_network():
    cmd = build_sandbox_command(Path("/var/patchbot/wt/abc"), image="patchbot-sandbox:node22", name="pb-1")
    joined = " ".join(cmd)
    assert "--network=patchbot-sandbox-egress" in cmd
    assert "--cap-drop=ALL" in cmd
    assert "--security-opt=no-new-privileges" in cmd
    assert "--read-only" in cmd
    assert "/var/patchbot/wt/abc:/work:rw" in joined
    for forbidden in ("ANTHROPIC", "GITHUB", "AWS_", "SLACK", "/var/run/docker.sock", "--privileged", "-e "):
        assert forbidden not in joined


class FakeExec:
    def __init__(self):
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        return (0, "ok", "")


def tools_for(root, allowed=(["npm", "test"],), exec_=None):
    return SandboxTools(root=root, exec_in_sandbox=exec_ or FakeExec(), allowed_commands=[list(a) for a in allowed])


def test_file_tools_are_confined_to_the_worktree(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/a.ts").write_text("old\n")
    tools = tools_for(tmp_path)
    assert tools.dispatch("read_file", {"path": "src/a.ts"}) == "old\n"
    tools.dispatch("write_file", {"path": "src/a.ts", "content": "new\n"})
    assert (tmp_path / "src/a.ts").read_text() == "new\n"
    for bad in ("../../etc/passwd", "/etc/hosts", ".git/config", "src/../../x"):
        with pytest.raises(ToolRejected):
            tools.dispatch("read_file", {"path": bad})
    with pytest.raises(ToolRejected):
        tools.dispatch("write_file", {"path": ".github/workflows/ci.yml", "content": "x"})


def test_symlink_escape_is_rejected(tmp_path):
    outside = tmp_path.parent / "outside-secret.txt"
    outside.write_text("secret")
    (tmp_path / "link").symlink_to(outside)
    with pytest.raises(ToolRejected):
        tools_for(tmp_path).dispatch("read_file", {"path": "link"})


def test_only_allowlisted_commands_run(tmp_path):
    exec_ = FakeExec()
    tools = tools_for(tmp_path, allowed=(["npm", "test"], ["npm", "ci", "--ignore-scripts"]), exec_=exec_)
    tools.dispatch("run_command", {"argv": ["npm", "test"]})
    for argv in (["curl", "https://evil.example"], ["npm", "test", "&&", "rm", "-rf", "/"], ["npm", "ci"]):
        with pytest.raises(ToolRejected):
            tools.dispatch("run_command", {"argv": argv})
    assert exec_.calls == [["npm", "test"]]


def test_tool_definitions_are_strict():
    assert {t["name"] for t in TOOLS} == {"read_file", "write_file", "list_dir", "run_command"}
    assert all(t["strict"] is True and t["input_schema"]["additionalProperties"] is False for t in TOOLS)


class ScriptedLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        return self.responses.pop(0)


def tool_use(id_, name, input_):
    return SimpleNamespace(type="tool_use", id=id_, name=name, input=input_)


def response(blocks, stop_reason):
    return SimpleNamespace(content=blocks, stop_reason=stop_reason, stop_details=None)


@pytest.mark.django_db
def test_patch_loop_executes_tools_and_returns_results(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/a.ts").write_text("template(x)\n")
    llm = ScriptedLLM([
        response([tool_use("t1", "write_file", {"path": "src/a.ts", "content": "safeTemplate(x)\n"}),
                  tool_use("t2", "read_file", {"path": "../secret"})], "tool_use"),
        response([SimpleNamespace(type="text", text="Fertig.")], "end_turn"),
    ])
    result = run_patch_loop(make_finding(package_name="lodash"), client=llm, tools=tools_for(tmp_path))
    assert result.status == "DONE"
    assert (tmp_path / "src/a.ts").read_text() == "safeTemplate(x)\n"
    results = llm.calls[1]["messages"][-1]["content"]
    assert [r["tool_use_id"] for r in results] == ["t1", "t2"]
    assert results[1]["is_error"] is True
    assert "tool_choice" not in llm.calls[0]


@pytest.mark.django_db
def test_patch_loop_stops_at_iteration_limit(tmp_path):
    loop_forever = [response([tool_use(f"t{i}", "list_dir", {"path": "."})], "tool_use") for i in range(5)]
    result = run_patch_loop(make_finding(), client=ScriptedLLM(loop_forever), tools=tools_for(tmp_path), max_iterations=3)
    assert result.status == "LIMIT"


@pytest.mark.django_db
def test_patch_loop_refusal_is_reported(tmp_path):
    result = run_patch_loop(make_finding(), client=ScriptedLLM([response([], "refusal")]), tools=tools_for(tmp_path))
    assert result.status == "REFUSED"
