import re
import shutil
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


def test_sandbox_mounts_worktree_git_pointer_read_only(tmp_path):
    """Code in the sandbox must not be able to repoint /work/.git at an attacker gitdir."""
    (tmp_path / ".git").write_text("gitdir: /var/patchbot/mirrors/x.git/worktrees/abc\n")
    cmd = build_sandbox_command(tmp_path, image="patchbot-sandbox:node22", name="pb-1")
    joined = " ".join(cmd)
    assert f"{tmp_path}:/work:rw" in joined
    assert f"{tmp_path / '.git'}:/work/.git:ro" in joined
    # the read-only overlay must come after the rw worktree mount
    assert joined.index(f"{tmp_path}:/work:rw") < joined.index("/work/.git:ro")


# --- review M-2: python dependency install, symlink races in the file tools, egress proxy ---

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_python_sandbox_can_install_locked_dependencies_without_building_sdists():
    from research.sandbox import ALLOWED_COMMANDS

    python = ALLOWED_COMMANDS["python"]
    installs = [c for c in python if c[0] == "uv"]
    assert ["uv", "sync", "--frozen", "--no-build", "--no-install-workspace"] in installs
    assert ["uv", "pip", "install", "--no-build", "-r", "requirements.txt"] in installs
    assert all("--no-build" in c for c in installs)
    dockerfile = (REPO_ROOT / "deploy" / "sandbox" / "Dockerfile.python312").read_text(encoding="utf-8")
    assert re.search(r"^COPY --from=\S+ /uv /usr/local/bin/uv$", dockerfile, flags=re.MULTILINE)
    # The venv must live on the tmpfs, never in the mounted worktree (it would end up in the diff).
    assert "UV_PROJECT_ENVIRONMENT=/tmp/venv" in dockerfile
    assert "VIRTUAL_ENV=/tmp/venv" in dockerfile
    assert "PATH=/tmp/venv/bin:" in dockerfile
    assert "--system-site-packages" in dockerfile  # the image's pytest stays importable from the venv
    # Docker mounts --tmpfs noexec by default; compiled wheels in /tmp/venv would fail to load.
    cmd = build_sandbox_command(Path("/wt"), image="patchbot-sandbox:python312", name="pb-1")
    tmpfs = cmd[cmd.index("--tmpfs") + 1]
    assert tmpfs.startswith("/tmp:") and "exec" in tmpfs.split(":", 1)[1].split(",")


def test_egress_proxy_denies_plain_http():
    lines = [ln.strip() for ln in (REPO_ROOT / "deploy" / "egress-proxy" / "squid.conf").read_text().splitlines()]
    rules = [ln for ln in lines if ln.startswith("http_access")]
    assert "http_access deny !CONNECT" in rules
    assert rules.index("http_access deny !CONNECT") < rules.index("http_access allow registries")


class RacyTools(SandboxTools):
    """Simulates sandboxed code swapping a path component for a symlink right after the confinement check."""

    def __init__(self, *args, swap, **kwargs):
        super().__init__(*args, **kwargs)
        self.swap = swap

    def _resolve(self, path):
        result = super()._resolve(path)
        self.swap()
        return result


def _racy(root, swap):
    return RacyTools(root=root, exec_in_sandbox=FakeExec(), allowed_commands=[], swap=swap)


@pytest.fixture
def race(tmp_path):
    root, outside = tmp_path / "repo", tmp_path / "outside"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.ts").write_text("old\n")
    outside.mkdir()
    (outside / "a.ts").write_text("worker secret\n")

    def swap_dir():
        shutil.rmtree(root / "src")
        (root / "src").symlink_to(outside)

    def swap_file():
        (root / "src" / "a.ts").unlink()
        (root / "src" / "a.ts").symlink_to(outside / "a.ts")

    return root, outside, {"dir": swap_dir, "file": swap_file}


@pytest.mark.parametrize("which", ["dir", "file"])
def test_read_file_never_follows_a_symlink_swapped_in_after_the_check(race, which):
    root, _, swaps = race
    try:
        out = _racy(root, swaps[which]).dispatch("read_file", {"path": "src/a.ts"})
    except (ToolRejected, OSError):
        return
    assert "worker secret" not in out


@pytest.mark.parametrize("which", ["dir", "file"])
def test_write_file_never_writes_through_a_symlink_swapped_in_after_the_check(race, which):
    root, outside, swaps = race
    with pytest.raises((ToolRejected, OSError)):
        _racy(root, swaps[which]).dispatch("write_file", {"path": "src/a.ts", "content": "pwned\n"})
    assert (outside / "a.ts").read_text() == "worker secret\n"


def test_write_file_still_creates_new_directories(tmp_path):
    tools = tools_for(tmp_path)
    tools.dispatch("write_file", {"path": "src/new/deep/b.ts", "content": "x\n"})
    assert (tmp_path / "src/new/deep/b.ts").read_text() == "x\n"
    assert tools.dispatch("list_dir", {"path": "src/new"}) == "deep/"


def test_list_dir_never_follows_a_symlink_swapped_in_after_the_check(race):
    root, _, swaps = race
    try:
        out = _racy(root, swaps["dir"]).dispatch("list_dir", {"path": "src"})
    except (ToolRejected, OSError):
        return
    assert "a.ts" not in out  # the outside directory's listing must not leak
