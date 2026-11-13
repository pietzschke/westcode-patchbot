from research.evidence import call_site_hits, find_call_sites, is_dev_only


def test_npm_dev_flag(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        '{"packages": {"node_modules/jest": {"version": "29.0.0", "dev": true},'
        ' "node_modules/lodash": {"version": "4.17.15"},'
        ' "node_modules/a/node_modules/lodash": {"version": "3.0.0", "dev": true}}}'
    )
    assert is_dev_only(tmp_path, "npm", "jest") is True
    assert is_dev_only(tmp_path, "npm", "lodash") is False
    assert is_dev_only(tmp_path, "npm", "unknown") is False


def test_poetry_dev_category(tmp_path):
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "pytest"\nversion = "8.0.0"\ncategory = "dev"\n\n'
        '[[package]]\nname = "requests"\nversion = "2.32.0"\ncategory = "main"\n'
    )
    assert is_dev_only(tmp_path, "poetry", "pytest") is True
    assert is_dev_only(tmp_path, "poetry", "requests") is False


def test_call_site_hits_ignore_vendor_dirs(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/a.ts").write_text("import _ from 'lodash';\nconst x = require(\"lodash/template\");\n")
    (tmp_path / "node_modules/x").mkdir(parents=True)
    (tmp_path / "node_modules/x/index.js").write_text("require('lodash')\n")
    assert call_site_hits(tmp_path, "npm", "lodash") == 2
    sites = find_call_sites(tmp_path, "npm", "lodash")
    assert sites[0]["path"] == "src/a.ts" and sites[0]["line"] == 1


def test_python_import_hits(tmp_path):
    (tmp_path / "app.py").write_text("import yaml\nfrom PyJWT import x\nfrom jwt import decode\n")
    assert call_site_hits(tmp_path, "pip", "PyYAML") == 0  # distribution name differs from module name
    assert call_site_hits(tmp_path, "pip", "pyyaml", module_hint="yaml") == 1
    assert call_site_hits(tmp_path, "pip", "jwt") == 1


# --- review M-2: evidence must never read files outside the checkout through symlinks ---


def _outside(tmp_path):
    repo, outside = tmp_path / "repo", tmp_path / "outside"
    repo.mkdir()
    outside.mkdir()
    return repo, outside


def test_call_sites_ignore_symlinked_files_pointing_outside_the_checkout(tmp_path):
    repo, outside = _outside(tmp_path)
    (outside / "settings.py").write_text("import yaml  # SECRET_KEY = 'worker'\n")
    (repo / "app.py").symlink_to(outside / "settings.py")
    assert find_call_sites(repo, "pip", "pyyaml", module_hint="yaml") == []


def test_call_sites_ignore_symlinked_directories(tmp_path):
    repo, outside = _outside(tmp_path)
    (outside / "a.py").write_text("import yaml\n")
    (repo / "src").symlink_to(outside, target_is_directory=True)
    assert find_call_sites(repo, "pip", "pyyaml", module_hint="yaml") == []


def test_call_sites_ignore_in_repo_symlinks_too(tmp_path):
    """Counting the same file twice (or a link target that changes later) is not evidence either."""
    repo, _ = _outside(tmp_path)
    (repo / "a.py").write_text("import yaml\n")
    (repo / "b.py").symlink_to(repo / "a.py")
    assert [s["path"] for s in find_call_sites(repo, "pip", "pyyaml", module_hint="yaml")] == ["a.py"]


def test_symlinked_lockfiles_are_not_evidence(tmp_path):
    repo, outside = _outside(tmp_path)
    (outside / "package-lock.json").write_text('{"packages": {"node_modules/jest": {"dev": true}}}')
    (repo / "package-lock.json").symlink_to(outside / "package-lock.json")
    (outside / "poetry.lock").write_text('[[package]]\nname = "pytest"\ncategory = "dev"\n')
    (repo / "poetry.lock").symlink_to(outside / "poetry.lock")
    assert is_dev_only(repo, "npm", "jest") is False
    assert is_dev_only(repo, "poetry", "pytest") is False
