import pytest

from research.bot_prs import parse_bot_pr


def pr(title, login="renovate[bot]"):
    return {"number": 1, "html_url": "u", "user_login": login, "head_ref": "renovate/x", "title": title, "draft": False}


@pytest.mark.parametrize(
    "title,login,package,version",
    [
        ("Update dependency lodash to v4.17.21", "renovate[bot]", "lodash", "4.17.21"),
        ("fix(deps): update dependency @angular/core to v22.2.1", "renovate[bot]", "@angular/core", "22.2.1"),
        ("chore(deps): update docker image postgres to v18.2", "renovate[bot]", "postgres", "18.2"),
        ("Bump lodash from 4.17.15 to 4.17.21", "dependabot[bot]", "lodash", "4.17.21"),
        ("Bump django from 5.2.1 to 5.2.8 in /backend", "dependabot[bot]", "django", "5.2.8"),
    ],
)
def test_parses_renovate_and_dependabot_titles(title, login, package, version):
    parsed = parse_bot_pr(pr(title, login))
    assert (parsed.package, parsed.version) == (package, version)


def test_ignores_human_prs_and_group_updates():
    assert parse_bot_pr(pr("Update dependency lodash to v4.17.21", login="moritz")) is None
    assert parse_bot_pr(pr("Update all non-major dependencies")) is None
