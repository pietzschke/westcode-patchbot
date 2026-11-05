import pytest

from triage.versions import compare_versions, max_version


@pytest.mark.parametrize(
    "eco,a,b,expected",
    [
        ("deb", "1.1.1f-1ubuntu2.20", "1.1.1f-1ubuntu2.22", -1),
        ("deb", "3.0.2-0ubuntu1.15", "3.0.2-0ubuntu1.9", 1),
        ("deb", "1.0~rc1-1", "1.0-1", -1),
        ("deb", "1:1.0-1", "2.0-1", 1),
        ("ubuntu", "2.39-0ubuntu8.3", "2.39-0ubuntu8.3", 0),
        ("pypi", "2.0.0rc1", "2.0.0", -1),
        ("pip", "2.10.0", "2.9.1", 1),
        ("npm", "4.17.21", "4.17.9", 1),
        ("npm", "2.0.0-rc.1", "2.0.0", -1),
        ("npm", "2.0.0-rc.2", "2.0.0-rc.10", -1),
        ("npm", "v1.2.3", "1.2.3", 0),
        ("gomod", "v0.23.0", "v0.9.1", 1),
    ],
)
def test_compare_versions(eco, a, b, expected):
    assert compare_versions(eco, a, b) == expected


def test_max_version_ignores_empty_values():
    assert max_version("npm", ["4.17.19", "", "4.17.21", "4.17.20"]) == "4.17.21"
    assert max_version("npm", []) == ""
