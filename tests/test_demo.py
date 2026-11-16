"""Demo corpus contract: the embedded demo must exercise every rule."""

from firelint.demo import DEMO_FILES, run_demo
from firelint.rules import REGISTRY


def test_demo_covers_every_rule():
    report = run_demo()
    fired = {f.rule for f in report.findings}
    missing = sorted({item.id for item in REGISTRY} - fired)
    assert not missing, f"demo corpus never triggers: {missing}"


def test_demo_shape():
    report = run_demo()
    assert len(report.targets) == len(DEMO_FILES) == 4
    assert report.rules_run == len(REGISTRY) == 20
    assert report.counts["critical"] >= 2
    assert report.counts["high"] >= 2
    assert report.counts["medium"] >= 4
    assert report.counts["low"] >= 3


def test_demo_summary_counts_add_up():
    report = run_demo()
    assert sum(report.counts.values()) == len(report.findings)


def test_demo_is_deterministic():
    first = run_demo()
    second = run_demo()
    assert [f.to_dict() for f in first.findings] == [f.to_dict() for f in second.findings]
