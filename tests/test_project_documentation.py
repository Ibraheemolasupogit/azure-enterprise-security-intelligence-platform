from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


REQUIRED_PROJECT_DOCS = [
    "PROJECT_WALKTHROUGH.md",
    "LOCAL_DEMO.md",
    "PORTFOLIO_SUMMARY.md",
    "docs/output_catalog.md",
    "docs/cli_reference.md",
    "docs/testing_strategy.md",
    "docs/limitations_and_future_work.md",
    "scripts/run_all_local.sh",
]


def test_final_project_documentation_exists() -> None:
    for relative_path in REQUIRED_PROJECT_DOCS:
        assert (ROOT / relative_path).is_file(), f"Missing {relative_path}"


def test_readme_references_demo_and_portfolio_docs() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "LOCAL_DEMO.md" in readme
    assert "PROJECT_WALKTHROUGH.md" in readme
    assert "PORTFOLIO_SUMMARY.md" in readme


def test_milestone_plan_marks_milestone_12_complete() -> None:
    milestone_plan = (ROOT / "docs/milestone_plan.md").read_text(encoding="utf-8")
    milestone_12_section = milestone_plan.split("## Milestone 12", maxsplit=1)[1]

    assert "Status: Complete" in milestone_12_section

