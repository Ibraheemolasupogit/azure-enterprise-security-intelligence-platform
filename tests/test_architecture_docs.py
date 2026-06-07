from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


REQUIRED_INFRA_FILES = [
    "infra/README.md",
    "infra/azure_architecture.md",
    "infra/deployment_plan.md",
    "infra/security_controls.md",
    "infra/cost_considerations.md",
    "infra/environments.md",
    "infra/bicep/README.md",
    "infra/bicep/main.bicep",
    "infra/bicep/parameters.dev.json",
    "infra/bicep/parameters.prod.json",
    "infra/terraform/README.md",
    "infra/terraform/main.tf",
    "infra/terraform/variables.tf",
    "infra/terraform/outputs.tf",
    "infra/terraform/terraform.tfvars.example",
]

REQUIRED_DOC_FILES = [
    "docs/production_architecture.md",
    "docs/security_operations_model.md",
]

REQUIRED_DIAGRAM_FILES = [
    "diagrams/azure_architecture.mmd",
    "diagrams/data_flow.mmd",
    "diagrams/security_operations_flow.mmd",
]


def test_required_infra_files_exist() -> None:
    for relative_path in REQUIRED_INFRA_FILES:
        assert (ROOT / relative_path).is_file(), f"Missing {relative_path}"


def test_required_architecture_docs_exist() -> None:
    for relative_path in REQUIRED_DOC_FILES:
        assert (ROOT / relative_path).is_file(), f"Missing {relative_path}"


def test_required_mermaid_diagrams_are_non_empty() -> None:
    for relative_path in REQUIRED_DIAGRAM_FILES:
        path = ROOT / relative_path
        assert path.is_file(), f"Missing {relative_path}"
        assert path.read_text(encoding="utf-8").strip(), f"{relative_path} is empty"


def test_readme_references_key_architecture_docs() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    expected_references = [
        "infra/README.md",
        "infra/azure_architecture.md",
        "infra/deployment_plan.md",
        "infra/security_controls.md",
        "docs/production_architecture.md",
        "docs/security_operations_model.md",
        "diagrams/azure_architecture.mmd",
        "diagrams/data_flow.mmd",
        "diagrams/security_operations_flow.mmd",
    ]

    for reference in expected_references:
        assert reference in readme


def test_infrastructure_templates_are_marked_as_placeholders() -> None:
    bicep_readme = (ROOT / "infra/bicep/README.md").read_text(encoding="utf-8")
    terraform_readme = (ROOT / "infra/terraform/README.md").read_text(encoding="utf-8")

    assert "safe placeholders" in bicep_readme
    assert "documentation-oriented skeletons" in terraform_readme

