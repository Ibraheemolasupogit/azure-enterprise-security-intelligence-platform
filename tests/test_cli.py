from security_intelligence.cli import main


def test_health_check_outputs_ready_message(capsys) -> None:
    exit_code = main(["health-check"])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "scaffold is ready" in captured.out

