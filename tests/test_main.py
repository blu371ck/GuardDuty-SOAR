import importlib
import logging
import sys
from unittest.mock import MagicMock, call, patch

import pytest

from guardduty_soar.main import handler, load_playbooks, setup_logging

logger = logging.getLogger(__name__)


def test_setup_logging(mock_app_config):
    """
    Tests that the setup_logging function correctly configures application and boto loggers.
    """
    with patch("guardduty_soar.main.get_config", return_value=mock_app_config):
        with patch("logging.basicConfig") as mock_basic_config:
            with patch("logging.getLogger") as mock_get_logger:
                mock_logger = MagicMock()
                mock_get_logger.return_value = mock_logger

                setup_logging()

                mock_basic_config.assert_called_once()
                assert mock_basic_config.call_args.kwargs["level"] == logging.INFO
                mock_logger.setLevel.assert_has_calls([call(logging.WARNING)] * 3)


def test_main_handler_success(valid_guardduty_event, mock_app_config):
    """
    Tests the main handler's "happy path".
    """
    with patch("guardduty_soar.main.get_config", return_value=mock_app_config):
        with patch("guardduty_soar.main.Engine") as MockEngine:
            mock_engine_instance = MockEngine.return_value
            result = handler(valid_guardduty_event, {})

            assert result["statusCode"] == 200
            MockEngine.assert_called_once_with(
                valid_guardduty_event["detail"], mock_app_config
            )
            mock_engine_instance.handle_finding.assert_called_once()


def test_main_handler_ignores_finding(valid_guardduty_event, mock_app_config):
    """
    Tests that the handler correctly skips findings listed in the config.
    """
    finding_type = valid_guardduty_event["detail"]["Type"]
    mock_app_config.ignored_findings = [finding_type]  # Ignore this specific finding

    with patch("guardduty_soar.main.get_config", return_value=mock_app_config):
        with patch("guardduty_soar.main.Engine") as MockEngine:
            result = handler(valid_guardduty_event, {})

            assert result["statusCode"] == 200
            assert "explicitly ignored" in result["message"]
            MockEngine.assert_not_called()  # Engine should never be initialized


class TestLoadPlaybooks:
    """Unit tests for the dynamic playbook and action loader."""

    def test_load_playbooks_success(self, mocker):
        """
        Tests that load_playbooks correctly discovers and imports modules.
        """
        mocker.patch("pathlib.Path.is_dir", return_value=True)
        from pathlib import Path

        fake_package_dir = Path("/project/src/guardduty_soar")

        mock_walk = mocker.patch("os.walk")
        mock_walk.side_effect = [
            [(str(fake_package_dir / "playbooks/s3"), [], ["compromise.py"])],
            [(str(fake_package_dir / "plugins/actions"), [], ["jira_action.py"])],
            [(str(fake_package_dir / "plugins/playbooks"), [], ["custom_s3.py"])],
        ]
        mock_import = mocker.patch("importlib.import_module")

        # Call the function directly, injecting the fake path
        load_playbooks(package_dir_override=fake_package_dir)

        expected_import_calls = [
            call("guardduty_soar.playbooks.s3.compromise"),
            call("guardduty_soar.plugins.actions.jira_action"),
            call("guardduty_soar.plugins.playbooks.custom_s3"),
        ]
        mock_import.assert_has_calls(expected_import_calls, any_order=True)

    def test_load_playbooks_handles_import_error(self, mocker, caplog):
        """
        Tests that load_playbooks logs an error but does not crash.
        """
        mocker.patch("pathlib.Path.is_dir", return_value=True)
        from pathlib import Path

        fake_package_dir = Path("/project/src/guardduty_soar")

        mock_walk = mocker.patch("os.walk")
        mock_walk.side_effect = [
            [],  # Built-ins
            [],  # Plugin actions
            [
                (str(fake_package_dir / "plugins/playbooks"), [], ["bad_playbook.py"])
            ],  # Plugin playbooks
        ]

        mock_import = mocker.patch("importlib.import_module")
        mock_import.side_effect = ImportError("could not import")

        with caplog.at_level(logging.ERROR):
            load_playbooks(package_dir_override=fake_package_dir)

            assert "Failed to import module" in caplog.text
            assert "guardduty_soar.plugins.playbooks.bad_playbook" in caplog.text

    def test_load_playbooks_handles_missing_directories(self, mocker):
        """
        Tests that the function runs without error if directories are missing.
        """
        mocker.patch("pathlib.Path.is_dir", return_value=False)
        from pathlib import Path

        fake_package_dir = Path("/project/src/guardduty_soar")

        mock_import = mocker.patch("importlib.import_module")

        load_playbooks(package_dir_override=fake_package_dir)

        mock_import.assert_not_called()
