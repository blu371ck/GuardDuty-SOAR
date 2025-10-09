from unittest.mock import mock_open, patch

import pytest

from guardduty_soar.config import AppConfig, get_config


def test_config_loading_success(mocker):
    """
    Tests that get_config() correctly parses a valid config file.
    """
    mocker.patch("guardduty_soar.config.boto3.Session")
    # Temporarily remove any real environment variables that could interfere.
    mocker.patch.dict("os.environ", clear=True)

    mock_config_content = """
[General]
log_level = DEBUG
[EC2]
allow_terminate = no
ignored_findings =
    Recon:EC2/PortProbeUnprotectedPort
[Notifications]
allow_ses = true
    """
    with patch("builtins.open", mock_open(read_data=mock_config_content)):
        with patch("os.path.exists", return_value=True):
            get_config.cache_clear()
            config = get_config()

            assert config.log_level == "DEBUG"
            assert config.allow_terminate is False
            assert config.allow_ses is True


def test_config_fallback_values(mocker):
    """
    Tests that get_config() uses fallback values for missing keys.
    """
    mocker.patch("guardduty_soar.config.boto3.Session")
    # Ensure a clean environment for this test too.
    mocker.patch.dict("os.environ", clear=True)

    mock_config_content = "[General]\nlog_level = INFO"

    with patch("builtins.open", mock_open(read_data=mock_config_content)):
        with patch("os.path.exists", return_value=True):
            get_config.cache_clear()
            config = get_config()

            # This should correctly use the fallback of False
            assert config.allow_sns is False


def test_config_handles_missing_file_gracefully(mocker):
    """
    Tests that get_config() returns a default AppConfig object
    when no files or environment variables are present.
    """
    mocker.patch("guardduty_soar.config.boto3.Session")
    # Ensure a completely empty environment for this test.
    mocker.patch.dict("os.environ", clear=True)

    with patch("os.path.exists", return_value=False):
        get_config.cache_clear()
        config = get_config()

        assert isinstance(config, AppConfig)
        # This should now correctly use the fallback of "INFO"
        assert config.log_level == "INFO"
