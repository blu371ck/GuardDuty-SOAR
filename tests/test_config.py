from unittest.mock import mock_open, patch

import pytest

from guardduty_soar.config import AppConfig, get_config


def test_config_loading_success(mocker):
    """
    Tests that get_config() correctly parses a valid config file.
    """
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
    # Ensure a completely empty environment for this test.
    mocker.patch.dict("os.environ", clear=True)

    with patch("os.path.exists", return_value=False):
        get_config.cache_clear()
        config = get_config()

        assert isinstance(config, AppConfig)
        # This should now correctly use the fallback of "INFO"
        assert config.log_level == "INFO"


@pytest.mark.parametrize(
    "config_value, expected_result",
    [
        ("30", 30),
        ("1", 1),
        ("50", 50),
        ("0", 1),
        ("100", 50),
        ("abc", 25),
        (None, 25),
    ],
    ids=[
        "valid_value",
        "min_boundary",
        "max_boundary",
        "clamp_below_min",
        "clamp_above_max",
        "invalid_string_fallback",
        "missing_key_fallback",
    ],
)
def test_cloudtrail_history_max_results_validation(
    config_value, expected_result, mocker
):
    """
    Tests the validation and clamping logic for cloudtrail_history_max_results.
    """
    mocker.patch.dict("os.environ", clear=True)

    mock_config_content = "[General]\nlog_level = INFO\n"
    if config_value is not None:
        mock_config_content += f"[IAM]\ncloudtrail_history_max_results = {config_value}"

    with patch("builtins.open", mock_open(read_data=mock_config_content)):
        with patch("os.path.exists", return_value=True):
            get_config.cache_clear()
            config = get_config()

            assert config.cloudtrail_history_max_results == expected_result


def test_cloudtrail_history_max_results_from_env_var(mocker):
    """
    Tests that the cloudtrail_history_max_results setting is correctly
    read from an environment variable, overriding the config file.
    """
    # Set the environment variable
    mocker.patch.dict(
        "os.environ", {"GD_CLOUDTRAIL_HISTORY_MAX_RESULTS": "42"}, clear=True
    )

    # Config file has a different value to prove the override works
    mock_config_content = """
[IAM]
cloudtrail_history_max_results = 10
    """
    with patch("builtins.open", mock_open(read_data=mock_config_content)):
        with patch("os.path.exists", return_value=True):
            get_config.cache_clear()
            config = get_config()

            # The value from the environment variable (42) should be used
            assert config.cloudtrail_history_max_results == 42


def test_config_analyze_iam_permissions_flag(mocker):
    """
    Tests that the analyze_iam_permissions boolean flag is read correctly.
    """
    mocker.patch.dict("os.environ", clear=True)

    mock_config_content = """
[IAM]
analyze_iam_permissions = false
    """
    with patch("builtins.open", mock_open(read_data=mock_config_content)):
        with patch("os.path.exists", return_value=True):
            get_config.cache_clear()
            config = get_config()

            # It should read 'false' from the config file
            assert config.analyze_iam_permissions is False

            # Test the default fallback is True
            get_config.cache_clear()
            with patch("builtins.open", mock_open(read_data="[General]")):
                config_with_fallback = get_config()
                assert config_with_fallback.analyze_iam_permissions is True
