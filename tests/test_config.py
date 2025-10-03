import configparser
import os
from unittest.mock import mock_open, patch

import pytest

from guardduty_soar.config import AppConfig, get_config


def test_config_loading_success():
    """
    Tests that AppConfig correctly parses a valid config file.
    We use mock_open to simulate the file existing.
    """
    mock_config_content = """
[General]
log_level = DEBUG

[EC2]
allow_terminate = no
ignored_findings =
    Recon:EC2/PortProbeUnprotectedPort
    Stealth:EC2/VPCAcccess

[Notifications]
allow_ses = true
    """

    # We patch 'builtins.open' to simulate reading our mock config content
    with patch("builtins.open", mock_open(read_data=mock_config_content)):
        # We also need to patch os.path.exists to return True
        with patch("os.path.exists", return_value=True):
            # Clear the cache for get_config to ensure a fresh instance is created
            get_config.cache_clear()
            config = AppConfig(config_file="dummy/path/gd.cfg")

            assert config.log_level == "DEBUG"
            assert config.allow_terminate is False
            assert config.allow_ses is True
            assert "Recon:EC2/PortProbeUnprotectedPort" in config.ec2_ignored_findings


def test_config_invalid_log_level_defaults_to_info():
    """
    Tests that an invalid log level in the config defaults to INFO.
    """
    mock_config_content = "[General]\nlog_level = INVALID"
    with patch("builtins.open", mock_open(read_data=mock_config_content)):
        with patch("os.path.exists", return_value=True):
            get_config.cache_clear()
            config = AppConfig()
            assert config.log_level == "INFO"


def test_config_file_not_found():
    """
    Tests that AppConfig raises a FileNotFoundError if the config file is missing.
    """
    with patch("os.path.exists", return_value=False):
        with pytest.raises(FileNotFoundError):
            get_config.cache_clear()
            AppConfig()
