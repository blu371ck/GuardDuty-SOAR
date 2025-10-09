import pytest

from guardduty_soar.playbook_registry import (
    _PLAYBOOK_REGISTRY,
    BasePlaybook,
    get_playbook_instance,
    register_playbook,
)


# A simple mock playbook for testing
class MockPlaybook(BasePlaybook):
    def run(self, event):
        pass


def test_register_playbook():
    """Tests that the decorator correctly adds a playbook to the registry."""
    register_playbook("FindingTypeA")(MockPlaybook)
    assert "FindingTypeA" in _PLAYBOOK_REGISTRY
    assert _PLAYBOOK_REGISTRY["FindingTypeA"] == MockPlaybook


def test_get_playbook_instance_success(mock_app_config):
    """Tests that the correct playbook instance is returned for a registered type."""
    register_playbook("FindingTypeA")(MockPlaybook)

    # We now pass the mock config to the function
    instance = get_playbook_instance("FindingTypeA", mock_app_config)

    assert isinstance(instance, MockPlaybook)
    assert instance.config == mock_app_config  # Verify config was injected


def test_get_playbook_instance_failure(mock_app_config):
    """Tests that a ValueError is raised for an unregistered finding type."""
    with pytest.raises(
        ValueError, match="No playbook registered for finding type: UnregisteredType"
    ):
        get_playbook_instance("UnregisteredType", mock_app_config)
