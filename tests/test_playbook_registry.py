import pytest

from guardduty_soar.playbook_registry import (_PLAYBOOK_REGISTRY, BasePlaybook,
                                              get_playbook_instance,
                                              register_playbook)


# Define some dummy playbook classes for testing purposes.
@register_playbook("FindingTypeA", "FindingTypeB")
class MockPlaybookA(BasePlaybook):
    def run(self, event):
        pass  # pragma: no cover


@register_playbook("FindingTypeC")
class MockPlaybookC(BasePlaybook):
    def run(self, event):
        pass  # pragma: no cover


def setup_function():
    """A pytest setup function to clear the registry before each test."""
    _PLAYBOOK_REGISTRY.clear()
    # Re-register after clearing
    register_playbook("FindingTypeA", "FindingTypeB")(MockPlaybookA)
    register_playbook("FindingTypeC")(MockPlaybookC)


def test_get_playbook_instance_success():
    """Tests that the correct playbook instance is returned for a registered type."""
    instance = get_playbook_instance("FindingTypeA")
    assert isinstance(instance, MockPlaybookA)

    instance_b = get_playbook_instance("FindingTypeB")
    assert isinstance(instance_b, MockPlaybookA)

    instance_c = get_playbook_instance("FindingTypeC")
    assert isinstance(instance_c, MockPlaybookC)


def test_get_playbook_instance_failure():
    """Tests that a ValueError is raised for an unregistered finding type."""
    with pytest.raises(
        ValueError, match="No playbook registered for finding type: UnregisteredType"
    ):
        get_playbook_instance("UnregisteredType")


def test_registration_populates_registry():
    """Verifies that the decorator correctly populates the internal registry."""
    assert _PLAYBOOK_REGISTRY["FindingTypeA"] == MockPlaybookA
    assert _PLAYBOOK_REGISTRY["FindingTypeB"] == MockPlaybookA
    assert _PLAYBOOK_REGISTRY["FindingTypeC"] == MockPlaybookC
    assert len(_PLAYBOOK_REGISTRY) == 3
