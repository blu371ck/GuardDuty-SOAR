from unittest.mock import MagicMock

from guardduty_soar.notifications.manager import NotificationManager


def test_manager_initializes_correct_actions(mock_app_config, mocker):
    """
    Tests that the NotificationManager initializes only the actions
    enabled in the application configuration.
    """
    # Mock the action classes
    mock_ses = mocker.patch(
        "guardduty_soar.notifications.manager.SendSESNotificationAction"
    )
    mock_sns = mocker.patch(
        "guardduty_soar.notifications.manager.SendSNSNotificationAction"
    )

    # Case 1: Both enabled
    mock_app_config.allow_ses = True
    mock_app_config.allow_sns = True
    manager = NotificationManager(MagicMock(), mock_app_config)
    assert len(manager.actions) == 2
    mock_ses.assert_called_once()
    mock_sns.assert_called_once()

    # Case 2: Only SES enabled
    mock_ses.reset_mock()
    mock_sns.reset_mock()
    mock_app_config.allow_ses = True
    mock_app_config.allow_sns = False
    manager = NotificationManager(MagicMock(), mock_app_config)
    assert len(manager.actions) == 1
    mock_ses.assert_called_once()
    mock_sns.assert_not_called()


def test_manager_dispatches_to_all_actions(
    mock_app_config, mocker, guardduty_finding_detail
):
    """
    Tests that dispatch methods call 'execute' on all initialized action instances.
    """
    mock_app_config.allow_ses = True
    mock_app_config.allow_sns = True

    # We don't need to patch the classes here, but their instances inside the manager
    manager = NotificationManager(MagicMock(), mock_app_config)

    # Spy on the execute method of each instance
    mocker.spy(manager.actions[0], "execute")
    mocker.spy(manager.actions[1], "execute")

    # Call a dispatch method
    manager.send_starting_notification(guardduty_finding_detail, playbook_name="TestPB")

    assert manager.actions[0].execute.call_count == 1
    assert manager.actions[1].execute.call_count == 1
