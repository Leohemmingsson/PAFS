"""Tests for service helper functions."""

import pytest

from src.services import get_dataverse_url, add_solution_flows


class TestGetDataverseUrl:
    """Tests for get_dataverse_url()."""

    def test_returns_urls_when_dataverse_enabled(self, mocker):
        mock_response = {
            "properties": {
                "linkedEnvironmentMetadata": {
                    "instanceUrl": "https://org.crm.dynamics.com"
                }
            }
        }
        mocker.patch("src.services.api_request_with_auth", return_value=mock_response)

        auth_url, dataverse_url, error = get_dataverse_url("env-123")

        assert auth_url == "https://make.powerautomate.com/environments/env-123"
        assert dataverse_url == "https://org.crm.dynamics.com"
        assert error is None

    @pytest.mark.parametrize("api_response", [
        {"properties": {}},
        {"properties": {"linkedEnvironmentMetadata": {}}},
    ])
    def test_returns_error_when_dataverse_unavailable(self, mocker, api_response):
        mocker.patch("src.services.api_request_with_auth", return_value=api_response)
        auth_url, dataverse_url, error = get_dataverse_url("env-123")
        assert auth_url is None
        assert dataverse_url is None
        assert error is not None
        assert "Dataverse" in error


class TestAddSolutionFlows:
    """Tests for add_solution_flows()."""

    def test_returns_added_labels(self, mocker):
        mock_flows = [
            {"msdyn_displayname": "Flow One", "msdyn_objectid": "flow-1"},
            {"msdyn_displayname": "Flow Two", "msdyn_objectid": "flow-2"},
        ]
        mocker.patch("src.services.api_request_with_auth", return_value=mock_flows)
        mocker.patch("src.services.load_solutions", return_value={})
        mocker.patch("src.services.save_solutions")
        mocker.patch("src.services.find_solution_by_id", return_value=None)

        flows = {}
        result = add_solution_flows(
            flows, "env-123", "sol-456", "My Solution",
            "https://auth.url", "https://dv.url"
        )

        assert len(result.data["added_labels"]) == 2
        assert "flow-one" in result.data["added_labels"]
        assert "flow-two" in result.data["added_labels"]
        assert len(flows) == 2

    def test_returns_empty_when_no_flows(self, mocker):
        mocker.patch("src.services.api_request_with_auth", return_value=[])

        result = add_solution_flows(
            {}, "env-123", "sol-456", "My Solution",
            "https://auth.url", "https://dv.url"
        )

        assert result.data["added_labels"] == []

    def test_skips_flows_without_object_id(self, mocker):
        mock_flows = [
            {"msdyn_displayname": "Flow One", "msdyn_objectid": "flow-1"},
            {"msdyn_displayname": "Flow Two"},  # Missing msdyn_objectid
        ]
        mocker.patch("src.services.api_request_with_auth", return_value=mock_flows)
        mocker.patch("src.services.load_solutions", return_value={})
        mocker.patch("src.services.save_solutions")
        mocker.patch("src.services.find_solution_by_id", return_value=None)

        flows = {}
        result = add_solution_flows(
            flows, "env-123", "sol-456", "My Solution",
            "https://auth.url", "https://dv.url"
        )

        assert len(result.data["added_labels"]) == 1
        assert "flow-one" in result.data["added_labels"]

    def test_does_not_register_already_tracked_solution(self, mocker):
        mock_flows = [
            {"msdyn_displayname": "Test Flow", "msdyn_objectid": "flow-1"},
        ]
        mocker.patch("src.services.api_request_with_auth", return_value=mock_flows)
        mocker.patch("src.services.load_solutions", return_value={"existing-sol": {}})
        mock_save = mocker.patch("src.services.save_solutions")
        mocker.patch("src.services.find_solution_by_id", return_value=("existing-sol", {}))

        flows = {}
        add_solution_flows(
            flows, "env-123", "sol-456", "My Solution",
            "https://auth.url", "https://dv.url"
        )

        # save_solutions should not be called when solution already exists
        mock_save.assert_not_called()

    def test_fetches_solution_name_when_not_provided(self, mocker):
        # First call returns flows, second returns solutions list
        mocker.patch("src.services.api_request_with_auth", side_effect=[
            [{"msdyn_displayname": "Test Flow", "msdyn_objectid": "flow-1"}],
            [{"solutionid": "sol-456", "friendlyname": "Fetched Name"}],
        ])
        mocker.patch("src.services.load_solutions", return_value={})
        mock_save = mocker.patch("src.services.save_solutions")
        mocker.patch("src.services.find_solution_by_id", return_value=None)

        flows = {}
        add_solution_flows(
            flows, "env-123", "sol-456", None,  # name=None triggers API lookup
            "https://auth.url", "https://dv.url"
        )

        # Verify save_solutions was called with the fetched name
        saved_registry = mock_save.call_args[0][0]
        assert "fetched-name" in saved_registry

    def test_uses_unknown_solution_when_name_not_found(self, mocker):
        # First call returns flows, second returns empty solutions list
        mocker.patch("src.services.api_request_with_auth", side_effect=[
            [{"msdyn_displayname": "Test Flow", "msdyn_objectid": "flow-1"}],
            [],  # No solutions found
        ])
        mocker.patch("src.services.load_solutions", return_value={})
        mock_save = mocker.patch("src.services.save_solutions")
        mocker.patch("src.services.find_solution_by_id", return_value=None)

        flows = {}
        add_solution_flows(
            flows, "env-123", "sol-456", None,
            "https://auth.url", "https://dv.url"
        )

        # Should use fallback name
        saved_registry = mock_save.call_args[0][0]
        assert "unknown-solution" in saved_registry

    def test_generates_unique_labels_for_duplicate_flow_names(self, mocker):
        mock_flows = [
            {"msdyn_displayname": "Same Name", "msdyn_objectid": "flow-1"},
            {"msdyn_displayname": "Same Name", "msdyn_objectid": "flow-2"},
        ]
        mocker.patch("src.services.api_request_with_auth", return_value=mock_flows)
        mocker.patch("src.services.load_solutions", return_value={})
        mocker.patch("src.services.save_solutions")
        mocker.patch("src.services.find_solution_by_id", return_value=None)

        flows = {}
        result = add_solution_flows(
            flows, "env-123", "sol-456", "My Solution",
            "https://auth.url", "https://dv.url"
        )

        assert len(result.data["added_labels"]) == 2
        assert "same-name" in result.data["added_labels"]
        assert "same-name-2" in result.data["added_labels"]
