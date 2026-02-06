"""Tests for shared utilities."""

import pytest

from src.shared import (
    build_flow_url,
    detect_url_type,
    parse_environment_url,
    parse_flow_url,
    parse_solution_url,
    sanitize_label,
)


class TestParseFlowUrl:
    """Tests for parse_flow_url()."""

    def test_simple_flow_url(self):
        url = "https://make.powerautomate.com/environments/env-123/flows/flow-456/details"
        env_id, flow_id, solution_id = parse_flow_url(url)
        assert env_id == "env-123"
        assert flow_id == "flow-456"
        assert solution_id is None

    def test_flow_url_with_solution(self):
        url = "https://make.powerautomate.com/environments/env-123/solutions/sol-789/flows/flow-456/details"
        env_id, flow_id, solution_id = parse_flow_url(url)
        assert env_id == "env-123"
        assert flow_id == "flow-456"
        assert solution_id == "sol-789"

    def test_flow_url_without_details_suffix(self):
        url = "https://make.powerautomate.com/environments/env-123/flows/flow-456"
        env_id, flow_id, solution_id = parse_flow_url(url)
        assert env_id == "env-123"
        assert flow_id == "flow-456"
        assert solution_id is None

    def test_invalid_flow_url(self):
        with pytest.raises(ValueError):
            parse_flow_url("https://example.com/not-a-flow-url")

    def test_missing_flow_id(self):
        with pytest.raises(ValueError):
            parse_flow_url("https://make.powerautomate.com/environments/env-123/flows/")


class TestParseSolutionUrl:
    """Tests for parse_solution_url()."""

    def test_simple_solution_url(self):
        url = "https://make.powerautomate.com/environments/env-123/solutions/sol-456"
        env_id, solution_id = parse_solution_url(url)
        assert env_id == "env-123"
        assert solution_id == "sol-456"

    def test_solution_url_with_suffix(self):
        url = "https://make.powerautomate.com/environments/env-123/solutions/sol-456/objects"
        env_id, solution_id = parse_solution_url(url)
        assert env_id == "env-123"
        assert solution_id == "sol-456"

    def test_solution_url_missing_solution_id(self):
        with pytest.raises(ValueError):
            parse_solution_url("https://make.powerautomate.com/environments/env-123/solutions")

    def test_solution_url_missing_solution_id_trailing_slash(self):
        with pytest.raises(ValueError):
            parse_solution_url("https://make.powerautomate.com/environments/env-123/solutions/")

    def test_invalid_solution_url(self):
        with pytest.raises(ValueError):
            parse_solution_url("https://example.com/not-a-solution-url")


class TestParseEnvironmentUrl:
    """Tests for parse_environment_url()."""

    def test_environment_url(self):
        url = "https://make.powerautomate.com/environments/env-123/solutions"
        env_id = parse_environment_url(url)
        assert env_id == "env-123"

    def test_environment_url_with_trailing_slash(self):
        url = "https://make.powerautomate.com/environments/env-123/solutions/"
        env_id = parse_environment_url(url)
        assert env_id == "env-123"

    def test_bare_environment_url(self):
        url = "https://make.powerautomate.com/environments/env-123"
        env_id = parse_environment_url(url)
        assert env_id == "env-123"

    def test_bare_environment_url_with_trailing_slash(self):
        url = "https://make.powerautomate.com/environments/env-123/"
        env_id = parse_environment_url(url)
        assert env_id == "env-123"

    def test_invalid_environment_url(self):
        with pytest.raises(ValueError):
            parse_environment_url("https://example.com/not-an-environment-url")


class TestDetectUrlType:
    """Tests for detect_url_type()."""

    def test_flow_url(self):
        url = "https://make.powerautomate.com/environments/env-123/flows/flow-456/details"
        assert detect_url_type(url) == "flow"

    def test_flow_url_with_solution(self):
        url = "https://make.powerautomate.com/environments/env-123/solutions/sol/flows/flow-456/details"
        assert detect_url_type(url) == "flow"

    def test_solution_url(self):
        url = "https://make.powerautomate.com/environments/env-123/solutions/sol-456"
        assert detect_url_type(url) == "solution"

    def test_environment_url(self):
        url = "https://make.powerautomate.com/environments/env-123/solutions"
        assert detect_url_type(url) == "environment"

    def test_environment_url_with_trailing_slash(self):
        url = "https://make.powerautomate.com/environments/env-123/solutions/"
        assert detect_url_type(url) == "environment"

    def test_bare_environment_url(self):
        url = "https://make.powerautomate.com/environments/env-123"
        assert detect_url_type(url) == "environment"

    def test_bare_environment_url_with_trailing_slash(self):
        url = "https://make.powerautomate.com/environments/env-123/"
        assert detect_url_type(url) == "environment"

    def test_invalid_url(self):
        with pytest.raises(ValueError):
            detect_url_type("https://example.com/not-a-power-automate-url")


class TestSanitizeLabel:
    """Tests for sanitize_label()."""

    @pytest.mark.parametrize("input_name,expected", [
        ("MyFlow", "myflow"),
        ("My Flow Name", "my-flow-name"),
        ("My Flow! @#$% Name", "my-flow-name"),
        ("Flow123Test", "flow123test"),
        ("My    Flow", "my-flow"),
        ("---My Flow---", "my-flow"),
        ("", "unnamed-flow"),
        ("@#$%^&*", "unnamed-flow"),
        ("my_flow_name", "my_flow_name"),
        ("my_flow name", "my_flow-name"),
        ("___my_flow___", "my_flow"),
    ])
    def test_sanitize_label(self, input_name, expected):
        assert sanitize_label(input_name) == expected


class TestBuildFlowUrl:
    """Tests for build_flow_url()."""

    def test_build_url(self):
        url = build_flow_url("env-123", "flow-456")
        assert url == "https://make.powerautomate.com/environments/env-123/flows/flow-456/details"
