"""Tests for authentication module."""

import pytest

from src.auth import _build_solutions_url, _is_login_page


class TestIsLoginPage:
    """Tests for _is_login_page()."""

    def test_microsoftonline_login(self):
        assert _is_login_page("https://login.microsoftonline.com/common/oauth2/authorize")

    def test_microsoft_login(self):
        assert _is_login_page("https://login.microsoft.com/some/path")

    def test_live_login(self):
        assert _is_login_page("https://login.live.com/oauth20_authorize.srf")

    def test_account_microsoft(self):
        assert _is_login_page("https://account.microsoft.com/auth")

    def test_powerautomate_not_login(self):
        assert not _is_login_page("https://make.powerautomate.com/environments/env-123")

    def test_arbitrary_url_not_login(self):
        assert not _is_login_page("https://example.com/login")

    def test_partial_host_match(self):
        # Ensure the host check works for URLs with query params
        assert _is_login_page("https://login.microsoftonline.com/common?client_id=abc")


class TestBuildSolutionsUrl:
    """Tests for _build_solutions_url()."""

    def test_url_with_environment_id(self):
        url = "https://make.powerautomate.com/environments/env-123/flows/flow-456"
        result = _build_solutions_url(url)
        assert result == "https://make.powerautomate.com/environments/env-123/solutions"

    def test_url_with_default_environment(self):
        url = "https://make.powerautomate.com/environments/Default-abc123/flows/flow-456"
        result = _build_solutions_url(url)
        assert result == "https://make.powerautomate.com/environments/Default-abc123/solutions"

    def test_url_without_environment(self):
        url = "https://make.powerautomate.com/"
        result = _build_solutions_url(url)
        assert result == url  # Returns original URL

    def test_empty_url(self):
        url = ""
        result = _build_solutions_url(url)
        assert result == url  # Returns original URL
