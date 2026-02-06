"""Tests for authentication module."""

import pytest

from src.auth import _build_solutions_url, _is_login_page


class TestIsLoginPage:
    """Tests for _is_login_page()."""

    @pytest.mark.parametrize("url", [
        "https://login.microsoftonline.com/common/oauth2/authorize",
        "https://login.microsoft.com/some/path",
        "https://login.live.com/oauth20_authorize.srf",
        "https://account.microsoft.com/auth",
        "https://login.microsoftonline.com/common?client_id=abc",
    ])
    def test_is_login_page(self, url):
        assert _is_login_page(url)

    @pytest.mark.parametrize("url", [
        "https://make.powerautomate.com/environments/env-123",
        "https://example.com/login",
    ])
    def test_is_not_login_page(self, url):
        assert not _is_login_page(url)


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
