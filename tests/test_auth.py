"""Tests for authentication module."""

import shutil

import pytest
from playwright.sync_api import Error as PlaywrightError

from src.auth import _build_solutions_url, _is_login_page, get_tokens


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


class TestGetTokensBrowserDataRecovery:
    """Tests for get_tokens() browser data cleanup on browser install."""

    def test_clears_browser_data_after_install(self, mocker, tmp_path):
        """When ensure_playwright_browsers installs a new version, old browser data is cleared."""
        mocker.patch("src.auth.load_flow_token", return_value=None)
        mocker.patch("src.auth.load_dataverse_token", return_value=None)
        mocker.patch("src.auth.ensure_playwright_browsers", return_value=True)
        mocker.patch("src.auth.BROWSER_DATA_DIR", tmp_path / "browser-data")
        mocker.patch("src.auth.save_tokens")

        # Create browser-data dir with a sentinel file
        browser_dir = tmp_path / "browser-data"
        browser_dir.mkdir()
        (browser_dir / "stale-profile").touch()

        mock_playwright = mocker.MagicMock()
        mock_context = mocker.MagicMock()
        mock_page = mocker.MagicMock()
        mock_page.url = "https://make.powerautomate.com/"
        mock_context.pages = [mock_page]
        mock_playwright.chromium.launch_persistent_context.return_value = mock_context

        mock_cm = mocker.MagicMock()
        mock_cm.__enter__ = mocker.MagicMock(return_value=mock_playwright)
        mock_cm.__exit__ = mocker.MagicMock(return_value=False)
        mocker.patch("src.auth.sync_playwright", return_value=mock_cm)

        with pytest.raises(RuntimeError):
            get_tokens("https://make.powerautomate.com/environments/env-1/flows/f-1/details")

        # Browser data should have been cleared before launch
        assert not (browser_dir / "stale-profile").exists()

    def test_keeps_browser_data_when_no_install(self, mocker, tmp_path):
        """When no browser install happens, browser data is preserved."""
        mocker.patch("src.auth.load_flow_token", return_value=None)
        mocker.patch("src.auth.load_dataverse_token", return_value=None)
        mocker.patch("src.auth.ensure_playwright_browsers", return_value=False)
        mocker.patch("src.auth.BROWSER_DATA_DIR", tmp_path / "browser-data")
        mocker.patch("src.auth.save_tokens")

        # Create browser-data dir with a sentinel file
        browser_dir = tmp_path / "browser-data"
        browser_dir.mkdir()
        (browser_dir / "stale-profile").touch()

        mock_playwright = mocker.MagicMock()
        mock_context = mocker.MagicMock()
        mock_page = mocker.MagicMock()
        mock_page.url = "https://make.powerautomate.com/"
        mock_context.pages = [mock_page]
        mock_playwright.chromium.launch_persistent_context.return_value = mock_context

        mock_cm = mocker.MagicMock()
        mock_cm.__enter__ = mocker.MagicMock(return_value=mock_playwright)
        mock_cm.__exit__ = mocker.MagicMock(return_value=False)
        mocker.patch("src.auth.sync_playwright", return_value=mock_cm)

        with pytest.raises(RuntimeError):
            get_tokens("https://make.powerautomate.com/environments/env-1/flows/f-1/details")

        # Browser data should be preserved
        assert (browser_dir / "stale-profile").exists()
