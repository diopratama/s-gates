import json
from unittest.mock import MagicMock, patch

import pytest

from app.engine.github_source import (
    GitHubSourceError,
    fetch_github_repository_zip,
    parse_github_repository_url,
)


class FakeStreamResponse:
    def __init__(self, content: bytes, url: str, status_code: int = 200):
        self._content = content
        self.url = url
        self.status_code = status_code

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def iter_bytes(self, chunk_size: int = 65536):
        yield self._content


def test_parse_github_repository_url_accepts_canonical_and_git_urls():
    assert parse_github_repository_url("https://github.com/octocat/Hello-World") == (
        "octocat",
        "Hello-World",
    )
    assert parse_github_repository_url("https://github.com/octocat/Hello-World.git/") == (
        "octocat",
        "Hello-World",
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/octocat/repo",
        "https://evil.example/octocat/repo",
        "https://user:token@github.com/octocat/repo",
        "https://github.com/octocat/repo/tree/main",
        "https://github.com/octocat/repo?token=secret",
    ],
)
def test_parse_github_repository_url_rejects_non_repository_urls(url: str):
    with pytest.raises(GitHubSourceError):
        parse_github_repository_url(url)


def test_fetch_github_archive_uses_default_branch_and_transient_token():
    metadata = FakeStreamResponse(
        json.dumps({"default_branch": "main"}).encode(),
        "https://api.github.com/repos/octocat/Hello-World",
    )
    archive_bytes = b"PK\x03\x04archive"
    archive = FakeStreamResponse(
        archive_bytes, "https://codeload.github.com/octocat/Hello-World/zip/main"
    )

    mock_client = MagicMock()
    mock_client.__enter__.return_value = mock_client
    mock_client.stream.side_effect = [metadata, archive]

    with patch("app.engine.github_source.httpx.Client", return_value=mock_client):
        owner, repository, branch, result = fetch_github_repository_zip(
            repository_url="https://github.com/octocat/Hello-World",
            ref=None,
            token="github-test-token",
            max_bytes=1024,
        )

    assert (owner, repository, branch, result) == (
        "octocat",
        "Hello-World",
        "main",
        archive_bytes,
    )
    metadata_headers = mock_client.stream.call_args_list[0].kwargs["headers"]
    archive_headers = mock_client.stream.call_args_list[1].kwargs["headers"]
    assert metadata_headers["Authorization"] == "Bearer github-test-token"
    assert archive_headers["Authorization"] == "Bearer github-test-token"
