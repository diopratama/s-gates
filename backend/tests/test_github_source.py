import io
import json
from unittest.mock import patch

import pytest

from app.engine.github_source import (
    GitHubSourceError,
    fetch_github_repository_zip,
    parse_github_repository_url,
)


class FakeResponse(io.BytesIO):
    def __init__(self, content: bytes, url: str):
        super().__init__(content)
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def geturl(self):
        return self.url


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
    metadata = FakeResponse(
        json.dumps({"default_branch": "main"}).encode(),
        "https://api.github.com/repos/octocat/Hello-World",
    )
    archive_bytes = b"PK\x03\x04archive"
    archive = FakeResponse(archive_bytes, "https://codeload.github.com/octocat/Hello-World/zip/main")

    with patch("app.engine.github_source.urlopen", side_effect=[metadata, archive]) as mocked_urlopen:
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
    metadata_request = mocked_urlopen.call_args_list[0].args[0]
    archive_request = mocked_urlopen.call_args_list[1].args[0]
    assert metadata_request.get_header("Authorization") == "Bearer github-test-token"
    assert archive_request.get_header("Authorization") == "Bearer github-test-token"
