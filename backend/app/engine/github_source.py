import json
import re
from typing import Callable, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

LogCallback = Optional[Callable[[str, str, str], None]]


GITHUB_API = "https://api.github.com"
GITHUB_HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "S-Gates-Security-Scanner",
    "X-GitHub-Api-Version": "2022-11-28",
}


class GitHubSourceError(ValueError):
    pass


def parse_github_repository_url(repository_url: str) -> tuple[str, str]:
    parsed = urlsplit(repository_url.strip())
    try:
        port = parsed.port
    except ValueError as exc:
        raise GitHubSourceError("The GitHub repository URL is invalid.") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise GitHubSourceError("Enter a GitHub HTTPS repository URL (github.com/owner/repository).")

    parts = parsed.path.strip("/").split("/")
    if len(parts) != 2:
        raise GitHubSourceError("Repository URL must contain exactly an owner and repository name.")

    owner, repository = parts
    if repository.endswith(".git"):
        repository = repository[:-4]
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", owner):
        raise GitHubSourceError("The GitHub owner in the repository URL is invalid.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", repository) or repository in {".", ".."}:
        raise GitHubSourceError("The GitHub repository name in the URL is invalid.")
    return owner, repository


def _request_headers(token: Optional[str]) -> dict[str, str]:
    headers = dict(GITHUB_HEADERS)
    if token and token.strip():
        if "\r" in token or "\n" in token:
            raise GitHubSourceError("GitHub token contains invalid characters.")
        headers["Authorization"] = f"Bearer {token.strip()}"
    return headers


def _github_http_error(error: HTTPError) -> GitHubSourceError:
    if error.code == 401:
        detail = "GitHub rejected the token. Check that it is valid and has repository Contents: read access."
    elif error.code == 404:
        detail = "GitHub repository or branch was not found. For a private repo, check the token and its access."
    elif error.code == 403:
        detail = "GitHub denied access or rate-limited the request. Check token permissions and try again later."
    else:
        detail = f"GitHub request failed (HTTP {error.code})."
    return GitHubSourceError(detail)


def _validate_ref(ref: str) -> str:
    ref = ref.strip()
    invalid = (
        not ref
        or len(ref) > 255
        or not re.fullmatch(r"[A-Za-z0-9._/-]+", ref)
        or ref.startswith("/")
        or ref.endswith("/")
        or "//" in ref
        or ".." in ref
        or "@{" in ref
        or any(part.startswith(".") or part.endswith(".") or part.endswith(".lock") for part in ref.split("/"))
    )
    if invalid:
        raise GitHubSourceError("Branch or tag name is invalid.")
    return ref


def _read_response(request: Request, max_bytes: int, timeout: int) -> bytes:
    try:
        with urlopen(request, timeout=timeout) as response:
            final_url = urlsplit(response.geturl())
            if final_url.scheme != "https" or final_url.hostname not in {
                "api.github.com",
                "github.com",
                "codeload.github.com",
            }:
                raise GitHubSourceError("GitHub returned an unexpected download host.")

            chunks = bytearray()
            while len(chunks) <= max_bytes:
                chunk = response.read(min(64 * 1024, max_bytes + 1 - len(chunks)))
                if not chunk:
                    return bytes(chunks)
                chunks.extend(chunk)
            raise GitHubSourceError(f"Repository archive exceeds the {max_bytes // (1024 * 1024)} MB ZIP limit.")
    except HTTPError as exc:
        raise _github_http_error(exc) from None
    except (URLError, TimeoutError) as exc:
        raise GitHubSourceError("Could not connect to GitHub. Check network access and try again.") from exc


def fetch_github_repository_zip(
    repository_url: str,
    ref: Optional[str],
    token: Optional[str],
    max_bytes: int,
    log_callback: LogCallback = None,
) -> tuple[str, str, str, bytes]:
    def emit(level: str, msg: str) -> None:
        if log_callback:
            log_callback(level, "INTAKE", msg)

    emit("INFO", f"Validating GitHub repository URL: {repository_url.strip()}")
    owner, repository = parse_github_repository_url(repository_url)
    headers = _request_headers(token)
    auth_mode = "authenticated (token masked)" if (token and token.strip()) else "unauthenticated (public)"
    emit("INFO", f"Resolved target repository '{owner}/{repository}' using {auth_mode} access.")

    if ref and ref.strip():
        resolved_ref = _validate_ref(ref)
        emit("INFO", f"Using requested ref '{resolved_ref}'.")
    else:
        emit("CMD", f"GET {GITHUB_API}/repos/{owner}/{repository} (resolving default branch)")
        metadata_request = Request(
            f"{GITHUB_API}/repos/{owner}/{repository}", headers=headers
        )
        metadata_body = _read_response(metadata_request, 1024 * 1024, timeout=30)
        try:
            metadata = json.loads(metadata_body)
            resolved_ref = _validate_ref(metadata["default_branch"])
            emit("OK", f"Resolved repository default branch: '{resolved_ref}'.")
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise GitHubSourceError("Could not determine the repository's default branch.") from exc

    archive_ref = quote(resolved_ref, safe="")
    emit("CMD", f"GET {GITHUB_API}/repos/{owner}/{repository}/zipball/{archive_ref}")
    archive_request = Request(
        f"{GITHUB_API}/repos/{owner}/{repository}/zipball/{archive_ref}",
        headers=headers,
    )
    archive = _read_response(archive_request, max_bytes, timeout=60)
    if not archive:
        raise GitHubSourceError("GitHub returned an empty repository archive.")
    emit("OK", f"Downloaded repository archive ({len(archive) / 1024:.1f} KB).")
    return owner, repository, resolved_ref, archive
