"""Minimal read-only GitHub client. Any incomplete answer raises, so nothing passes on partial data."""
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from limits_config import ToolError

PER_PAGE = 100
MAX_PAGES = 30
RUN_LIST_CAP = 1000


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # urllib would resend the token to the new host.


class GitHub:
    def __init__(self, base_url, token, attempts=2, backoff=1.0):
        if not token:
            raise ToolError("github_api", "no GitHub token")
        self.base, self.token, self.attempts, self.backoff = base_url.rstrip("/"), token, attempts, backoff
        self.opener = urllib.request.build_opener(_NoRedirect)

    def get(self, path, params=None):
        url = self.base + path + ("?" + urllib.parse.urlencode(params) if params else "")
        request = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + self.token,
            "X-GitHub-Api-Version": "2022-11-28",
        })
        for attempt in range(self.attempts):
            try:
                with self.opener.open(request, timeout=20) as response:
                    return json.load(response)
            except urllib.error.HTTPError as error:
                if error.code < 500 or attempt + 1 == self.attempts:
                    raise ToolError("github_api", "GET %s returned HTTP %d" % (path, error.code))
            except (urllib.error.URLError, OSError, ValueError) as error:
                if attempt + 1 == self.attempts:
                    raise ToolError("github_api", "GET %s failed: %s" % (path, type(error).__name__))
            time.sleep(self.backoff)
        raise ToolError("github_api", "GET %s failed" % path)

    def pages(self, path, params=None, key=None):
        items = []
        for page in range(1, MAX_PAGES + 1):
            body = self.get(path, dict(params or {}, per_page=PER_PAGE, page=page))
            if key is not None:
                if not isinstance(body, dict):
                    raise ToolError("github_api", "GET %s returned an unexpected body" % path)
                if body.get("total_count", 0) > RUN_LIST_CAP:
                    raise ToolError("github_api", "GET %s is over GitHub's %d-result cap" % (path, RUN_LIST_CAP))
                body = body.get(key)
            if not isinstance(body, list):
                raise ToolError("github_api", "GET %s returned an unexpected body" % path)
            items.extend(body)
            if len(body) < PER_PAGE:
                return items
        raise ToolError("github_api", "GET %s has more than %d pages" % (path, MAX_PAGES))
