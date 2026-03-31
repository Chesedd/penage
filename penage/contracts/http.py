from __future__ import annotations

from typing import Any, Mapping, Optional, TypedDict, Literal


HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


class HttpRequestParams(TypedDict, total=False):
    method: HttpMethod
    url: str
    headers: Mapping[str, str]
    params: Mapping[str, Any]         # query string
    data: Any                         # form / bytes / str
    json: Any                         # json-serializable
    cookies: Mapping[str, str]
    follow_redirects: bool
    timeout_s: float