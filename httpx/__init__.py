"""Minimal synchronous subset of httpx for unit testing without external dependency."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable, List, Mapping, MutableMapping, Optional, Tuple, Union
from urllib.parse import urlencode, urljoin, urlsplit

from . import _types
from ._client import USE_CLIENT_DEFAULT, UseClientDefault


__all__ = [
    "BaseTransport",
    "ByteStream",
    "Client",
    "Request",
    "Response",
    "USE_CLIENT_DEFAULT",
    "UseClientDefault",
]


class Headers:
    """Case-insensitive header container with multi-value support."""

    def __init__(self, data: Optional[Union[Mapping[str, str], Iterable[Tuple[str, str]]]] = None) -> None:
        items: List[Tuple[str, str]] = []
        if data:
            if isinstance(data, Mapping):
                iterable = data.items()
            else:
                iterable = data
            for key, value in iterable:
                items.append((str(key), str(value)))
        self._items = items

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        key_lower = key.lower()
        for stored_key, value in reversed(self._items):
            if stored_key.lower() == key_lower:
                return value
        return default

    def multi_items(self) -> List[Tuple[str, str]]:
        return list(self._items)

    def items(self) -> List[Tuple[str, str]]:
        return [(k.lower(), v) for k, v in self._items]

    def update(self, data: Union[Mapping[str, str], Iterable[Tuple[str, str]]]) -> None:
        if isinstance(data, Mapping):
            iterable = data.items()
        else:
            iterable = data
        for key, value in iterable:
            self._items.append((str(key), str(value)))

    def copy(self) -> "Headers":
        return Headers(self._items)

    def setdefault(self, key: str, value: str) -> None:
        if self.get(key) is None:
            self._items.append((key, value))

    def __contains__(self, key: object) -> bool:  # pragma: no cover - simple predicate
        if not isinstance(key, str):
            return False
        return self.get(key) is not None


@dataclass
class URL:
    """Very small helper mimicking httpx.URL behaviour used in tests."""

    scheme: str
    netloc: bytes
    path: str
    query: bytes
    raw_path: bytes

    @classmethod
    def from_string(cls, url: str) -> "URL":
        parts = urlsplit(url)
        scheme = parts.scheme or "http"
        netloc = parts.netloc.encode("ascii")
        path = parts.path or "/"
        query = parts.query.encode("ascii")
        raw = path
        if parts.query:
            raw = f"{path}?{parts.query}"
        return cls(scheme=scheme, netloc=netloc, path=path, query=query, raw_path=raw.encode("utf-8"))

    def __str__(self) -> str:  # pragma: no cover - debugging helper
        query = f"?{self.query.decode('ascii')}" if self.query else ""
        return f"{self.scheme}://{self.netloc.decode('ascii')}{self.path}{query}"


class Request:
    def __init__(
        self,
        method: str,
        url: Union[str, URL],
        *,
        headers: Optional[Union[Headers, Mapping[str, str], Iterable[Tuple[str, str]]]] = None,
        content: Optional[Union[bytes, str]] = None,
    ) -> None:
        self.method = method.upper()
        self.url = url if isinstance(url, URL) else URL.from_string(str(url))
        self.headers = headers if isinstance(headers, Headers) else Headers(headers)
        if content is None:
            self._body = b""
        elif isinstance(content, bytes):
            self._body = content
        elif isinstance(content, str):
            self._body = content.encode("utf-8")
        else:
            raise TypeError("Unsupported request content type")

    def read(self) -> bytes:
        return self._body


class ByteStream:
    def __init__(self, data: Union[bytes, bytearray]) -> None:
        self._data = bytes(data)

    def read(self) -> bytes:
        return self._data


class Response:
    def __init__(
        self,
        status_code: int = 200,
        *,
        headers: Optional[Union[Mapping[str, str], Iterable[Tuple[str, str]]]] = None,
        stream: Optional[ByteStream] = None,
        request: Optional[Request] = None,
    ) -> None:
        self.status_code = status_code
        self.headers = Headers(headers)
        self._stream = stream or ByteStream(b"")
        self.request = request

    @property
    def content(self) -> bytes:
        return self._stream.read()

    @property
    def text(self) -> str:
        return self.content.decode("utf-8")

    def json(self) -> Any:
        data = self.text
        if not data:
            return None
        return json.loads(data)


class BaseTransport:
    def handle_request(self, request: Request) -> Response:  # pragma: no cover - abstract
        raise NotImplementedError


class Client:
    def __init__(
        self,
        *,
        base_url: str = "http://localhost",
        headers: Optional[Mapping[str, str]] = None,
        transport: Optional[BaseTransport] = None,
        follow_redirects: bool = True,
        cookies: Optional[MutableMapping[str, str]] = None,
    ) -> None:
        if transport is None:
            raise ValueError("transport is required for the minimal httpx client")
        self.base_url = base_url
        self._transport = transport
        self.follow_redirects = follow_redirects
        self.cookies = cookies or {}
        self.headers = Headers(headers)

    def _merge_url(self, url: _types.URLTypes) -> URL:
        if isinstance(url, URL):
            return url
        return URL.from_string(urljoin(self.base_url, str(url)))

    def build_request(
        self,
        method: str,
        url: _types.URLTypes,
        *,
        content: _types.RequestContent = None,
        data: Optional[Mapping[str, Any]] = None,
        files: _types.RequestFiles = None,
        json: Any = None,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        cookies: _types.CookieTypes = None,
        **kwargs: Any,
    ) -> Request:
        target = self._merge_url(url)
        if params:
            query_string = urlencode(params, doseq=True)
            base = str(target)
            separator = "&" if target.query else "?"
            target = URL.from_string(f"{base}{separator}{query_string}")
        combined_headers = self.headers.copy()
        if headers:
            combined_headers.update(headers)

        body: Optional[bytes] = None
        if json is not None:
            body = json_module.dumps(json).encode("utf-8")
            combined_headers.update({"content-type": "application/json"})
        elif data is not None:
            body = urlencode(data, doseq=True).encode("utf-8")
            combined_headers.update({"content-type": "application/x-www-form-urlencoded"})
        elif content is not None:
            if isinstance(content, bytes):
                body = content
            elif isinstance(content, str):
                body = content.encode("utf-8")
            else:
                raise TypeError("Unsupported content type")
        else:
            body = b""

        return Request(method, target, headers=combined_headers, content=body)

    def send(self, request: Request, *, stream: bool = False, **kwargs: Any) -> Response:
        response = self._transport.handle_request(request)
        response.request = request
        return response

    def request(self, method: str, url: _types.URLTypes, **kwargs: Any) -> Response:
        stream = kwargs.pop("stream", False)
        request = self.build_request(method, url, **kwargs)
        return self.send(request, stream=stream)

    def get(self, url: _types.URLTypes, **kwargs: Any) -> Response:
        return self.request("GET", url, **kwargs)

    def options(self, url: _types.URLTypes, **kwargs: Any) -> Response:
        return self.request("OPTIONS", url, **kwargs)

    def head(self, url: _types.URLTypes, **kwargs: Any) -> Response:
        return self.request("HEAD", url, **kwargs)

    def post(self, url: _types.URLTypes, **kwargs: Any) -> Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: _types.URLTypes, **kwargs: Any) -> Response:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: _types.URLTypes, **kwargs: Any) -> Response:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: _types.URLTypes, **kwargs: Any) -> Response:
        return self.request("DELETE", url, **kwargs)

    def close(self) -> None:  # pragma: no cover - nothing to clean up
        pass

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


# Keep json module lazy in build_request to simplify testing overrides.
json_module = json
