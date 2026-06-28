# -*- coding: utf-8 -*-

"""
httpbin.models
~~~~~~~~~~~~~~

Pydantic models describing httpbin's JSON responses. They are attached to
routes via ``response_model=`` purely to enrich the OpenAPI schema / Swagger UI
— the handlers still build their responses by hand (so the exact byte output,
pretty-printing, and trailing newline are preserved). Because httpbin echoes
arbitrary request data, several fields are intentionally loose (``Any`` /
``dict[str, Any]``).
"""

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class IPResponse(BaseModel):
    origin: str = Field(..., description="The requester's IP address.")


class UUIDResponse(BaseModel):
    uuid: str = Field(..., description="A UUID4.")


class HeadersResponse(BaseModel):
    headers: dict[str, str] = Field(..., description="The request's headers.")


class UserAgentResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    user_agent: Optional[str] = Field(
        None, alias="user-agent", description="The request's User-Agent header."
    )


class GetResponse(BaseModel):
    """The classic httpbin echo of a GET request."""

    args: dict[str, Any] = Field(default_factory=dict, description="Query parameters.")
    headers: dict[str, str] = Field(default_factory=dict)
    origin: Optional[str] = None
    url: str = ""


class MethodResponse(GetResponse):
    """Echo of a request that may carry a body (POST/PUT/PATCH/DELETE)."""

    model_config = ConfigDict(populate_by_name=True)
    data: str = ""
    files: dict[str, Any] = Field(default_factory=dict)
    form: dict[str, Any] = Field(default_factory=dict)
    json_: Optional[Any] = Field(None, alias="json", description="Parsed JSON body.")


class AnythingResponse(MethodResponse):
    method: str = Field("", description="The HTTP method used.")


class StreamResponse(GetResponse):
    id: int = Field(0, description="The 0-based index of this streamed line.")


class EncodedResponse(BaseModel):
    """Echo returned (encoded) by /gzip, /deflate and /brotli."""

    headers: dict[str, str] = Field(default_factory=dict)
    method: str = ""
    origin: Optional[str] = None
    gzipped: Optional[bool] = None
    deflated: Optional[bool] = None
    brotli: Optional[bool] = None


class CookiesResponse(BaseModel):
    cookies: dict[str, str] = Field(default_factory=dict)


class AuthResponse(BaseModel):
    authenticated: bool = True
    user: str = ""


class BearerResponse(BaseModel):
    authenticated: bool = True
    token: str = ""


class Slide(BaseModel):
    type: str
    title: str
    items: Optional[list[str]] = None


class Slideshow(BaseModel):
    title: str
    date: str
    author: str
    slides: list[Slide] = Field(default_factory=list)


class JsonResponse(BaseModel):
    slideshow: Slideshow
