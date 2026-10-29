from typing import Literal

from pydantic import ConfigDict, model_validator

from app.modules.oauth.schemas import OauthStartResponse
from app.modules.shared.schemas import DashboardModel


class BrowserStartRequest(DashboardModel):
    model_config = ConfigDict(extra="forbid")
    account_id: str | None = None
    pool_id: str | None = None
    direct: bool = False

    @model_validator(mode="after")
    def explicit_route(self) -> "BrowserStartRequest":
        if self.account_id:
            if self.pool_id or self.direct:
                raise ValueError("Existing accounts use their saved route")
        elif bool(self.pool_id) == self.direct:
            raise ValueError("Choose direct routing or a proxy pool before signing in")
        return self


class BrowserFlowRequest(DashboardModel):
    model_config = ConfigDict(extra="forbid")
    flow_id: str


class BrowserCapabilities(DashboardModel):
    enabled: bool


class BrowserStartResponse(OauthStartResponse):
    managed_browser: bool = True
    persona_id: str
    browser_label: str
    route_mode: Literal["direct", "proxy"]


class BrowserActionResponse(DashboardModel):
    status: str
