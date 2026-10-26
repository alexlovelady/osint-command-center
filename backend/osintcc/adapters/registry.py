from __future__ import annotations

from ..config import Settings
from .base import IntelAdapter
from .cli import (
    AmassAdapter,
    DnstwistAdapter,
    MaigretAdapter,
    SherlockAdapter,
    SubfinderAdapter,
    TheHarvesterAdapter,
)
from .http import (
    CensysAdapter,
    CrtShAdapter,
    DnsAdapter,
    EdgarAdapter,
    GdeltAdapter,
    GithubEmailSearchAdapter,
    GithubPublicAdapter,
    GravatarEmailAdapter,
    KeyserverEmailAdapter,
    OpenCorporatesAdapter,
    OverpassAdapter,
    PageContactsAdapter,
    RdapAdapter,
    ShodanAdapter,
    UrlscanAdapter,
    VirusTotalAdapter,
    WaybackAdapter,
    WebSearchEmailAdapter,
)
from .local import LookalikeAdapter


def default_adapters(settings: Settings | None = None) -> dict[str, IntelAdapter]:
    sp = settings.tools_state_path if settings is not None else None
    items: list[IntelAdapter] = [RdapAdapter(), DnsAdapter(), CrtShAdapter(), WaybackAdapter(), SubfinderAdapter(state_path=sp),
                                 SherlockAdapter(state_path=sp), MaigretAdapter(state_path=sp), LookalikeAdapter(), EdgarAdapter(),
                                 VirusTotalAdapter(), UrlscanAdapter(), ShodanAdapter(), OverpassAdapter(), GdeltAdapter(), OpenCorporatesAdapter(), CensysAdapter(),
                                 AmassAdapter(state_path=sp), TheHarvesterAdapter(state_path=sp), DnstwistAdapter(state_path=sp),
                                 GithubPublicAdapter(), PageContactsAdapter(),
                                 GravatarEmailAdapter(), GithubEmailSearchAdapter(), KeyserverEmailAdapter(), WebSearchEmailAdapter()]
    if settings is not None and settings.enable_active_module:
        from .active import TcpConnectAdapter
        items.append(TcpConnectAdapter())
    return {a.manifest.id: a for a in items}
