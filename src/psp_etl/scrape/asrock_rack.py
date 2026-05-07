"""ASRock Rack BIOS scraper.

ASRock Rack (asrockrack.com) is a separate corporate entity from the
consumer ASRock brand but its BIOSes share the same content delivery
network at ``download.asrock.com``. Unlike consumer boards (filed under
``/BIOS/AM4/`` and ``/BIOS/AM5/``) Rack boards live in a single
``/BIOS/Server/`` folder mixed with Intel Xeon products. The socket has
to be inferred from the model name.

CDX inventory (download.asrock.com/BIOS/Server/, 2026-05-07):

* AMD Rack boards present on the unprotected CDN:

  - ``X470D4U`` / ``X470D4U2-2T`` / ``X570D4I-2T``  -> AM4 (Ryzen)
  - ``TRX40D8-2N2T``                                -> sTRX4 (Threadripper)

* AMD Rack boards NOT on download.asrock.com (live behind the Imperva
  WAF on www.asrockrack.com and are not Wayback-indexed):

  - ``ROMED*`` / ``ROMED4ID-2T`` / ``EPYCD8(-2T)``  -> SP3 (EPYC Naples/Rome/Milan)
  - ``GENOAD*`` / ``TURIND*``                       -> SP5 (EPYC Genoa/Bergamo/Turin)
  - ``SIENAD*``                                     -> SP6 (EPYC Siena)
  - ``WRX80*``                                      -> sWRX8 (Threadripper Pro)
  - ``WRX90*``                                      -> sWRX9 (Threadripper Pro)
  - ``EPYC3xxx*`` / ``EPYC4000*``                   -> embedded / AM5 EPYC

The model -> socket patterns below cover both groups so the scraper
forward-compatibly picks up EPYC and Threadripper Pro BIOSes if and
when they appear on the unprotected CDN, while currently materialising
only the boards that ARE available there.
"""

from __future__ import annotations

import re
from urllib.parse import quote

import httpx

from psp_etl.scrape.asrock import AsRockScraper

_RACK_FOLDERS: tuple[str, ...] = ("Server",)

# Model-prefix -> socket map, matched longest-prefix first so e.g.
# ``EPYC4000`` (AM5 desktop EPYC) wins over ``EPYC3xxx`` embedded.
_MODEL_SOCKET: tuple[tuple[re.Pattern[str], str], ...] = (
    # EPYC server (Naples / Rome / Milan) — single- and dual-socket boards
    (re.compile(r"^ROME[D2]", re.IGNORECASE), "SP3"),
    (re.compile(r"^EPYCD8", re.IGNORECASE), "SP3"),
    # EPYC server (Genoa / Bergamo / Turin) — single- and dual-socket boards
    (re.compile(r"^GENOA[D2]", re.IGNORECASE), "SP5"),
    (re.compile(r"^TURIN[D2]", re.IGNORECASE), "SP5"),
    # EPYC server (Siena)
    (re.compile(r"^SIENAD", re.IGNORECASE), "SP6"),
    # Threadripper Pro
    (re.compile(r"^WRX80", re.IGNORECASE), "sWRX8"),
    (re.compile(r"^WRX90", re.IGNORECASE), "sWRX9"),
    # Threadripper (non-Pro, on Rack only via TRX40 boards)
    (re.compile(r"^TRX40", re.IGNORECASE), "sTRX4"),
    # AM5 EPYC 4004 (desktop EPYC) — must precede the EPYC3xxx embedded rule
    (re.compile(r"^EPYC4000", re.IGNORECASE), "AM5"),
    # Embedded EPYC 3000 series (BGA, soldered)
    (re.compile(r"^EPYC3\d{3}", re.IGNORECASE), "AM4-Embedded"),
    # AMD desktop chipsets used on Rack workstation boards
    (re.compile(r"^X470D", re.IGNORECASE), "AM4"),
    (re.compile(r"^X570D", re.IGNORECASE), "AM4"),
    (re.compile(r"^B550D", re.IGNORECASE), "AM4"),
    (re.compile(r"^B650D", re.IGNORECASE), "AM5"),
    (re.compile(r"^AM5D", re.IGNORECASE), "AM5"),
)


def classify_rack_socket(folder: str, model: str) -> str | None:
    """Return the normalised socket for an ASRock Rack board model.

    ``folder`` is the CDN path segment (currently always ``Server``);
    ``model`` is the parsed board name (e.g. ``ROMED8-2T``). Returns
    ``None`` for non-AMD boards (e.g. ``C246 WS``, ``EPC621D8A``) so
    they are excluded from the scraper output.
    """
    del folder  # currently unused; kept for signature symmetry with consumer scraper
    for pattern, socket in _MODEL_SOCKET:
        if pattern.match(model):
            return socket
    return None


class AsRockRackScraper(AsRockScraper):
    """ASRock Rack BIOS scraper using the same CDX + CDN strategy as consumer ASRock.

    Only differs from :class:`AsRockScraper` in the folder list and the
    folder + model -> socket classifier. Inherits all download / unzip /
    cache behaviour.
    """

    vendor: str = "ASRock Rack"

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        super().__init__(client=client, folders=_RACK_FOLDERS, classify=classify_rack_socket)

    def board_support_url(self, model: str) -> str:
        return f"https://www.asrockrack.com/general/productdetail.asp?Model={quote(model)}"
