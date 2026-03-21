"""ASUS vendor scraper for AM4/AM5 motherboard BIOS downloads."""

import html
import re
import zipfile
from io import BytesIO
from pathlib import Path

import httpx

from psp_etl.scrape.base import BiosUpdate, BoardInfo, VendorScraper

# ASUS capsule header size to strip from .CAP files
ASUS_CAP_HEADER_SIZE = 0x800

# Public CDN - no auth required
CDN_BASE = "https://dlcdnets.asus.com"

# SeriesFilterResult API for socket-filtered board listing
SERIES_FILTER_URL = "https://odinapi.asus.com/recent-data/apiv2/SeriesFilterResult"

# Support webapi for BIOS file listing
BIOS_API_URL = "https://www.asus.com/support/webapi/ProductV2/GetPDBIOS"

# Socket SubSpec IDs for odinapi
SOCKET_SUBSPECS: dict[str, int] = {
    "AM4": 532,
    "AM5": 172178,
}

# AM5 and AM4 chipset identifiers for socket detection from model name
AM5_CHIPSETS = re.compile(r"\b(X670E?|B650E?|A620|X870E?|B850|B840)\b", re.IGNORECASE)
AM4_CHIPSETS = re.compile(
    r"\b(X570|B550|B450|A520|X470|B350|X370|B250|A320|B150|X299|TRX40|TRX50)\b",
    re.IGNORECASE,
)

# Required headers for support API endpoints
SUPPORT_API_HEADERS = {
    "X-Requested-With": "XMLHttpRequest",
    "Referer": "https://www.asus.com/de/support/download-center/",
}

# Website locale (DE is what we get due to geo-routing; all APIs accept it)
WEBSITE = "de"


_HTML_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(text: str) -> str:
    """Strip HTML tags and unescape entities from a string."""
    return html.unescape(_HTML_TAG_RE.sub("", text)).strip()


def _detect_socket(model_name: str) -> str | None:
    """Detect AM4 or AM5 socket from board model name."""
    if AM5_CHIPSETS.search(model_name):
        return "AM5"
    if AM4_CHIPSETS.search(model_name):
        return "AM4"
    return None


def _extract_agesa(description: str | None) -> str | None:
    """Extract AGESA version string from BIOS description text."""
    if not description:
        return None
    # Matches e.g. "ComboAM5 PI_1.3.0.0a" or "ComboAM4v2PI_1.2.0.7"
    match = re.search(
        r"(Combo(?:AM4|AM5)[v\w]*\s*PI_[\d.]+[a-zA-Z]?)",
        description,
        re.IGNORECASE,
    )
    if match:
        return match.group(1).strip()
    return None


class AsusScraper(VendorScraper):
    """VendorScraper implementation for ASUS AM4/AM5 motherboards."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client
        self._owns_client = client is None

    async def __aenter__(self) -> "AsusScraper":
        if self._owns_client:
            self._client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; psp-etl/0.1)"},
            )
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("AsusScraper must be used as an async context manager")
        return self._client

    async def _fetch_boards_for_socket(self, socket: str) -> list[BoardInfo]:
        """Fetch all boards for a given socket via SeriesFilterResult API."""
        client = await self._get_client()
        subspec = SOCKET_SUBSPECS[socket]
        boards: list[BoardInfo] = []
        page = 1
        page_size = 200

        while True:
            resp = await client.get(
                SERIES_FILTER_URL,
                params={
                    "SystemCode": "asus",
                    "WebsiteCode": "global",
                    "ProductLevel1Code": "motherboards-components",
                    "ProductLevel2Code": "motherboards",
                    "SubSpec": subspec,
                    "Page": page,
                    "PageSize": page_size,
                },
            )
            resp.raise_for_status()
            data = resp.json()

            result = data.get("Result", {})
            product_list = result.get("ProductList", [])
            if not product_list:
                break

            for item in product_list:
                name = _strip_html(item.get("Name") or item.get("ProductName", ""))
                product_url = item.get("ProductURL") or item.get("Url", "")
                # Build absolute URL if relative
                if product_url and not product_url.startswith("http"):
                    product_url = "https://www.asus.com" + product_url

                boards.append(
                    BoardInfo(
                        vendor="ASUS",
                        model=name,
                        socket=socket,
                        url=product_url,
                    )
                )

            # Check if there are more pages
            total = result.get("Total", 0)
            if page * page_size >= total:
                break
            page += 1

        return boards

    async def list_boards(self) -> list[BoardInfo]:
        """Enumerate all AM4 and AM5 ASUS motherboard models."""
        boards: list[BoardInfo] = []
        for socket in ("AM4", "AM5"):
            socket_boards = await self._fetch_boards_for_socket(socket)
            boards.extend(socket_boards)
        return boards

    async def list_bios_updates(self, board: BoardInfo) -> list[BiosUpdate]:
        """List all available BIOS updates for the given board."""
        client = await self._get_client()

        resp = await client.get(
            BIOS_API_URL,
            params={
                "website": WEBSITE,
                "model": board.model,
                "pdhashedid": "",
            },
            headers=SUPPORT_API_HEADERS,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("Status") != "SUCCESS":
            return []

        result = data.get("Result", {})
        updates: list[BiosUpdate] = []

        for obj in result.get("Obj", []):
            if obj.get("Name") != "BIOS":
                continue
            for file_info in obj.get("Files", []):
                version = file_info.get("Version", "")
                release_date = file_info.get("ReleaseDate")
                description = file_info.get("Description")
                download_url_obj = file_info.get("DownloadUrl", {})
                # Prefer Global CDN path; fall back to China if absent
                cdn_path = download_url_obj.get("Global") or download_url_obj.get("China")
                if not cdn_path:
                    continue

                download_url = CDN_BASE + cdn_path
                agesa_version = _extract_agesa(description)

                updates.append(
                    BiosUpdate(
                        board=board,
                        bios_version=version,
                        download_url=download_url,
                        release_date=release_date,
                        agesa_version=agesa_version,
                    )
                )

        return updates

    async def download(self, update: BiosUpdate, dest_dir: Path) -> Path:
        """Download a BIOS ZIP, extract the .CAP file, strip the 0x800-byte header."""
        client = await self._get_client()

        resp = await client.get(update.download_url)
        resp.raise_for_status()

        dest_dir.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(BytesIO(resp.content)) as zf:
            cap_names = [n for n in zf.namelist() if n.upper().endswith(".CAP")]
            if not cap_names:
                raise ValueError(f"No .CAP file found in ZIP for {update.board.model} v{update.bios_version}")
            # Use the first .CAP (there is typically only one)
            cap_name = cap_names[0]
            raw_cap = zf.read(cap_name)

        # Strip the ASUS capsule header
        rom_data = raw_cap[ASUS_CAP_HEADER_SIZE:]

        # Derive output filename from ZIP entry, replacing extension with .rom
        stem = Path(cap_name).stem
        out_path = dest_dir / f"{stem}.rom"
        out_path.write_bytes(rom_data)

        return out_path
