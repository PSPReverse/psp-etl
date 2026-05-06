"""Abstract base class and data models for vendor BIOS scrapers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path


@dataclass
class BoardInfo:
    vendor: str
    model: str
    socket: str  # 'AM4' or 'AM5'
    url: str  # vendor support page URL


@dataclass
class BiosUpdate:
    board: BoardInfo
    bios_version: str
    download_url: str
    release_date: str | None
    agesa_version: str | None  # if listed in release notes


class VendorScraper(ABC):
    """Abstract base for vendor-specific BIOS scrapers.

    Subclasses typically override ``__aenter__`` to lazily create an
    ``httpx.AsyncClient`` and ``__aexit__`` to close it. The default
    implementations here are no-ops so a subclass can opt out by passing
    a pre-built client to ``__init__``.
    """

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    @abstractmethod
    async def list_boards(self) -> list[BoardInfo]:
        """Enumerate all AM4/AM5 motherboard models."""

    @abstractmethod
    async def list_bios_updates(self, board: BoardInfo) -> list[BiosUpdate]:
        """List all available BIOS updates for a board."""

    @abstractmethod
    async def download(self, update: BiosUpdate, dest_dir: Path) -> Path:
        """Download and unwrap a BIOS update, return path to raw ROM."""
