from __future__ import annotations

from abc import ABC
from dataclasses import dataclass

from purepython_aes.aes.interface import Aes


@dataclass
class AesMode(ABC):
    """Base class for all AES modes of operation."""

    algorithm: Aes
    """Either AES-128, AES-192, or AES-256."""
