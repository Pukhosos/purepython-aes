from typing import TypeAlias

IntLookupTable256: TypeAlias = tuple[
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
    int, int, int, int, int, int, int, int,  # fmt: skip
]
"""Type alias describing a fixed-length tuple containing exactly 256 integer values."""


RoundKey: TypeAlias = tuple[int, int, int, int]
"""Round key representation in FastAesCore."""

RoundKeys: TypeAlias = list[RoundKey]
"""Round keys representation in FastAesCore."""
