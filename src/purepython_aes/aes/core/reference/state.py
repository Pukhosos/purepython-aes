from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, final, Final

from purepython_aes.aes.core.reference.operations import inverse_mix_column, mix_column
from purepython_aes.const import AES_BLOCK_SIZE, INVERSE_SBOX, SBOX

COLUMN_0: Final[slice] = slice(0, 4)
COLUMN_1: Final[slice] = slice(4, 8)
COLUMN_2: Final[slice] = slice(8, 12)
COLUMN_3: Final[slice] = slice(12, 16)


@final
@dataclass(slots=True)
class AesState:
    __constructor_key: ClassVar[object] = object()
    __b: list[int]

    @classmethod
    def from_bytes(cls, block: bytes) -> AesState:
        """Create `AesState` from a 16-byte block."""

        return cls(cls.__constructor_key, values=list(block))

    def to_bytes(self) -> bytes:
        """Serialize the AES state in column-major order."""

        return bytes(self.__b)

    def add_round_key(self, key: bytes) -> None:
        """XOR a round key into this state."""

        for index, key_byte in enumerate(key):
            self.__b[index] ^= key_byte

    def subs_bytes(self) -> None:
        """Apply the AES S-box to every state byte."""

        for index in range(AES_BLOCK_SIZE):
            self.__b[index] = SBOX[self.__b[index]]

    def inverse_subs_bytes(self) -> None:
        """Apply the inverse AES S-box to every state byte."""

        for index in range(AES_BLOCK_SIZE):
            self.__b[index] = INVERSE_SBOX[self.__b[index]]

    def shift_rows(self) -> None:
        """Cyclically shift each AES state row to the left."""

        (
            self.__b[1],
            self.__b[5],
            self.__b[9],
            self.__b[13],
            self.__b[2],
            self.__b[6],
            self.__b[10],
            self.__b[14],
            self.__b[3],
            self.__b[7],
            self.__b[11],
            self.__b[15],
        ) = (
            self.__b[5],
            self.__b[9],
            self.__b[13],
            self.__b[1],
            self.__b[10],
            self.__b[14],
            self.__b[2],
            self.__b[6],
            self.__b[15],
            self.__b[3],
            self.__b[7],
            self.__b[11],
        )

    def inverse_shift_rows(self) -> None:
        """Cyclically shift each AES state row to the right."""

        (
            self.__b[1],
            self.__b[5],
            self.__b[9],
            self.__b[13],
            self.__b[2],
            self.__b[6],
            self.__b[10],
            self.__b[14],
            self.__b[3],
            self.__b[7],
            self.__b[11],
            self.__b[15],
        ) = (
            self.__b[13],
            self.__b[1],
            self.__b[5],
            self.__b[9],
            self.__b[10],
            self.__b[14],
            self.__b[2],
            self.__b[6],
            self.__b[7],
            self.__b[11],
            self.__b[15],
            self.__b[3],
        )

    def mix_columns(self) -> None:
        """Apply the AES `MixColumns` transformation."""

        self.__b[COLUMN_0] = mix_column(*self.__b[COLUMN_0])
        self.__b[COLUMN_1] = mix_column(*self.__b[COLUMN_1])
        self.__b[COLUMN_2] = mix_column(*self.__b[COLUMN_2])
        self.__b[COLUMN_3] = mix_column(*self.__b[COLUMN_3])

    def inverse_mix_columns(self) -> None:
        """Apply the AES `InvMixColumns` transformation."""

        self.__b[COLUMN_0] = inverse_mix_column(*self.__b[COLUMN_0])
        self.__b[COLUMN_1] = inverse_mix_column(*self.__b[COLUMN_1])
        self.__b[COLUMN_2] = inverse_mix_column(*self.__b[COLUMN_2])
        self.__b[COLUMN_3] = inverse_mix_column(*self.__b[COLUMN_3])

    def __init__(self, __constructor_sentinel: object, /, values: list[int]) -> None:
        if __constructor_sentinel is not AesState.__constructor_key:
            raise ValueError(f'{AesState.__name__}() must not be called externally')
        if len(values) != AES_BLOCK_SIZE:
            raise ValueError(f'expected {AES_BLOCK_SIZE} values, got {len(values)}')
        self.__b = values
