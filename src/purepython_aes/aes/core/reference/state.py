from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, final

from purepython_aes.aes.core.reference.operations import inverse_mix_column, mix_column
from purepython_aes.const import AES_BLOCK_SIZE, INVERSE_SBOX, SBOX


@dataclass(slots=True)
@final
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

        (
            self.__b[0],
            self.__b[1],
            self.__b[2],
            self.__b[3],
        ) = mix_column(
            self.__b[0],
            self.__b[1],
            self.__b[2],
            self.__b[3],
        )
        (
            self.__b[4],
            self.__b[5],
            self.__b[6],
            self.__b[7],
        ) = mix_column(
            self.__b[4],
            self.__b[5],
            self.__b[6],
            self.__b[7],
        )
        (
            self.__b[8],
            self.__b[9],
            self.__b[10],
            self.__b[11],
        ) = mix_column(
            self.__b[8],
            self.__b[9],
            self.__b[10],
            self.__b[11],
        )
        (
            self.__b[12],
            self.__b[13],
            self.__b[14],
            self.__b[15],
        ) = mix_column(
            self.__b[12],
            self.__b[13],
            self.__b[14],
            self.__b[15],
        )

    def inverse_mix_columns(self) -> None:
        """Apply the AES `InvMixColumns` transformation."""

        (
            self.__b[0],
            self.__b[1],
            self.__b[2],
            self.__b[3],
        ) = inverse_mix_column(
            self.__b[0],
            self.__b[1],
            self.__b[2],
            self.__b[3],
        )
        (
            self.__b[4],
            self.__b[5],
            self.__b[6],
            self.__b[7],
        ) = inverse_mix_column(
            self.__b[4],
            self.__b[5],
            self.__b[6],
            self.__b[7],
        )
        (
            self.__b[8],
            self.__b[9],
            self.__b[10],
            self.__b[11],
        ) = inverse_mix_column(
            self.__b[8],
            self.__b[9],
            self.__b[10],
            self.__b[11],
        )
        (
            self.__b[12],
            self.__b[13],
            self.__b[14],
            self.__b[15],
        ) = inverse_mix_column(
            self.__b[12],
            self.__b[13],
            self.__b[14],
            self.__b[15],
        )

    def __init__(self, __constructor_sentinel: object, /, values: list[int]) -> None:
        if __constructor_sentinel is not AesState.__constructor_key:
            raise ValueError(f'{AesState.__name__}() must not be called externally')
        if len(values) != AES_BLOCK_SIZE:
            raise ValueError(f'expected {AES_BLOCK_SIZE} values, got {len(values)}')
        self.__b = values
