from dataclasses import dataclass
from typing import Final

from purepython_aes import (
    Aes,
    Aes128,
    Aes192,
    Aes256,
    ReferenceAes128,
    ReferenceAes192,
    ReferenceAes256,
)
from purepython_aes.const import AES_BLOCK_SIZE
from purepython_aes.types import CfbSegmentSize


@dataclass(frozen=True, slots=True)
class AlgorithmCase:
    """Describe one implementation and key-size combination."""

    identifier: str
    algorithm: type[Aes]
    key: bytes


AES_128_KEY: Final[bytes] = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
AES_192_KEY: Final[bytes] = bytes.fromhex(
    '000102030405060708090A0B0C0D0E0F1011121314151617'
)
AES_256_KEY: Final[bytes] = bytes.fromhex(
    '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F'
)

ALGORITHM_CASES: Final[tuple[AlgorithmCase, ...]] = (
    AlgorithmCase('aes-128', Aes128, AES_128_KEY),
    AlgorithmCase('aes-192', Aes192, AES_192_KEY),
    AlgorithmCase('aes-256', Aes256, AES_256_KEY),
    AlgorithmCase('reference-aes-128', ReferenceAes128, AES_128_KEY),
    AlgorithmCase('reference-aes-192', ReferenceAes192, AES_192_KEY),
    AlgorithmCase('reference-aes-256', ReferenceAes256, AES_256_KEY),
)
ALGORITHM_CASE_IDENTIFIERS: Final[tuple[str, ...]] = tuple(
    algorithm_case.identifier for algorithm_case in ALGORITHM_CASES
)

INITIALIZATION_VALUE: Final[bytes] = bytes.fromhex('F0E0D0C0B0A090807060504030201000')

SINGLE_BLOCK_PLAINTEXTS: Final[tuple[bytes, ...]] = (
    bytes(16),
    bytes(range(16)),
    bytes.fromhex('00112233445566778899AABBCCDDEEFF'),
    bytes.fromhex('FFEEDDCCBBAA99887766554433221100'),
)

BLOCK_ALIGNED_PLAINTEXTS: Final[tuple[bytes, ...]] = (
    bytes(0),
    bytes(range(16)),
    bytes(range(32)),
    bytes(range(48)),
    bytes(0).join(
        (
            b'6BC1BEE22E409F96E93D7E117393172A',
            b'AE2D8A571E03AC9C9EB76FAC45AF8E51',
            b'30C81C46A35CE411E5FBC1191A0A52EF',
            b'F69F2445DF4F9B17AD2B417BE66C3710',
        )
    ),
)

ARBITRARY_LENGTH_PLAINTEXTS: Final[tuple[bytes, ...]] = (
    bytes(0),
    bytes([0]),
    bytes(range(2)),
    bytes(range(15)),
    bytes(range(16)),
    bytes(range(17)),
    bytes(range(31)),
    bytes(range(32)),
    bytes(range(33)),
    bytes(range(65)),
)

CFB_SEGMENT_SIZES: Final[tuple[CfbSegmentSize, ...]] = tuple(
    range(1, AES_BLOCK_SIZE + 1),  # type: ignore[arg-type]
)

COUNTER_VALUES: Final[tuple[int, ...]] = (0, 1, 0x00112233445566778899AABBCCDDEEFF)

COUNTER_ROLLOVER_INITIAL_VALUE: Final[int] = (1 << 128) - 4
COUNTER_ROLLOVER_PLAINTEXT: Final[bytes] = bytes(range(65))
