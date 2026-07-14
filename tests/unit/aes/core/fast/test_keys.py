from hypothesis import given
from pytest import mark

from purepython_aes.aes.core.fast.expansion import (
    expand_aes128_key,
    expand_aes192_key,
    expand_aes256_key,
)
from purepython_aes.aes.core.fast.keys import build_decryption_round_keys
from purepython_aes.const import (
    AES_128_ROUND_COUNT,
    AES_192_ROUND_COUNT,
    AES_256_ROUND_COUNT,
)
from purepython_aes.types import RoundKeys
from tests.unit.aes.strategies import aes128key, aes192key, aes256key


@mark.quick
@mark.parametrize(
    'round_count',
    (
        AES_128_ROUND_COUNT,
        AES_192_ROUND_COUNT,
        AES_256_ROUND_COUNT,
    ),
)
def test_preserves_round_key_count(round_count: int) -> None:
    encryption_round_keys: RoundKeys = [
        (round_index, round_index, round_index, round_index)
        for round_index in range(round_count)
    ]
    decryption_round_keys: RoundKeys = build_decryption_round_keys(
        encryption_round_keys
    )
    assert len(decryption_round_keys) == round_count


@mark.quick
def test_first_decryption_key_is_last_encryption_key() -> None:
    encryption_round_keys: RoundKeys = [
        (0x00000000, 0x11111111, 0x22222222, 0x33333333),
        (0x44444444, 0x55555555, 0x66666666, 0x77777777),
        (0x88888888, 0x99999999, 0xAAAAAAAA, 0xBBBBBBBB),
    ]
    decryption_round_keys: RoundKeys = build_decryption_round_keys(
        encryption_round_keys
    )
    assert decryption_round_keys[0] == encryption_round_keys[-1]


@mark.quick
def test_last_decryption_key_is_first_encryption_key() -> None:
    encryption_round_keys: RoundKeys = [
        (0x00000000, 0x11111111, 0x22222222, 0x33333333),
        (0x44444444, 0x55555555, 0x66666666, 0x77777777),
        (0x88888888, 0x99999999, 0xAAAAAAAA, 0xBBBBBBBB),
    ]
    decryption_round_keys: RoundKeys = build_decryption_round_keys(
        encryption_round_keys
    )
    assert decryption_round_keys[-1] == encryption_round_keys[0]


@mark.quick
@given(key=aes128key)
def test_accepts_aes128_expansion(key: bytes) -> None:
    encryption_round_keys: RoundKeys = expand_aes128_key(key)
    decryption_round_keys: RoundKeys = build_decryption_round_keys(
        encryption_round_keys
    )
    assert len(decryption_round_keys) == AES_128_ROUND_COUNT + 1
    assert decryption_round_keys[0] == encryption_round_keys[-1]
    assert decryption_round_keys[-1] == encryption_round_keys[0]


@mark.quick
@given(key=aes192key)
def test_accepts_aes192_expansion(key: bytes) -> None:
    encryption_round_keys: RoundKeys = expand_aes192_key(key)
    decryption_round_keys: RoundKeys = build_decryption_round_keys(
        encryption_round_keys
    )
    assert len(decryption_round_keys) == AES_192_ROUND_COUNT + 1
    assert decryption_round_keys[0] == encryption_round_keys[-1]
    assert decryption_round_keys[-1] == encryption_round_keys[0]


@mark.quick
@given(key=aes256key)
def test_accepts_aes256_expansion(key: bytes) -> None:
    encryption_round_keys: RoundKeys = expand_aes256_key(key)
    decryption_round_keys: RoundKeys = build_decryption_round_keys(
        encryption_round_keys
    )
    assert len(decryption_round_keys) == AES_256_ROUND_COUNT + 1
    assert decryption_round_keys[0] == encryption_round_keys[-1]
    assert decryption_round_keys[-1] == encryption_round_keys[0]
