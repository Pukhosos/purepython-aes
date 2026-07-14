from itertools import product

from hypothesis import given
from hypothesis.strategies import binary
from pytest import mark

from purepython_aes import (
    Aes,
    Aes128,
    Aes192,
    Aes256,
    CfbMode,
    ReferenceAes128,
    ReferenceAes192,
    ReferenceAes256,
)
from purepython_aes.types import CfbSegmentSize
from tests.unit.aes.strategies import aes256key


@mark.quick
class TestCfbMode:
    @staticmethod
    @mark.parametrize(
        ['aes', 'segment_size'],
        tuple(
            product(
                [
                    Aes128,
                    Aes192,
                    Aes256,
                    ReferenceAes128,
                    ReferenceAes192,
                    ReferenceAes256,
                ],
                [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            ),
        ),
    )
    @given(key=aes256key, data=binary())
    def test_decrypt_inverts_encrypt(
        aes: type[Aes],
        segment_size: CfbSegmentSize,
        key: bytes,
        data: bytes,
    ) -> None:
        cfb: CfbMode = CfbMode(aes(key[:aes.__key_size__]), segment_size)  # fmt: skip
        assert cfb.decrypt(cfb.encrypt(data)) == data
