from hypothesis import given
from hypothesis.strategies import binary
from pytest import mark

from purepython_aes import (
    Aes,
    Aes128,
    Aes192,
    Aes256,
    CtrMode,
    ReferenceAes128,
    ReferenceAes192,
    ReferenceAes256,
)
from tests.unit.aes.strategies import aes256key


@mark.quick
class TestCtrMode:
    @staticmethod
    @mark.parametrize(
        'aes',
        [Aes128, Aes192, Aes256, ReferenceAes128, ReferenceAes192, ReferenceAes256],
    )
    @given(key=aes256key, data=binary())
    def test_decrypt_inverts_encrypt(aes: type[Aes], key: bytes, data: bytes) -> None:
        ctr: CtrMode = CtrMode(aes(key[:aes.__key_size__]))  # fmt: skip
        assert ctr.decrypt(ctr.encrypt(data)) == data
