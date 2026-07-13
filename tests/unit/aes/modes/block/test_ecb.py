from itertools import product

from hypothesis import assume, given
from hypothesis.strategies import binary
from pytest import mark

from purepython_aes import (
    Aes,
    Aes128,
    Aes192,
    Aes256,
    AnsiX923Padding,
    BasePadding,
    EcbMode,
    Iso7816Padding,
    Iso10126Padding,
    NoPadding,
    Pkcs7Padding,
    ZeroPadding,
)
from tests.unit.aes.strategies import aes256key, aes_blocks


@mark.quick
class TestEcbMode:
    @staticmethod
    @mark.parametrize(
        ['aes', 'padding'],
        tuple(
            product(
                [Aes128, Aes192, Aes256],
                [AnsiX923Padding, Iso10126Padding, Iso7816Padding, Pkcs7Padding],
            ),
        ),
    )
    @given(key=aes256key, data=binary())
    def test_decrypt_inverts_encrypt(
        aes: type[Aes],
        padding: type[BasePadding],
        key: bytes,
        data: bytes,
    ) -> None:
        ecb: EcbMode = EcbMode(aes(key[:aes.__key_size__]), padding())  # fmt: skip
        assert ecb.decrypt(ecb.encrypt(data)) == data

    @staticmethod
    @mark.parametrize(['aes'], [[Aes128], [Aes192], [Aes256]])
    @given(key=aes256key, data=binary())
    def test_decrypt_inverts_encrypt_zero_padding(
        aes: type[Aes],
        key: bytes,
        data: bytes,
    ) -> None:
        assume(not data.endswith(bytes(1)))
        ecb: EcbMode = EcbMode(aes(key[:aes.__key_size__]), ZeroPadding())  # fmt: skip
        assert ecb.decrypt(ecb.encrypt(data)) == data

    @staticmethod
    @mark.parametrize(['aes'], [[Aes128], [Aes192], [Aes256]])
    @given(key=aes256key, data=aes_blocks)
    def test_decrypt_inverts_encrypt_no_padding(
        aes: type[Aes],
        key: bytes,
        data: bytes,
    ) -> None:
        ecb: EcbMode = EcbMode(aes(key[:aes.__key_size__]), NoPadding())  # fmt: skip
        assert ecb.decrypt(ecb.encrypt(data)) == data
