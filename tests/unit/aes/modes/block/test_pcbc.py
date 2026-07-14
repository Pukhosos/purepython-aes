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
    Iso7816Padding,
    Iso10126Padding,
    NoPadding,
    PcbcMode,
    Pkcs7Padding,
    ReferenceAes128,
    ReferenceAes192,
    ReferenceAes256,
    ZeroPadding,
)
from tests.unit.aes.strategies import aes256key, aes_blocks


@mark.quick
class TestPcbcMode:
    @staticmethod
    @mark.parametrize(
        ['aes', 'padding'],
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
        pcbc: PcbcMode = PcbcMode(aes(key[:aes.__key_size__]), padding())  # fmt: skip
        assert pcbc.decrypt(pcbc.encrypt(data)) == data

    @staticmethod
    @mark.parametrize(['aes'], [[Aes128], [Aes192], [Aes256]])
    @given(key=aes256key, data=binary())
    def test_decrypt_inverts_encrypt_zero_padding(
        aes: type[Aes],
        key: bytes,
        data: bytes,
    ) -> None:
        assume(not data.endswith(bytes(1)))
        pcbc: PcbcMode = PcbcMode(
            algorithm=aes(key[:aes.__key_size__]),  # fmt: skip
            padding=ZeroPadding(),
        )
        assert pcbc.decrypt(pcbc.encrypt(data)) == data

    @staticmethod
    @mark.parametrize(['aes'], [[Aes128], [Aes192], [Aes256]])
    @given(key=aes256key, data=aes_blocks)
    def test_decrypt_inverts_encrypt_no_padding(
        aes: type[Aes],
        key: bytes,
        data: bytes,
    ) -> None:
        pcbc: PcbcMode = PcbcMode(aes(key[:aes.__key_size__]), NoPadding())  # fmt: skip
        assert pcbc.decrypt(pcbc.encrypt(data)) == data
