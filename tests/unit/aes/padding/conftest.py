from pytest import fixture

from purepython_aes import (
    AnsiX923Padding,
    Iso7816Padding,
    Iso10126Padding,
    NoPadding,
    Pkcs7Padding,
    ZeroPadding,
)


@fixture
def ansix923() -> AnsiX923Padding:
    return AnsiX923Padding()


@fixture
def iso7816() -> Iso7816Padding:
    return Iso7816Padding()


@fixture
def iso10126() -> Iso10126Padding:
    return Iso10126Padding()


@fixture
def no() -> NoPadding:
    return NoPadding()


@fixture
def pkcs7() -> Pkcs7Padding:
    return Pkcs7Padding()


@fixture
def zero() -> ZeroPadding:
    return ZeroPadding()
