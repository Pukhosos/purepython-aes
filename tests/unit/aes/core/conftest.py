from pytest import fixture


@fixture
def example_plaintext() -> bytes:
    return bytes.fromhex('00112233445566778899aabbccddeeff')


@fixture
def spa_800_38a_plaintexts() -> tuple[bytes, bytes, bytes, bytes]:
    return (
        bytes.fromhex('6bc1bee22e409f96e93d7e117393172a'),
        bytes.fromhex('ae2d8a571e03ac9c9eb76fac45af8e51'),
        bytes.fromhex('30c81c46a35ce411e5fbc1191a0a52ef'),
        bytes.fromhex('f69f2445df4f9b17ad2b417be66c3710'),
    )
