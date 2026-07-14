from pytest import mark, raises

from purepython_aes.aes.core import AesCore


@mark.quick
class TestAesCore:
    @staticmethod
    def test_creation_fail() -> None:
        with raises(
            expected_exception=AttributeError,
            match=f'{AesCore.__name__!r} object has no attribute \'__key_size__\'',
        ):
            AesCore(key=b'00112233445566778899aabbccddeeff')
