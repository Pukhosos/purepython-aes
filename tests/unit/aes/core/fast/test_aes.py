from pytest import mark, raises

from purepython_aes.aes.core import FastAesCore


@mark.quick
class TestFastAesCore:
    @staticmethod
    def test_creation_fail() -> None:
        with raises(
            expected_exception=AttributeError,
            match=f'{FastAesCore.__name__!r} object has no attribute \'__key_size__\'',
        ):
            FastAesCore(key=b'00112233445566778899aabbccddeeff')
