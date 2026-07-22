from pytest import mark, raises

from purepython_aes.aes.core import ReferenceAesCore


@mark.quick
class TestAesCore:
    @staticmethod
    def test_creation_fail() -> None:
        with raises(
            expected_exception=AttributeError,
            match=f'{ReferenceAesCore.__name__!r} object has no attribute',
        ):
            ReferenceAesCore(key=b'00112233445566778899aabbccddeeff')
