from re import escape

from hypothesis import given, HealthCheck, settings
from pytest import mark, raises

from purepython_aes import NoPadding
from purepython_aes.const import AES_BLOCK_SIZE
from tests.unit.aes.padding.strategies import aligned_messages


@mark.quick
class TestNoPadding:
    @staticmethod
    def test_pad_empty_data_returns_empty_data(no: NoPadding) -> None:
        assert no.pad(bytes(0)) == bytes(0)

    @staticmethod
    def test_unpad_empty_data_returns_empty_data(no: NoPadding) -> None:
        assert no.unpad(bytes(0)) == bytes(0)

    @staticmethod
    def test_pad_aligned_data_returns_data_unchanged(no: NoPadding) -> None:
        data: bytes = bytes(range(AES_BLOCK_SIZE * 2))
        assert no.pad(data) == data

    @staticmethod
    def test_unpad_aligned_data_returns_data_unchanged(no: NoPadding) -> None:
        data: bytes = bytes(range(AES_BLOCK_SIZE * 2))
        assert no.unpad(data) == data

    @staticmethod
    def test_pad_rejects_unaligned_data(no: NoPadding) -> None:
        with raises(
            expected_exception=ValueError,
            match=escape('expected len(data) % 16 == 0, got 15'),
        ):
            no.pad(bytes(AES_BLOCK_SIZE - 1))

    @staticmethod
    @given(data=aligned_messages())
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_unpad_inverts_pad(no: NoPadding, data: bytes) -> None:
        assert no.unpad(no.pad(data)) == data
