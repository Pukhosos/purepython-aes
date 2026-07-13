from re import escape

from hypothesis import given, HealthCheck, settings
from hypothesis.strategies import binary
from pytest import mark, raises

from purepython_aes import Iso7816Padding
from purepython_aes.const import AES_BLOCK_SIZE


@mark.quick
class TestIso7816Padding:
    @staticmethod
    def test_pad_empty_data_adds_full_block(iso7816: Iso7816Padding) -> None:
        assert iso7816.pad(bytes(0)) == b'\x80' + bytes(AES_BLOCK_SIZE - 1)

    @staticmethod
    def test_pad_partial_block(iso7816: Iso7816Padding) -> None:
        assert iso7816.pad(b'ABC') == b'ABC\x80' + bytes(12)

    @staticmethod
    def test_pad_aligned_data_adds_full_block(iso7816: Iso7816Padding) -> None:
        data: bytes = bytes(range(AES_BLOCK_SIZE))
        assert iso7816.pad(data) == data + b'\x80' + bytes(AES_BLOCK_SIZE - 1)

    @staticmethod
    def test_payload_end_with_marker_and_zeroes(iso7816: Iso7816Padding) -> None:
        data: bytes = b'payload\x80\x00\x00'
        assert iso7816.unpad(iso7816.pad(data)) == data

    @staticmethod
    def test_unpad_rejects_unaligned_data(iso7816: Iso7816Padding) -> None:
        with raises(
            expected_exception=ValueError,
            match=escape('ISO/IEC 7816-4 padding marker not found'),
        ):
            iso7816.unpad(bytes(AES_BLOCK_SIZE - 1))

    @staticmethod
    def test_unpad_rejects_missing_marker(iso7816: Iso7816Padding) -> None:
        with raises(
            expected_exception=ValueError,
            match=escape('ISO/IEC 7816-4 padding marker not found'),
        ):
            iso7816.unpad(bytes(AES_BLOCK_SIZE))

    @staticmethod
    def test_unpad_rejects_wrong_final_nonzero_byte(iso7816: Iso7816Padding) -> None:
        with raises(
            expected_exception=ValueError,
            match=escape('invalid ISO/IEC 7816-4 padding marker'),
        ):
            iso7816.unpad(b'A' * 13 + b'\x7f\x00\x00')

    @staticmethod
    def test_unpad_rejects_marker_more_than_one_block_from_end(
        iso7816: Iso7816Padding,
    ) -> None:
        with raises(
            expected_exception=ValueError,
            match=escape('invalid ISO/IEC 7816-4 padding size'),
        ):
            iso7816.unpad(b'\x80' + bytes((AES_BLOCK_SIZE * 2) - 1))

    @staticmethod
    @given(data=binary())
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_unpad_inverts_pad(iso7816: Iso7816Padding, data: bytes) -> None:
        padded_data: bytes = iso7816.pad(data)
        unpadded_data: bytes = iso7816.unpad(padded_data)
        assert unpadded_data == data

    @staticmethod
    @given(data=binary())
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_padding_structure(iso7816: Iso7816Padding, data: bytes) -> None:
        padded_data: bytes = iso7816.pad(data)
        padding_size: int = AES_BLOCK_SIZE - len(data) % AES_BLOCK_SIZE
        assert len(padded_data) % AES_BLOCK_SIZE == 0
        assert len(padded_data) == len(data) + padding_size
        assert padded_data[: len(data)] == data
        assert padded_data[len(data)] == 0x80
        assert padded_data[len(data) + 1 :] == bytes(padding_size - 1)
