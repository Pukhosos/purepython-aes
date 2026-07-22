from typing import ClassVar

from hypothesis import given, HealthCheck, settings
from hypothesis.strategies import binary
from pytest import mark, MonkeyPatch, raises

from purepython_aes import Iso10126Padding
from purepython_aes.const import AES_BLOCK_SIZE


class PatchTokenBytes:
    requested_length: ClassVar[int]

    @staticmethod
    def deterministic_token_bytes_0x5A(length: int) -> bytes:  # noqa: N802
        return bytes([0x5A]) * length

    @classmethod
    def deterministic_token_bytes_0xA5_writing(cls, length: int) -> bytes:  # noqa: N802
        cls.requested_length = length
        return bytes([0xA5]) * length

    @staticmethod
    def deterministic_token_bytes_zero(length: int) -> bytes:
        return bytes(range(length))


@mark.quick
class TestIso10126Padding:
    @staticmethod
    def test_pad_uses_random_fill_and_length_byte(
        iso10126: Iso10126Padding,
        monkeypatch: MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            'purepython_aes.aes.padding.iso10126.token_bytes',
            PatchTokenBytes.deterministic_token_bytes_0xA5_writing,
        )
        assert iso10126.pad(b'ABC') == b'ABC' + bytes([0xA5]) * 12 + b'\x0d'
        assert PatchTokenBytes.requested_length == 12

    @staticmethod
    def test_pad_empty_data_adds_full_block(
        iso10126: Iso10126Padding,
        monkeypatch: MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            'purepython_aes.aes.padding.iso10126.token_bytes',
            PatchTokenBytes.deterministic_token_bytes_zero,
        )
        assert iso10126.pad(bytes(0)) == bytes(range(AES_BLOCK_SIZE - 1)) + bytes(
            [AES_BLOCK_SIZE]
        )

    @staticmethod
    def test_pad_aligned_data_adds_full_block(
        iso10126: Iso10126Padding,
        monkeypatch: MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            'purepython_aes.aes.padding.iso10126.token_bytes',
            PatchTokenBytes.deterministic_token_bytes_0x5A,
        )
        data: bytes = bytes(range(AES_BLOCK_SIZE))
        assert iso10126.pad(data) == data + bytes([0x5A]) * 15 + bytes([AES_BLOCK_SIZE])

    @staticmethod
    def test_unpad_accepts_arbitrary_fill_bytes(iso10126: Iso10126Padding) -> None:
        assert iso10126.unpad(b'A' * 13 + b'\x00\xff\x03') == b'A' * 13

    @staticmethod
    def test_unpad_rejects_empty_data(iso10126: Iso10126Padding) -> None:
        with raises(
            expected_exception=IndexError,
            match='index out of range',
        ):
            iso10126.unpad(bytes(0))

    @staticmethod
    def test_unpad_rejects_unaligned_data(iso10126: Iso10126Padding) -> None:
        with raises(
            expected_exception=ValueError,
            match='invalid ISO 10126 padding size',
        ):
            iso10126.unpad(bytes(AES_BLOCK_SIZE - 1))

    @staticmethod
    def test_unpad_rejects_zero_padding_size(iso10126: Iso10126Padding) -> None:
        with raises(
            expected_exception=ValueError,
            match='invalid ISO 10126 padding size',
        ):
            iso10126.unpad(bytes(AES_BLOCK_SIZE))

    @staticmethod
    def test_unpad_rejects_padding_size_larger_than_block(
        iso10126: Iso10126Padding,
    ) -> None:
        with raises(
            expected_exception=ValueError,
            match='invalid ISO 10126 padding size',
        ):
            iso10126.unpad(bytes(AES_BLOCK_SIZE - 1) + bytes([AES_BLOCK_SIZE + 1]))

    @staticmethod
    @given(data=binary())
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_unpad_inverts_pad(iso10126: Iso10126Padding, data: bytes) -> None:
        assert iso10126.unpad(iso10126.pad(data)) == data

    @staticmethod
    @given(data=binary())
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_padding_structure(iso10126: Iso10126Padding, data: bytes) -> None:
        padded_data: bytes = iso10126.pad(data)
        padding_size: int = AES_BLOCK_SIZE - len(data) % AES_BLOCK_SIZE
        assert len(padded_data) % AES_BLOCK_SIZE == 0
        assert len(padded_data) == len(data) + padding_size
        assert padded_data[:len(data)] == data  # fmt: skip
        assert padded_data[-1] == padding_size
