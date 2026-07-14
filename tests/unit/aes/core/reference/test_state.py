from re import escape

from hypothesis import given
from pytest import mark, raises

from purepython_aes.aes.core.reference.state import AesState
from purepython_aes.const import AES_BLOCK_SIZE, INVERSE_SBOX, SBOX
from tests.unit.aes.strategies import aes_blocks


@mark.quick
class TestAesState:
    @staticmethod
    @given(block=aes_blocks)
    def test_from_bytes_round_trips(block: bytes) -> None:
        state: AesState = AesState.from_bytes(block)
        assert state.to_bytes() == block

    @staticmethod
    @mark.parametrize('block', (bytes(), bytes(1), bytes(15), bytes(17), bytes(32)))
    def test_from_bytes_rejects_invalid_block_lengths(block: bytes) -> None:
        with raises(
            expected_exception=ValueError,
            match=f'expected {AES_BLOCK_SIZE} values, got {len(block)}',
        ):
            AesState.from_bytes(block)

    @staticmethod
    def test_constructor_rejects_external_calls() -> None:
        with raises(
            expected_exception=ValueError,
            match=escape('AesState() must not be called externally'),
        ):
            AesState(object(), values=([0x00] * AES_BLOCK_SIZE))

    @staticmethod
    @given(block=aes_blocks)
    def test_to_bytes(block: bytes) -> None:
        assert AesState.from_bytes(block).to_bytes() == block

    @staticmethod
    @given(block=aes_blocks, key=aes_blocks)
    def test_add_round_key_xors_each_byte(block: bytes, key: bytes) -> None:
        state: AesState = AesState.from_bytes(block)
        state.add_round_key(key)
        assert state.to_bytes() == bytes(
            left ^ right for left, right in zip(block, key, strict=True)
        )

    @staticmethod
    @given(block=aes_blocks)
    def test_subs_bytes_applies_sbox(block: bytes) -> None:
        state: AesState = AesState.from_bytes(block)
        expected: bytes = bytes(SBOX[value] for value in block)
        state.subs_bytes()
        assert state.to_bytes() == expected

    @staticmethod
    @given(block=aes_blocks)
    def test_inverse_subs_bytes_applies_inverse_sbox(block: bytes) -> None:
        state: AesState = AesState.from_bytes(block)
        expected: bytes = bytes(INVERSE_SBOX[value] for value in block)
        state.inverse_subs_bytes()
        assert state.to_bytes() == expected

    @staticmethod
    @given(block=aes_blocks)
    def test_inverse_subs_bytes_reverses_subs_bytes(block: bytes) -> None:
        state: AesState = AesState.from_bytes(block)
        state.subs_bytes()
        state.inverse_subs_bytes()
        assert state.to_bytes() == block

    @staticmethod
    @given(block=aes_blocks)
    def test_subs_bytes_reverses_inverse_subs_bytes(block: bytes) -> None:
        state: AesState = AesState.from_bytes(block)
        state.inverse_subs_bytes()
        state.subs_bytes()
        assert state.to_bytes() == block

    @staticmethod
    def test_shift_rows_known_vector() -> None:
        state: AesState = AesState.from_bytes(bytes(range(16)))
        state.shift_rows()
        assert state.to_bytes() == bytes(
            (0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11)
        )

    @staticmethod
    def test_inverse_shift_rows_known_vector() -> None:
        state: AesState = AesState.from_bytes(bytes(range(16)))
        state.inverse_shift_rows()
        assert state.to_bytes() == bytes(
            (0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3)
        )

    @staticmethod
    @given(block=aes_blocks)
    def test_inverse_shift_rows_reverses_shift_rows(block: bytes) -> None:
        state: AesState = AesState.from_bytes(block)
        state.shift_rows()
        state.inverse_shift_rows()
        assert state.to_bytes() == block

    @staticmethod
    @given(block=aes_blocks)
    def test_shift_rows_reverses_inverse_shift_rows(block: bytes) -> None:
        state: AesState = AesState.from_bytes(block)
        state.inverse_shift_rows()
        state.shift_rows()
        assert state.to_bytes() == block

    @staticmethod
    @given(block=aes_blocks)
    def test_four_shift_rows_operations_restore_state(block: bytes) -> None:
        state: AesState = AesState.from_bytes(block)
        for _ in range(4):
            state.shift_rows()
        assert state.to_bytes() == block

    @staticmethod
    def test_mix_columns_known_vector() -> None:
        block: bytes = bytes(
            (
                0xDB, 0x13, 0x53, 0x45,  # fmt: skip
                0xF2, 0x0A, 0x22, 0x5C,  # fmt: skip
                0x01, 0x01, 0x01, 0x01,  # fmt: skip
                0xC6, 0xC6, 0xC6, 0xC6,  # fmt: skip
            ),
        )
        expected: bytes = bytes(
            (
                0x8E, 0x4D, 0xA1, 0xBC,  # fmt: skip
                0x9F, 0xDC, 0x58, 0x9D,  # fmt: skip
                0x01, 0x01, 0x01, 0x01,  # fmt: skip
                0xC6, 0xC6, 0xC6, 0xC6,  # fmt: skip
            ),
        )
        state: AesState = AesState.from_bytes(block)
        state.mix_columns()
        assert state.to_bytes() == expected

    @staticmethod
    def test_inverse_mix_columns_known_vector() -> None:
        block: bytes = bytes(
            (
                0x8E, 0x4D, 0xA1, 0xBC,  # fmt: skip
                0x9F, 0xDC, 0x58, 0x9D,  # fmt: skip
                0x01, 0x01, 0x01, 0x01,  # fmt: skip
                0xC6, 0xC6, 0xC6, 0xC6,  # fmt: skip
            ),
        )
        expected: bytes = bytes(
            (
                0xDB, 0x13, 0x53, 0x45,  # fmt: skip
                0xF2, 0x0A, 0x22, 0x5C,  # fmt: skip
                0x01, 0x01, 0x01, 0x01,  # fmt: skip
                0xC6, 0xC6, 0xC6, 0xC6,  # fmt: skip
            ),
        )
        state: AesState = AesState.from_bytes(block)
        state.inverse_mix_columns()
        assert state.to_bytes() == expected

    @staticmethod
    @given(block=aes_blocks)
    def test_inverse_mix_columns_reverses_mix_columns(block: bytes) -> None:
        state: AesState = AesState.from_bytes(block)
        state.mix_columns()
        state.inverse_mix_columns()
        assert state.to_bytes() == block

    @staticmethod
    @given(block=aes_blocks)
    def test_mix_columns_reverses_inverse_mix_columns(block: bytes) -> None:
        state: AesState = AesState.from_bytes(block)
        state.inverse_mix_columns()
        state.mix_columns()
        assert state.to_bytes() == block

    @staticmethod
    @given(block=aes_blocks, key=aes_blocks)
    def test_full_forward_and_inverse_sequence(block: bytes, key: bytes) -> None:
        state: AesState = AesState.from_bytes(block)
        state.subs_bytes()
        state.shift_rows()
        state.mix_columns()
        state.add_round_key(key)
        state.add_round_key(key)
        state.inverse_mix_columns()
        state.inverse_shift_rows()
        state.inverse_subs_bytes()
        assert state.to_bytes() == block
