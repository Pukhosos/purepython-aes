from hypothesis import given
from hypothesis.strategies import binary
from pytest import mark, raises

from purepython_aes.aes.modes.block.operations import split_into_blocks, xor
from purepython_aes.const import AES_BLOCK_SIZE


@mark.quick
def test_xor_empty_inputs() -> None:
    assert xor(bytes(0), bytes(0)) == bytes(0)


@mark.quick
@mark.parametrize(
    ('left', 'right', 'expected'),
    [
        (b'\x00', b'\x00', b'\x00'),
        (b'\x00', b'\xff', b'\xff'),
        (b'\xff', b'\xff', b'\x00'),
        (b'\x0f', b'\xf0', b'\xff'),
        (
            bytes.fromhex('00112233445566778899aabbccddeeff'),
            bytes.fromhex('ffffffffffffffffffffffffffffffff'),
            bytes.fromhex('ffeeddccbbaa99887766554433221100'),
        ),
        (
            b'hello',
            b'world',
            bytes(
                [
                    ord('h') ^ ord('w'),
                    ord('e') ^ ord('o'),
                    ord('l') ^ ord('r'),
                    ord('l') ^ ord('l'),
                    ord('o') ^ ord('d'),
                ]
            ),
        ),
    ],
)
def test_xor_known_values(left: bytes, right: bytes, expected: bytes) -> None:
    assert xor(left, right) == expected


@mark.quick
@mark.parametrize(
    ('left', 'right'),
    [
        (b'\x00', bytes(0)),
        (bytes(0), b'\x00'),
        (b'\x00\x01', b'\x00'),
        (b'\x00', b'\x00\x01'),
        (bytes(AES_BLOCK_SIZE), bytes(AES_BLOCK_SIZE + 1)),
    ],
)
def test_xor_rejects_inputs_of_different_lengths(
    left: bytes,
    right: bytes,
) -> None:
    with raises(
        expected_exception=ValueError,
        match=r'zip\(\) argument 2 is (?:shorter|longer) than argument 1',
    ):
        xor(left, right)


@mark.quick
@given(value=binary())
def test_xor_with_itself_is_zero(value: bytes) -> None:
    assert xor(value, value) == bytes(len(value))


@mark.quick
def test_split_into_blocks_empty_input() -> None:
    assert split_into_blocks(bytes(0)) == ()


@mark.quick
def test_split_into_blocks_single_complete_block() -> None:
    data: bytes = bytes(range(AES_BLOCK_SIZE))
    assert split_into_blocks(data) == (data,)


@mark.quick
def test_split_into_blocks_multiple_complete_blocks() -> None:
    block0: bytes = bytes([0x11]) * AES_BLOCK_SIZE
    block1: bytes = bytes([0x22]) * AES_BLOCK_SIZE
    block2: bytes = bytes([0x33]) * AES_BLOCK_SIZE
    assert split_into_blocks(block0 + block1 + block2) == (block0, block1, block2)


@mark.quick
def test_split_into_blocks_input_smaller_than_one_block() -> None:
    data: bytes = b'partial'
    assert split_into_blocks(data) == (data,)


@mark.quick
@mark.parametrize('remainder_size', tuple(range(1, AES_BLOCK_SIZE)))
def test_split_into_blocks_includes_a_final_partial_block(remainder_size: int) -> None:
    complete_block: bytes = bytes([0x11]) * AES_BLOCK_SIZE
    remainder: bytes = bytes([0x22]) * remainder_size
    assert split_into_blocks(complete_block + remainder) == (complete_block, remainder)


@mark.quick
def test_split_into_blocks_uses_original_order() -> None:
    data: bytes = bytes(range(3 * AES_BLOCK_SIZE))
    blocks = split_into_blocks(data)
    assert blocks[0] == data[:AES_BLOCK_SIZE]
    assert blocks[1] == data[AES_BLOCK_SIZE : (2 * AES_BLOCK_SIZE)]
    assert blocks[2] == data[(2 * AES_BLOCK_SIZE) :]


@mark.quick
def test_split_into_blocks_does_not_pad_partial_block() -> None:
    remainder: bytes = b'\xaa\xbb\xcc'
    data: bytes = bytes(AES_BLOCK_SIZE) + remainder
    blocks: tuple[bytes, ...] = split_into_blocks(data)
    assert blocks[-1] == remainder
    assert len(blocks[-1]) == len(remainder)


@mark.quick
def test_split_into_blocks_does_not_drop_partial_block() -> None:
    blocks: tuple[bytes, ...] = split_into_blocks(bytes(AES_BLOCK_SIZE + 1))
    assert len(blocks) == 2
    assert len(blocks[-1]) == 1


@mark.quick
@given(binary())
def test_split_blocks_reassemble_to_original_data(data: bytes) -> None:
    assert bytes(0).join(split_into_blocks(data)) == data


@mark.quick
@given(binary())
def test_split_never_returns_empty_blocks(data: bytes) -> None:
    assert all(len(block) != 0 for block in split_into_blocks(data))
