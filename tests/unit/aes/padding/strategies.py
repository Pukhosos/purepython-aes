from hypothesis.strategies import binary, composite, DrawFn

from purepython_aes.const import AES_BLOCK_SIZE


@composite
def aligned_messages(draw: DrawFn) -> bytes:
    return draw(binary()) * AES_BLOCK_SIZE
