from hypothesis import given
from pytest import mark

from purepython_aes import Aes256
from purepython_aes.const import AES_256_KEY_SIZE, AES_256_ROUND_COUNT
from tests.unit.aes.strategies import aes256, aes_blocks


@mark.quick
class TestAes256:
    @staticmethod
    def test_aes_256_key_size() -> None:
        assert Aes256(bytes(AES_256_KEY_SIZE)).__key_size__ == AES_256_KEY_SIZE

    @staticmethod
    def test_aes_256_round_count() -> None:
        assert Aes256(bytes(AES_256_KEY_SIZE)).__round_count__ == AES_256_ROUND_COUNT

    @staticmethod
    def test_fips_197_aes_256_known_answer(example_plaintext: bytes) -> None:
        key: bytes = bytes.fromhex(
            '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        )
        ciphertext: bytes = bytes.fromhex('8ea2b7ca516745bfeafc49904b496089')
        assert Aes256(key).encrypt_block(example_plaintext) == ciphertext

    @staticmethod
    def test_spa_800_38a_plaintexts(
        spa_800_38a_plaintexts: tuple[bytes, bytes, bytes, bytes],
    ) -> None:
        aes: Aes256 = Aes256(
            key=bytes.fromhex(
                '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
            ),
        )
        assert aes.encrypt_block(spa_800_38a_plaintexts[0]) == bytes.fromhex(
            'f3eed1bdb5d2a03c064b5a7e3db181f8'
        )
        assert aes.encrypt_block(spa_800_38a_plaintexts[1]) == bytes.fromhex(
            '591ccb10d410ed26dc5ba74a31362870'
        )
        assert aes.encrypt_block(spa_800_38a_plaintexts[2]) == bytes.fromhex(
            'b6ed21b99ca6f4f9f153e7b1beafed1d'
        )
        assert aes.encrypt_block(spa_800_38a_plaintexts[3]) == bytes.fromhex(
            '23304b7a39f9f3ff067d8d8f9e24ecc7'
        )

    @staticmethod
    @given(aes=aes256, block=aes_blocks)
    def test_aes256_decrypt_block_inverts_encrypt_block(
        aes: Aes256,
        block: bytes,
    ) -> None:
        assert aes.decrypt_block(aes.encrypt_block(block)) == block

    @staticmethod
    @given(aes=aes256, block=aes_blocks)
    def test_aes256_encrypt_block_inverts_decrypt_block(
        aes: Aes256,
        block: bytes,
    ) -> None:
        assert aes.encrypt_block(aes.decrypt_block(block)) == block
