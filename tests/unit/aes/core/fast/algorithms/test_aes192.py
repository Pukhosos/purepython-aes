from hypothesis import given
from pytest import mark

from purepython_aes import Aes192
from purepython_aes.const import AES_192_KEY_SIZE, AES_192_ROUND_COUNT
from tests.unit.aes.core.fast.algorithms.strategies import aes192
from tests.unit.aes.strategies import aes_blocks


@mark.quick
class TestAes192:
    @staticmethod
    def test_aes_192_key_size() -> None:
        assert Aes192(bytes(AES_192_KEY_SIZE)).__key_size__ == AES_192_KEY_SIZE

    @staticmethod
    def test_aes_192_round_count() -> None:
        assert Aes192(bytes(AES_192_KEY_SIZE)).__round_count__ == AES_192_ROUND_COUNT

    @staticmethod
    def test_fips_197_aes_192_known_answer(example_plaintext: bytes) -> None:
        key: bytes = bytes.fromhex('000102030405060708090a0b0c0d0e0f1011121314151617')
        ciphertext: bytes = bytes.fromhex('dda97ca4864cdfe06eaf70a0ec0d7191')
        assert Aes192(key).encrypt_block(example_plaintext) == ciphertext

    @staticmethod
    def test_spa_800_38a_plaintexts(
        spa_800_38a_plaintexts: tuple[bytes, bytes, bytes, bytes],
    ) -> None:
        aes: Aes192 = Aes192(
            key=bytes.fromhex('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b'),
        )
        assert aes.encrypt_block(spa_800_38a_plaintexts[0]) == bytes.fromhex(
            'bd334f1d6e45f25ff712a214571fa5cc'
        )
        assert aes.encrypt_block(spa_800_38a_plaintexts[1]) == bytes.fromhex(
            '974104846d0ad3ad7734ecb3ecee4eef'
        )
        assert aes.encrypt_block(spa_800_38a_plaintexts[2]) == bytes.fromhex(
            'ef7afd2270e2e60adce0ba2face6444e'
        )
        assert aes.encrypt_block(spa_800_38a_plaintexts[3]) == bytes.fromhex(
            '9a4b41ba738d6c72fb16691603c18e0e'
        )

    @staticmethod
    @given(aes=aes192, block=aes_blocks)
    def test_aes192_decrypt_block_inverts_encrypt_block(
        aes: Aes192,
        block: bytes,
    ) -> None:
        assert aes.decrypt_block(aes.encrypt_block(block)) == block

    @staticmethod
    @given(aes=aes192, block=aes_blocks)
    def test_aes192_encrypt_block_inverts_decrypt_block(
        aes: Aes192,
        block: bytes,
    ) -> None:
        assert aes.encrypt_block(aes.decrypt_block(block)) == block
