from hypothesis import given

from purepython_aes.aes.algorithms import Aes128
from purepython_aes.const import AES_128_KEY_SIZE, AES_128_ROUND_COUNT
from tests.unit.aes.algorithms.strategies import aes128
from tests.unit.aes.strategies import aes_blocks


class TestAes128:
    @staticmethod
    def test_aes_128_key_size() -> None:
        assert Aes128(bytes(AES_128_KEY_SIZE)).key_size == AES_128_KEY_SIZE

    @staticmethod
    def test_aes_128_round_count() -> None:
        assert Aes128(bytes(AES_128_KEY_SIZE)).round_count == AES_128_ROUND_COUNT

    @staticmethod
    def test_fips_197_aes_128_known_answer(example_plaintext: bytes) -> None:
        key: bytes = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        ciphertext: bytes = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
        assert Aes128(key).encrypt_block(example_plaintext) == ciphertext

    @staticmethod
    def test_spa_800_38a_plaintexts(
        spa_800_38a_plaintexts: tuple[bytes, bytes, bytes, bytes],
    ) -> None:
        aes: Aes128 = Aes128(key=bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c'))
        assert aes.encrypt_block(spa_800_38a_plaintexts[0]) == bytes.fromhex(
            '3ad77bb40d7a3660a89ecaf32466ef97'
        )
        assert aes.encrypt_block(spa_800_38a_plaintexts[1]) == bytes.fromhex(
            'f5d3d58503b9699de785895a96fdbaaf'
        )
        assert aes.encrypt_block(spa_800_38a_plaintexts[2]) == bytes.fromhex(
            '43b1cd7f598ece23881b00e3ed030688'
        )
        assert aes.encrypt_block(spa_800_38a_plaintexts[3]) == bytes.fromhex(
            '7b0c785e27e8ad3f8223207104725dd4'
        )

    @staticmethod
    @given(aes=aes128, block=aes_blocks)
    def test_aes128_decrypt_block_inverts_encrypt_block(
        aes: Aes128,
        block: bytes,
    ) -> None:
        assert aes.decrypt_block(aes.encrypt_block(block)) == block

    @staticmethod
    @given(aes=aes128, block=aes_blocks)
    def test_aes128_encrypt_block_inverts_decrypt_block(
        aes: Aes128,
        block: bytes,
    ) -> None:
        assert aes.encrypt_block(aes.decrypt_block(block)) == block
