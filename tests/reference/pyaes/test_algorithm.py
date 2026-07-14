from pytest import mark

from purepython_aes import Aes
from tests.reference.pyaes.cases import (
    AlgorithmCase,
    SINGLE_BLOCK_PLAINTEXTS,
)
from tests.reference.pyaes.reference import decrypt_block, encrypt_block


@mark.reference_pyaes
class TestPyaesAlgorithmReference:
    @staticmethod
    @mark.parametrize('plaintext', SINGLE_BLOCK_PLAINTEXTS)
    def test_encrypt_block_matches_pyaes(
        algorithm_case: AlgorithmCase,
        plaintext: bytes,
    ) -> None:
        algorithm: Aes = algorithm_case.algorithm(algorithm_case.key)
        assert algorithm.encrypt_block(plaintext) == encrypt_block(
            key=algorithm_case.key,
            plaintext=plaintext,
        )

    @staticmethod
    @mark.parametrize('plaintext', SINGLE_BLOCK_PLAINTEXTS)
    def test_decrypt_block_matches_pyaes(
        algorithm_case: AlgorithmCase,
        plaintext: bytes,
    ) -> None:
        ciphertext: bytes = encrypt_block(algorithm_case.key, plaintext)
        algorithm: Aes = algorithm_case.algorithm(algorithm_case.key)
        purepython_plaintext: bytes = algorithm.decrypt_block(ciphertext)
        assert purepython_plaintext == decrypt_block(algorithm_case.key, ciphertext)
        assert purepython_plaintext == plaintext
