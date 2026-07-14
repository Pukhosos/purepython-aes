from pytest import mark

from purepython_aes import OfbMode
from purepython_aes.const import AES_BLOCK_SIZE
from tests.reference.pyaes.cases import (
    AlgorithmCase,
    ARBITRARY_LENGTH_PLAINTEXTS,
    INITIALIZATION_VALUE,
)
from tests.reference.pyaes.reference import decrypt_ofb, encrypt_ofb


@mark.reference_pyaes
class TestPyaesOfbReference:
    @staticmethod
    @mark.parametrize('plaintext', ARBITRARY_LENGTH_PLAINTEXTS)
    def test_matches_pyaes(
        algorithm_case: AlgorithmCase,
        plaintext: bytes,
    ) -> None:
        ofb: OfbMode = OfbMode(algorithm_case.algorithm(algorithm_case.key))
        purepython_ciphertext: bytes = ofb.encrypt(plaintext)
        generated_initialization_value: bytes = purepython_ciphertext[:AES_BLOCK_SIZE]
        encrypted_payload: bytes = purepython_ciphertext[AES_BLOCK_SIZE:]
        reference_payload: bytes = encrypt_ofb(
            key=algorithm_case.key,
            initialization_value=INITIALIZATION_VALUE,
            plaintext=plaintext,
        )
        assert encrypted_payload == encrypt_ofb(
            key=algorithm_case.key,
            initialization_value=generated_initialization_value,
            plaintext=plaintext,
        )
        assert (
            decrypt_ofb(
                key=algorithm_case.key,
                initialization_value=generated_initialization_value,
                ciphertext=encrypted_payload,
            )
            == plaintext
        )
        assert ofb.decrypt(INITIALIZATION_VALUE + reference_payload) == plaintext
