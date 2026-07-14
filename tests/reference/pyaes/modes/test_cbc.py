from pytest import mark

from purepython_aes import CbcMode, NoPadding, Pkcs7Padding
from purepython_aes.const import AES_BLOCK_SIZE
from tests.reference.pyaes.cases import (
    AlgorithmCase,
    ARBITRARY_LENGTH_PLAINTEXTS,
    BLOCK_ALIGNED_PLAINTEXTS,
    INITIALIZATION_VALUE,
)
from tests.reference.pyaes.reference import (
    decrypt_cbc_with_pkcs7,
    decrypt_cbc_without_padding,
    encrypt_cbc_with_pkcs7,
    encrypt_cbc_without_padding,
)


@mark.reference_pyaes
class TestPyaesCbcReference:
    @staticmethod
    @mark.parametrize('plaintext', BLOCK_ALIGNED_PLAINTEXTS)
    def test_without_padding_matches_pyaes(
        algorithm_case: AlgorithmCase,
        plaintext: bytes,
    ) -> None:
        cbc: CbcMode = CbcMode(
            algorithm=algorithm_case.algorithm(algorithm_case.key),
            padding=NoPadding(),
        )
        purepython_ciphertext: bytes = cbc.encrypt(plaintext)
        generated_initialization_value: bytes = purepython_ciphertext[:AES_BLOCK_SIZE]
        encrypted_payload: bytes = purepython_ciphertext[AES_BLOCK_SIZE:]
        reference_payload: bytes = encrypt_cbc_without_padding(
            key=algorithm_case.key,
            initialization_value=INITIALIZATION_VALUE,
            plaintext=plaintext,
        )
        assert encrypted_payload == encrypt_cbc_without_padding(
            key=algorithm_case.key,
            initialization_value=generated_initialization_value,
            plaintext=plaintext,
        )
        assert (
            decrypt_cbc_without_padding(
                key=algorithm_case.key,
                initialization_value=generated_initialization_value,
                ciphertext=encrypted_payload,
            )
            == plaintext
        )
        assert cbc.decrypt(INITIALIZATION_VALUE + reference_payload) == plaintext

    @staticmethod
    @mark.parametrize('plaintext', ARBITRARY_LENGTH_PLAINTEXTS)
    def test_pkcs7_padding_matches_pyaes(
        algorithm_case: AlgorithmCase,
        plaintext: bytes,
    ) -> None:
        cbc: CbcMode = CbcMode(
            algorithm=algorithm_case.algorithm(algorithm_case.key),
            padding=Pkcs7Padding(),
        )
        purepython_ciphertext: bytes = cbc.encrypt(plaintext)
        generated_initialization_value: bytes = purepython_ciphertext[:AES_BLOCK_SIZE]
        encrypted_payload: bytes = purepython_ciphertext[AES_BLOCK_SIZE:]
        reference_payload: bytes = encrypt_cbc_with_pkcs7(
            key=algorithm_case.key,
            initialization_value=INITIALIZATION_VALUE,
            plaintext=plaintext,
        )
        assert encrypted_payload == encrypt_cbc_with_pkcs7(
            key=algorithm_case.key,
            initialization_value=generated_initialization_value,
            plaintext=plaintext,
        )
        assert (
            decrypt_cbc_with_pkcs7(
                key=algorithm_case.key,
                initialization_value=generated_initialization_value,
                ciphertext=encrypted_payload,
            )
            == plaintext
        )
        assert cbc.decrypt(INITIALIZATION_VALUE + reference_payload) == plaintext
