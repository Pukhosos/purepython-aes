from pytest import mark

from purepython_aes import EcbMode, NoPadding, Pkcs7Padding
from tests.reference.pyaes.cases import (
    AlgorithmCase,
    ARBITRARY_LENGTH_PLAINTEXTS,
    BLOCK_ALIGNED_PLAINTEXTS,
)
from tests.reference.pyaes.reference import (
    decrypt_ecb_with_pkcs7,
    decrypt_ecb_without_padding,
    encrypt_ecb_with_pkcs7,
    encrypt_ecb_without_padding,
)


@mark.reference_pyaes
class TestPyaesEcbReference:
    @staticmethod
    @mark.parametrize('plaintext', BLOCK_ALIGNED_PLAINTEXTS)
    def test_without_padding_matches_pyaes(
        algorithm_case: AlgorithmCase,
        plaintext: bytes,
    ) -> None:
        ecb: EcbMode = EcbMode(
            algorithm=algorithm_case.algorithm(algorithm_case.key),
            padding=NoPadding(),
        )
        reference_ciphertext: bytes = encrypt_ecb_without_padding(
            key=algorithm_case.key,
            plaintext=plaintext,
        )
        assert ecb.encrypt(plaintext) == reference_ciphertext
        assert (
            ecb.decrypt(reference_ciphertext)  # fmt: skip
            == decrypt_ecb_without_padding(algorithm_case.key, reference_ciphertext)
        )
        assert ecb.decrypt(reference_ciphertext) == plaintext

    @staticmethod
    @mark.parametrize('plaintext', ARBITRARY_LENGTH_PLAINTEXTS)
    def test_pkcs7_padding_matches_pyaes(
        algorithm_case: AlgorithmCase,
        plaintext: bytes,
    ) -> None:
        ecb: EcbMode = EcbMode(
            algorithm=algorithm_case.algorithm(algorithm_case.key),
            padding=Pkcs7Padding(),
        )
        reference_ciphertext: bytes = encrypt_ecb_with_pkcs7(
            key=algorithm_case.key,
            plaintext=plaintext,
        )
        assert ecb.encrypt(plaintext) == reference_ciphertext
        assert (
            ecb.decrypt(reference_ciphertext)  # fmt: skip
            == decrypt_ecb_with_pkcs7(algorithm_case.key, reference_ciphertext)
        )
        assert ecb.decrypt(reference_ciphertext) == plaintext
