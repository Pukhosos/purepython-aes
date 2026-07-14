from itertools import product

from pytest import mark

from purepython_aes import CfbMode
from purepython_aes.const import AES_BLOCK_SIZE
from purepython_aes.types import CfbSegmentSize
from tests.reference.pyaes.cases import (
    AlgorithmCase,
    ARBITRARY_LENGTH_PLAINTEXTS,
    CFB_SEGMENT_SIZES,
    INITIALIZATION_VALUE,
)
from tests.reference.pyaes.reference import decrypt_cfb, encrypt_cfb


@mark.reference_pyaes
class TestPyaesCfbReference:
    @staticmethod
    @mark.parametrize(
        ['segment_size', 'plaintext'],
        tuple(product(CFB_SEGMENT_SIZES, ARBITRARY_LENGTH_PLAINTEXTS)),
    )
    def test_matches_pyaes(
        algorithm_case: AlgorithmCase,
        segment_size: CfbSegmentSize,
        plaintext: bytes,
    ) -> None:
        cfb: CfbMode = CfbMode(
            algorithm=algorithm_case.algorithm(algorithm_case.key),
            segment_size=segment_size,
        )
        purepython_ciphertext: bytes = cfb.encrypt(plaintext)
        generated_initialization_value: bytes = purepython_ciphertext[:AES_BLOCK_SIZE]
        encrypted_payload: bytes = purepython_ciphertext[AES_BLOCK_SIZE:]
        reference_payload: bytes = encrypt_cfb(
            key=algorithm_case.key,
            initialization_value=INITIALIZATION_VALUE,
            segment_size=segment_size,
            plaintext=plaintext,
        )
        assert encrypted_payload == encrypt_cfb(
            key=algorithm_case.key,
            initialization_value=generated_initialization_value,
            segment_size=segment_size,
            plaintext=plaintext,
        )
        assert (
            decrypt_cfb(
                key=algorithm_case.key,
                initialization_value=generated_initialization_value,
                segment_size=segment_size,
                ciphertext=encrypted_payload,
            )
            == plaintext
        )
        assert cfb.decrypt(INITIALIZATION_VALUE + reference_payload) == plaintext
