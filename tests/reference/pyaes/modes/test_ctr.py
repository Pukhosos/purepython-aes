from itertools import product

from pytest import mark

from purepython_aes import CtrMode
from purepython_aes.const import AES_BLOCK_SIZE
from tests.reference.pyaes.cases import (
    AlgorithmCase,
    ARBITRARY_LENGTH_PLAINTEXTS,
    COUNTER_ROLLOVER_INITIAL_VALUE,
    COUNTER_ROLLOVER_PLAINTEXT,
    COUNTER_VALUES,
    INITIALIZATION_VALUE,
)
from tests.reference.pyaes.reference import decrypt_ctr, encrypt_ctr


@mark.reference_pyaes
class TestPyaesCtrReference:
    @staticmethod
    @mark.parametrize('plaintext', ARBITRARY_LENGTH_PLAINTEXTS)
    def test_matches_pyaes(algorithm_case: AlgorithmCase, plaintext: bytes) -> None:
        ctr: CtrMode = CtrMode(algorithm_case.algorithm(algorithm_case.key))
        purepython_ciphertext: bytes = ctr.encrypt(plaintext)
        initialization_value: bytes = purepython_ciphertext[:AES_BLOCK_SIZE]
        encrypted_payload: bytes = purepython_ciphertext[AES_BLOCK_SIZE:]
        counter: int = int.from_bytes(initialization_value, byteorder='big')
        reference_payload: bytes = encrypt_ctr(
            key=algorithm_case.key,
            counter=int.from_bytes(INITIALIZATION_VALUE, byteorder='big'),
            plaintext=plaintext,
        )
        assert encrypted_payload == encrypt_ctr(
            key=algorithm_case.key,
            counter=counter,
            plaintext=plaintext,
        )
        assert (
            decrypt_ctr(
                key=algorithm_case.key,
                counter=counter,
                ciphertext=encrypted_payload,
            )
            == plaintext
        )
        assert ctr.decrypt(INITIALIZATION_VALUE + reference_payload) == plaintext

    @staticmethod
    @mark.parametrize(
        ['counter', 'plaintext'],
        tuple(product(COUNTER_VALUES, ARBITRARY_LENGTH_PLAINTEXTS)),
    )
    def test_transform_matches_explicit_pyaes_counter(
        algorithm_case: AlgorithmCase,
        counter: int,
        plaintext: bytes,
    ) -> None:
        ctr: CtrMode = CtrMode(algorithm_case.algorithm(algorithm_case.key))
        initialization_value: bytes = counter.to_bytes(
            AES_BLOCK_SIZE,
            byteorder='big',
        )
        assert ctr.transform(initialization_value, plaintext) == encrypt_ctr(
            key=algorithm_case.key,
            counter=counter,
            plaintext=plaintext,
        )

    @staticmethod
    def test_counter_rollover_matches_pyaes(algorithm_case: AlgorithmCase) -> None:
        ctr: CtrMode = CtrMode(algorithm_case.algorithm(algorithm_case.key))
        initialization_value: bytes = COUNTER_ROLLOVER_INITIAL_VALUE.to_bytes(
            AES_BLOCK_SIZE,
            byteorder='big',
        )
        assert ctr.transform(
            initialization_value=initialization_value,
            data=COUNTER_ROLLOVER_PLAINTEXT,
        ) == encrypt_ctr(
            key=algorithm_case.key,
            counter=COUNTER_ROLLOVER_INITIAL_VALUE,
            plaintext=COUNTER_ROLLOVER_PLAINTEXT,
        )
