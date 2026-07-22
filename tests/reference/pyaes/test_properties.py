from typing import Final

from hypothesis import assume, given, HealthCheck, settings
from pytest import mark

from purepython_aes import (
    Aes,
    CbcMode,
    CfbMode,
    CtrMode,
    EcbMode,
    NoPadding,
    OfbMode,
    Pkcs7Padding,
)
from purepython_aes.const import AES_BLOCK_SIZE
from purepython_aes.types import CfbSegmentSize
from tests.reference.pyaes.cases import AlgorithmCase
from tests.reference.pyaes.reference import (
    decrypt_block,
    decrypt_cbc_with_pkcs7,
    decrypt_cbc_without_padding,
    decrypt_cfb,
    decrypt_ctr,
    decrypt_ecb_with_pkcs7,
    decrypt_ecb_without_padding,
    decrypt_ofb,
    encrypt_block,
    encrypt_cbc_with_pkcs7,
    encrypt_cbc_without_padding,
    encrypt_cfb,
    encrypt_ctr,
    encrypt_ecb_with_pkcs7,
    encrypt_ecb_without_padding,
    encrypt_ofb,
)
from tests.reference.pyaes.strategies import (
    aes256key,
    aes_blocks,
    aligned_aes_blocks,
    arbitrary_aes_blocks,
    counters,
    rollover_aes_blocks,
    rollover_counters,
)

property_settings: Final[settings] = settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)


@mark.reference_pyaes
class TestAgainstPyaes:
    @staticmethod
    @given(key_material=aes256key, plaintext=aes_blocks)
    @property_settings
    def test_block_primitive_matches_pyaes(
        algorithm_case: AlgorithmCase,
        key_material: bytes,
        plaintext: bytes,
    ) -> None:
        key: bytes = key_material[:len(algorithm_case.key)]  # fmt: skip
        algorithm: Aes = algorithm_case.algorithm(key)
        reference_ciphertext: bytes = encrypt_block(key, plaintext)
        assert algorithm.encrypt_block(plaintext) == reference_ciphertext
        assert algorithm.decrypt_block(reference_ciphertext) == plaintext
        assert decrypt_block(key, reference_ciphertext) == plaintext

    @staticmethod
    @given(key_material=aes256key, plaintext=aligned_aes_blocks)
    @property_settings
    def test_ecb_without_padding_matches_pyaes(
        algorithm_case: AlgorithmCase,
        key_material: bytes,
        plaintext: bytes,
    ) -> None:
        key: bytes = key_material[:len(algorithm_case.key)]  # fmt: skip
        ecb: EcbMode = EcbMode(algorithm_case.algorithm(key), NoPadding())
        reference_ciphertext: bytes = encrypt_ecb_without_padding(key, plaintext)
        assert ecb.encrypt(plaintext) == reference_ciphertext
        assert ecb.decrypt(reference_ciphertext) == plaintext
        assert decrypt_ecb_without_padding(key, reference_ciphertext) == plaintext

    @staticmethod
    @given(key_material=aes256key, plaintext=arbitrary_aes_blocks)
    @property_settings
    def test_ecb_with_pkcs7_matches_pyaes(
        algorithm_case: AlgorithmCase,
        key_material: bytes,
        plaintext: bytes,
    ) -> None:
        key: bytes = key_material[:len(algorithm_case.key)]  # fmt: skip
        ecb: EcbMode = EcbMode(algorithm_case.algorithm(key), Pkcs7Padding())
        reference_ciphertext: bytes = encrypt_ecb_with_pkcs7(key, plaintext)
        assert ecb.encrypt(plaintext) == reference_ciphertext
        assert ecb.decrypt(reference_ciphertext) == plaintext
        assert decrypt_ecb_with_pkcs7(key, reference_ciphertext) == plaintext

    @staticmethod
    @given(
        initialization_value=aes_blocks,
        key_material=aes256key,
        plaintext=aligned_aes_blocks,
    )
    @property_settings
    def test_cbc_without_padding_matches_pyaes(
        algorithm_case: AlgorithmCase,
        initialization_value: bytes,
        key_material: bytes,
        plaintext: bytes,
    ) -> None:
        key: bytes = key_material[:len(algorithm_case.key)]  # fmt: skip
        cbc: CbcMode = CbcMode(algorithm_case.algorithm(key), NoPadding())
        purepython_ciphertext: bytes = cbc.encrypt(plaintext)
        generated_initialization_value: bytes = purepython_ciphertext[:AES_BLOCK_SIZE]
        encrypted_payload: bytes = purepython_ciphertext[AES_BLOCK_SIZE:]
        reference_payload: bytes = encrypt_cbc_without_padding(
            key=key,
            initialization_value=initialization_value,
            plaintext=plaintext,
        )
        assert encrypted_payload == encrypt_cbc_without_padding(
            key=key,
            initialization_value=generated_initialization_value,
            plaintext=plaintext,
        )
        assert (
            decrypt_cbc_without_padding(
                key=key,
                initialization_value=generated_initialization_value,
                ciphertext=encrypted_payload,
            )
            == plaintext
        )
        assert cbc.decrypt(initialization_value + reference_payload) == plaintext

    @staticmethod
    @given(
        initialization_value=aes_blocks,
        key_material=aes256key,
        plaintext=arbitrary_aes_blocks,
    )
    @property_settings
    def test_cbc_with_pkcs7_matches_pyaes(
        algorithm_case: AlgorithmCase,
        initialization_value: bytes,
        key_material: bytes,
        plaintext: bytes,
    ) -> None:
        key: bytes = key_material[:len(algorithm_case.key)]  # fmt: skip
        cbc: CbcMode = CbcMode(algorithm_case.algorithm(key), Pkcs7Padding())
        purepython_ciphertext: bytes = cbc.encrypt(plaintext)
        generated_initialization_value: bytes = purepython_ciphertext[:AES_BLOCK_SIZE]
        encrypted_payload: bytes = purepython_ciphertext[AES_BLOCK_SIZE:]
        reference_payload: bytes = encrypt_cbc_with_pkcs7(
            key=key,
            initialization_value=initialization_value,
            plaintext=plaintext,
        )
        assert encrypted_payload == encrypt_cbc_with_pkcs7(
            key=key,
            initialization_value=generated_initialization_value,
            plaintext=plaintext,
        )
        assert (
            decrypt_cbc_with_pkcs7(
                key=key,
                initialization_value=generated_initialization_value,
                ciphertext=encrypted_payload,
            )
            == plaintext
        )
        assert cbc.decrypt(initialization_value + reference_payload) == plaintext

    @staticmethod
    @mark.parametrize('segment_size', tuple(range(1, AES_BLOCK_SIZE + 1)))
    @property_settings
    @given(
        initialization_value=aes_blocks,
        key_material=aes256key,
        plaintext=arbitrary_aes_blocks,
    )
    def test_cfb_matches_pyaes(
        segment_size: CfbSegmentSize,
        algorithm_case: AlgorithmCase,
        initialization_value: bytes,
        key_material: bytes,
        plaintext: bytes,
    ) -> None:
        key: bytes = key_material[:len(algorithm_case.key)]  # fmt: skip
        cfb: CfbMode = CfbMode(algorithm_case.algorithm(key), segment_size)
        purepython_ciphertext: bytes = cfb.encrypt(plaintext)
        generated_initialization_value: bytes = purepython_ciphertext[:AES_BLOCK_SIZE]
        encrypted_payload: bytes = purepython_ciphertext[AES_BLOCK_SIZE:]
        reference_payload: bytes = encrypt_cfb(
            key=key,
            initialization_value=initialization_value,
            segment_size=segment_size,
            plaintext=plaintext,
        )
        assert encrypted_payload == encrypt_cfb(
            key=key,
            initialization_value=generated_initialization_value,
            segment_size=segment_size,
            plaintext=plaintext,
        )
        assert (
            decrypt_cfb(
                key=key,
                initialization_value=generated_initialization_value,
                segment_size=segment_size,
                ciphertext=encrypted_payload,
            )
            == plaintext
        )
        assert cfb.decrypt(initialization_value + reference_payload) == plaintext

    @staticmethod
    @given(
        initialization_value=aes_blocks,
        key_material=aes256key,
        plaintext=arbitrary_aes_blocks,
    )
    @property_settings
    def test_ofb_matches_pyaes(
        algorithm_case: AlgorithmCase,
        initialization_value: bytes,
        key_material: bytes,
        plaintext: bytes,
    ) -> None:
        key: bytes = key_material[:len(algorithm_case.key)]  # fmt: skip
        ofb: OfbMode = OfbMode(algorithm_case.algorithm(key))
        purepython_ciphertext: bytes = ofb.encrypt(plaintext)
        generated_initialization_value: bytes = purepython_ciphertext[:AES_BLOCK_SIZE]
        encrypted_payload: bytes = purepython_ciphertext[AES_BLOCK_SIZE:]
        reference_payload: bytes = encrypt_ofb(
            key=key,
            initialization_value=initialization_value,
            plaintext=plaintext,
        )
        assert encrypted_payload == encrypt_ofb(
            key=key,
            initialization_value=generated_initialization_value,
            plaintext=plaintext,
        )
        assert (
            decrypt_ofb(
                key=key,
                initialization_value=generated_initialization_value,
                ciphertext=encrypted_payload,
            )
            == plaintext
        )
        assert ofb.decrypt(initialization_value + reference_payload) == plaintext

    @staticmethod
    @given(
        counter=counters,
        key_material=aes256key,
        plaintext=arbitrary_aes_blocks,
    )
    @property_settings
    def test_ctr_matches_pyaes(
        algorithm_case: AlgorithmCase,
        counter: int,
        key_material: bytes,
        plaintext: bytes,
    ) -> None:
        key: bytes = key_material[:len(algorithm_case.key)]  # fmt: skip
        ctr: CtrMode = CtrMode(algorithm_case.algorithm(key))
        initialization_value: bytes = counter.to_bytes(AES_BLOCK_SIZE, byteorder='big')
        reference_ciphertext: bytes = encrypt_ctr(key, counter, plaintext)
        assert (
            ctr.__transform_stream__(initialization_value, plaintext)
            == reference_ciphertext
        )
        assert (
            ctr.__transform_stream__(initialization_value, reference_ciphertext)
            == plaintext
        )
        assert decrypt_ctr(key, counter, reference_ciphertext) == plaintext

    @staticmethod
    @given(
        counter=rollover_counters,
        key_material=aes256key,
        plaintext=rollover_aes_blocks,
    )
    @property_settings
    def test_ctr_rollover_matches_pyaes(
        algorithm_case: AlgorithmCase,
        counter: int,
        key_material: bytes,
        plaintext: bytes,
    ) -> None:
        key: bytes = key_material[:len(algorithm_case.key)]  # fmt: skip
        ctr: CtrMode = CtrMode(algorithm_case.algorithm(key))
        initialization_value: bytes = counter.to_bytes(AES_BLOCK_SIZE, byteorder='big')
        assert (
            ctr.__transform_stream__(initialization_value, plaintext)  # fmt: skip
            == encrypt_ctr(key, counter, plaintext)
        )

    @staticmethod
    @given(key_material=aes256key, plaintext=arbitrary_aes_blocks)
    @property_settings
    def test_stream_mode_ciphertext_length_matches_pyaes(
        algorithm_case: AlgorithmCase,
        key_material: bytes,
        plaintext: bytes,
    ) -> None:
        assume(len(plaintext) != 0)
        key: bytes = key_material[:len(algorithm_case.key)]  # fmt: skip
        ofb: OfbMode = OfbMode(algorithm_case.algorithm(key))
        ctr: CtrMode = CtrMode(algorithm_case.algorithm(key))
        assert len(ofb.encrypt(plaintext)) == AES_BLOCK_SIZE + len(plaintext)
        assert len(ctr.encrypt(plaintext)) == AES_BLOCK_SIZE + len(plaintext)
