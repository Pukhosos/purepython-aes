from typing import cast

from pytest import fixture, FixtureRequest

from tests.reference.pyaes.cases import (
    ALGORITHM_CASE_IDENTIFIERS,
    ALGORITHM_CASES,
    AlgorithmCase,
)


@fixture(params=ALGORITHM_CASES, ids=ALGORITHM_CASE_IDENTIFIERS)
def algorithm_case(request: FixtureRequest) -> AlgorithmCase:
    """Provide every production and reference AES implementation."""

    return cast(AlgorithmCase, request.param)
