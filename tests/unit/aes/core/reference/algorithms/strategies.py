from typing import Final

from hypothesis.strategies import builds, SearchStrategy

from purepython_aes import ReferenceAes128, ReferenceAes192, ReferenceAes256
from tests.unit.aes.strategies import aes128key, aes192key, aes256key

reference_aes128: Final[SearchStrategy[ReferenceAes128]] = builds(
    ReferenceAes128, aes128key
)
reference_aes192: Final[SearchStrategy[ReferenceAes192]] = builds(
    ReferenceAes192, aes192key
)
reference_aes256: Final[SearchStrategy[ReferenceAes256]] = builds(
    ReferenceAes256, aes256key
)
