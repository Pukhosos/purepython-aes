from typing import Final

from hypothesis.strategies import builds, SearchStrategy

from purepython_aes import Aes128, Aes192, Aes256
from tests.unit.aes.strategies import aes128key, aes192key, aes256key

aes128: Final[SearchStrategy[Aes128]] = builds(Aes128, aes128key)
aes192: Final[SearchStrategy[Aes192]] = builds(Aes192, aes192key)
aes256: Final[SearchStrategy[Aes256]] = builds(Aes256, aes256key)
