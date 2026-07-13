from typing import Final

from hypothesis.strategies import SearchStrategy, tuples

from tests.unit.aes.strategies import byte_values

columns: Final[SearchStrategy[tuple[int, int, int, int]]] = tuples(
    byte_values, byte_values, byte_values, byte_values
)
