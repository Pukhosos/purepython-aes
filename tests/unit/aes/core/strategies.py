from typing import Final

from hypothesis.strategies import integers, SearchStrategy, tuples

byte_values: Final[SearchStrategy[int]] = integers(min_value=0x00, max_value=0xFF)
columns: Final[SearchStrategy[tuple[int, int, int, int]]] = tuples(
    byte_values, byte_values, byte_values, byte_values
)
