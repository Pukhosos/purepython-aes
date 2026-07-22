# purepython-aes

Pure-Python implementation of AES encryption algorithm.

## Prerequisites

`purepython-aes` requires [Python 3.10](https://www.python.org/downloads/release/python-3100/) or newer.

## Installation

This package is available on PyPI.

```sh
pip install purepython-aes
```

### Extras

This package provides four extras: `dev`, `test`, `fuzz`, and `build`. These are intended solely for development and do not add any runtime functionality.

## Quick start

`purepython-aes` supports AES-128, AES-192, and AES-256, with ECB, CBC, PCBC, CFB, OFB, and CTR modes. Available [padding schemes](https://en.wikipedia.org/wiki/Padding_%28cryptography%29) are [ANSI X9.23](https://en.wikipedia.org/wiki/Padding_%28cryptography%29#ANSI_X9.23), [ISO/IEC 7816-4](https://en.wikipedia.org/wiki/Padding_%28cryptography%29#ISO/IEC_7816-4), [ISO 10126](https://en.wikipedia.org/wiki/Padding_%28cryptography%29#ISO_10126), [PKCS#7](https://en.wikipedia.org/wiki/Padding_%28cryptography%29#PKCS#5_and_PKCS#7), [zero padding](https://en.wikipedia.org/wiki/Padding_%28cryptography%29#Zero_padding), and no padding *(requires data to be 16-byte-aligned)*.

```pycon
>>> from purepython_aes import Aes128, EcbMode, Pkcs7Padding
>>>
>>> message: str = 'Hello, World!'
>>> key: bytes = bytes.fromhex('8d39342d15f50bcaa47cce2ec306fc11')
>>> aes: EcbMode = EcbMode(algorithm=Aes128(key), padding=Pkcs7Padding())
>>>
>>>
>>> ciphertext: bytes = aes.encrypt(message.encode('utf-8'))
>>> ciphertext.hex()
'aba1a8622feb8ae23a4791e24fa08fc1'
>>> aes.decrypt(ciphertext).decode('utf-8')
'Hello, World!'
>>>
```

**Security note:** ECB mode is deterministic and does not conceal repeated plaintext patterns. It is included for compatibility and testing, but should generally not be used to encrypt sensitive data.

## Development

### Setting up the development environment

1. Clone the repository and create a virtual environment:

    ```sh
    git clone https://github.com/Pukhosos/purepython-aes.git cd purepython-aes
    python3.10 -m venv .venv
    ```

2. Activate the virtual environment:

    - Linux and MacOS:

        ```sh
        source .venv/bin/activate
        ```

    - Windows *(PowerShell)*

        ```sh
        .venv\Scripts\Activate.ps1
        ```

3. Install the package in editable mode with the extra dependencies:

    ```sh
    python -m pip install --editable ".[dev, test, fuzz, build]"
    ```

    The optional dependency groups are:

    - `dev` — formatters, linters, type checking, and pre-commit
    - `test` — pytest, Hypothesis, parallel test execution, and the reference implementation
    - `fuzz` — fuzz-testing dependencies *(depends on `purepython-aes[test]`)*
    - `build` — package-building distribution-validation tools

4. Install the Git hooks:

    ```sh
    pre-commit install
    ```

### Running tests

The following commands assume the virtual environment is activated

- All the tests *(may take several minutes to complete)*

    ```sh
    pytest . -n 8
    ```

- Reasonably quick tests *(recommended)*

    ```sh
    pytest . -m "(quick or reference_pyaes) and not slow" -n 8
    ```

- Most relevant tests

    ```sh
    pytest . -m "quick and not slow" -n 8
    ```

- `pre-commit` testsuite

    ```sh
    pre-commit run pytest-discovery && \
        pre-commit run pytest-doctest && \
        pre-commit run pytest-markguard && \
        pre-commit run pytest-unit && \
        pre-commit run pytest-reference
    ```

- All `pre-commit` hooks

    ```sh
    pre-commit run --all-files
    ```

The test suite uses the following markers:

- `quick` — tests intended to run on every commit
- `slow` — tests intended to run once when added
- `reference_pyaes` — tests comparing behavior with the `pyaes==1.6.1` reference implementation

## License

`purepython-aes` is a free, open-source software distributed under the [MIT License](https://github.com/Pukhosos/purepython-aes/blob/main/LICENSE.txt).
