# Security Policy

## Supported versions

`purepython-aes` is currently an alpha-stage project. Security fixes are provided
for the latest published release only.

| Version                   | Supported   |
| ------------------------- | ----------- |
| Latest release            | Yes         |
| Older releases            | No          |
| Unreleased code on `main` | Best effort |

Users should upgrade to the latest release before reporting a vulnerability and
when a security fix becomes available.

## Security considerations

`purepython-aes` is a pure-Python implementation of AES intended primarily for
learning, experimentation, interoperability testing, and environments where a
pure-Python implementation is specifically required.

The project does not claim to provide constant-time execution, resistance to
timing or other side-channel attacks, formal verification, regulatory
certification, or an independent security audit. It should not be treated as a
drop-in replacement for a mature, reviewed cryptographic library in
security-critical production systems.

Correct use of AES also depends on the selected mode of operation, padding,
initialization values or nonces, authentication, key generation, key storage,
and protocol design. A correct AES primitive alone does not make an application
secure.

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do not open a public GitHub
issue, discussion, or pull request before the vulnerability has been assessed
and, when necessary, fixed.

Preferred reporting methods:

- Use GitHub's Report a vulnerability feature from the repository's Security tab.

Include as much of the following information as possible:

- the affected `purepython-aes` version or commit;
- the affected component, mode, padding scheme, or API;
- a clear description of the vulnerability and its security impact;
- the conditions required to reproduce or exploit it;
- a minimal proof of concept or a test case;
- relevant Python, operating-system, and architecture details;
- any suggested remediation;
- whether the report or any part of it has already been disclosed publicly.

Do not include real encryption keys, plaintexts, credentials, personal data, or
other sensitive production information. Use synthetic test data.

## What to expect

The maintainer will make a reasonable effort to:

- assess its severity and reproducibility;
- keep the reporter informed when material progress is made;
- prepare a fix and regression tests when the issue is confirmed;
- publish a security advisory and release when warranted;
- credit the reporter, unless anonymity is requested.

Response and remediation times depend on severity, complexity, maintainer
availability, and the need to coordinate disclosure. No bug bounty or monetary
reward is currently offered.

## Coordinated disclosure

Please allow a reasonable remediation period before public disclosure. A
90-day disclosure window is preferred unless a different timeline is agreed
upon or active exploitation requires accelerated disclosure.

After a fix is available, coordinated publication may include a GitHub security
advisory, a patched release, upgrade guidance, affected-version information,
and reporter credit.

## Scope

Examples of reports that are generally in scope include:

- incorrect AES encryption, decryption, key expansion, or mode behavior;
- nonce, counter, initialization-value, or authentication-tag handling that
  can compromise confidentiality or integrity;
- padding-oracle or unauthenticated-decryption risks caused by library behavior;
- key, plaintext, or internal-state disclosure;
- practically exploitable timing or other side-channel weaknesses;
- denial of service caused by attacker-controlled cryptographic input;
- package-build, release, or distribution compromise;
- a discrepancy from a documented security guarantee.

The following are generally not treated as vulnerabilities by themselves:

- use of an inherently unsuitable mode, such as ECB, when the documented API
  behaves as specified;
- weaknesses caused solely by application-level key management or protocol
  design outside the library;
- reports that only state that pure-Python cryptography may be slower or less
  side-channel-resistant, without a concrete and reproducible impact;
- ordinary bugs, feature requests, documentation issues, or compatibility
  problems without a security impact;
- vulnerabilities that affect only unsupported versions and are already fixed
  in the latest release.

When uncertain whether an issue has security impact, report it privately.
