# Instructions for AI agents and reviewers

PHP encryption helpers wrapping [Halite](https://github.com/paragonie/halite). The public API is the three classes `SymmetricKeyEncryption`, `AuthenticatedPublicKeyEncryption`, `AnonymousPublicKeyEncryption`, and the `Exceptions\` namespace; everything in `Format\` is internal and can change freely. The `README.md` documents usage and design, commit messages document why changes were made. This file lists the rules that no linter enforces and the code itself doesn't show.

## Commands

- `composer test` runs everything: parallel-lint, phpcs, PHPStan (level max + strict rules, including tests), nette/tester with code coverage
- `vendor/nette/tester/src/tester -c tests/php-unix.ini tests/<File>.phpt` runs one test file
- `composer cs-fix` fixes coding style violations, so don't spend time on style, the tools define it
- CI runs the suite on the PHP versions listed in `.github/workflows/php.yml`, each with current and with lowest allowed dependency versions (`--prefer-lowest`), so version floors in `composer.json` are exercised, not decorative

## Invariants

Breaking any of these is a bug even when all tests pass. When a change makes a test with a pinned value fail, don't update the pin: stop and say what you were doing, the pin likely just did its job.

- **The stored formats are frozen.** The output of this library lives in databases. Pinned ciphertext fixtures in the tests are the contract: never edit or regenerate an existing fixture. Adding fixtures is how new behavior ships: generate the value once with a throwaway script and paste it verbatim. Values in the old format without the marker must decrypt forever.
- **Markers are append-only.** `FormatMarker` values never change and are never removed; a format change means a new case, named like the existing ones (`SymmetricKeyV2 = 'SymV2'`). The verified-value recipe (`buildBoundAdditionalData()`) is frozen per marker; a changed recipe is a new marker too.
- **No key material in exception messages, traces, or object dumps.** Raw key bytes are held only in `HiddenString`, never in plain properties. Values repeated in messages that can come from stored data or from a mispasted config slot go through `LogSafeValue`. Parameters carrying keys or plaintext get `#[SensitiveParameter]`, including on private helper methods, because traces mask arguments per frame.
- **Exception constructors are not public API**, change their parameters freely. The exception class names, the inheritance (related failures are empty subclasses inheriting the message), and the no-key-material guarantee are API.
- **Validation happens in constructors**, not on first use: a misconfiguration fails at deploy time.
- **Byte encoding goes through the constant-time sodium functions** (`sodium_hex2bin()`, `sodium_bin2hex()`, `sodium_bin2base64()`), never `hex2bin()`/`bin2hex()`/`base64_*()`; PHPStan enforces this everywhere via the bundled `disallowed-non-timing-safe-calls.neon`.
- **Verify claims about Halite and libsodium against `vendor/paragonie/halite` sources or a `php -r` experiment**, never from memory or secondhand docs.

## Conventions

- README and commit messages are plain English: no unexplained crypto jargon (say "protected against tampering", not "authenticated"; describe what happens instead of naming the primitive). Precise class and function names are fine.
- Commit messages: imperative subject with backticks around identifiers, then a long explanatory body covering why the change exists and what was rejected. One paragraph is one line, no hard wrapping, no trailers (no `Co-authored-by` and similar).
- New behavior gets a test that pins it; tamper protections and error messages are asserted with exact values.
