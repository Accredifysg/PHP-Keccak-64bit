# PHP-Keccak-64bit

Fast, dependency-free **Keccak** (224/256/384/512) and **SHAKE** (128/256) for 64-bit PHP.

It is a drop-in replacement for [`kornrunner/keccak`](https://github.com/kornrunner/php-keccak)
that is roughly **5× faster** on large inputs. Output is byte-for-byte identical to
kornrunner for every fixed-length hash and for SHAKE up to the rate; for longer SHAKE output
this package follows the NIST standard, where kornrunner does not (see
[Compatibility](#compatibility-with-kornrunnerkeccak)).

> **Note:** this is the original (Ethereum-style, `0x01`-suffixed) Keccak, the same variant
> implemented by `kornrunner/keccak`. It is **not** the NIST-finalised SHA-3 (which uses the
> `0x06` suffix). The SHAKE functions, however, are the NIST `0x1F`-suffixed XOFs.

## Why

When the native [`Keccak256` C extension](https://github.com/Accredify/Keccak256PHP) is not
installed, a pure-PHP Keccak dominates hashing time. Profiling a ~0.6 MB
document, a single Keccak-256 call accounted for ~99% of processing time. This package keeps the
1600-bit state as 25 native 64-bit integers, unpacks the message once, and unrolls the
permutation — for an end-to-end speed-up of ~5.6× over `kornrunner/keccak`:

| Workload (PHP 8.5, no C extension, Xdebug off) | kornrunner/keccak | this package | speed-up |
| --- | --- | --- | --- |
| Keccak-256 of 0.6 MB | ~525 ms | ~92 ms | ~5.7× |
| End-to-end wrap of a 0.59 MB document | ~540 ms | ~97 ms | ~5.6× |

The whole message is unpacked into memory up front (that's where most of the speed-up comes
from), so peak memory is a few times the input size. This is ideal for documents and other
bounded payloads; for streaming or very large (hundreds-of-MB) inputs, a constant-memory
hasher is a better fit.

## Requirements

- **64-bit PHP** (`PHP_INT_SIZE === 8`). The lane arithmetic relies on native 64-bit integers;
  on a 32-bit build the entry points throw a `RuntimeException` rather than return a wrong
  digest. If you need 32-bit support, use `kornrunner/keccak` directly.
- PHP **8.2+**. No PHP extensions and no runtime dependencies.

## Installation

```bash
composer require accredifysg/php-keccak-64bit
```

## Usage

The API mirrors `kornrunner/keccak`, so it is a drop-in replacement.

```php
use Accredify\Keccak\Keccak;

// Fixed-length Keccak hashes (hex output by default)
Keccak::hash('', 224);
// f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd

Keccak::hash('', 256);
// c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470

Keccak::hash('', 384);
// 2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff

Keccak::hash('', 512);
// 0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e

// SHAKE extendable-output functions (output length given in bits)
Keccak::shake('', 128, 256);
// 7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26

Keccak::shake('', 256, 512);
// 46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be

// Raw binary output instead of hex
Keccak::hash('data', 256, true);   // 32 raw bytes
Keccak::shake('data', 128, 256, true);
```

### API

```php
Keccak::hash(string $input, int $bits, bool $binaryOutput = false): string
```
- `$bits` — one of `224`, `256`, `384`, `512`.

```php
Keccak::shake(string $input, int $security, int $length, bool $binaryOutput = false): string
```
- `$security` — `128` (SHAKE128) or `256` (SHAKE256).
- `$length` — output length **in bits**; must be a non-negative multiple of 8.

Both methods return a lowercase hex string, or raw bytes when `$binaryOutput` is `true`.

## Compatibility with kornrunner/keccak

The API and output match `kornrunner/keccak` exactly for:

- **all fixed-length hashes** (`hash` at 224/256/384/512), and
- **SHAKE output up to the rate** — 168 bytes for SHAKE128, 136 bytes for SHAKE256.

For SHAKE output **longer than the rate** the two libraries diverge. kornrunner squeezes a
single 200-byte state once and never re-permutes, so it cannot return more than 200 bytes and
is non-conformant beyond the rate. This package implements the full NIST sponge squeeze, so its
long SHAKE output matches the SHA-3 standard (verified against OpenSSL / Python `hashlib`).
If you depend on kornrunner's exact byte stream past the rate, that output is not standard and
is not reproduced here.

**Output length:** `shake()` requires `$length` to be a multiple of 8 bits and throws
otherwise; kornrunner instead silently floors a non-multiple down to whole bytes. For
byte-aligned lengths (the usual case) the two behave identically.

## Correctness

Digests are verified to be byte-for-byte identical to `kornrunner/keccak` by the test suite:
NIST/Ethereum known-answer vectors for every variant, cross-checks across rate-block
boundaries for all four hash sizes and both SHAKE variants, the multi-block squeeze path,
and a property test over random binary input.

```bash
composer test       # run the test suite
composer lint       # check code style (Pint)
composer stan       # static analysis (PHPStan, level max)
composer check      # all of the above
```

## License

MIT. See [LICENSE](LICENSE).
