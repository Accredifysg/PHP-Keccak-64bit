<?php

namespace Accredify\Keccak\Tests;

use Accredify\Keccak\Keccak;
use InvalidArgumentException;
use kornrunner\Keccak as Reference;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class KeccakTest extends TestCase
{
    /**
     * Seed the PRNG so the randomized cross-checks are deterministic and any failure is
     * reproducible across runs and PHP versions (mt_rand has been stable since PHP 7.1).
     */
    protected function setUp(): void
    {
        parent::setUp();

        mt_srand(20260624);
    }

    /**
     * A pseudo-random binary string of pseudo-random length in [1, $maxLength], drawn from the
     * seeded PRNG. Used instead of random_bytes() so a failing case can be replayed.
     */
    private function randomBytes(int $maxLength): string
    {
        $length = mt_rand(1, $maxLength);

        $bytes = '';
        for ($i = 0; $i < $length; $i++) {
            $bytes .= chr(mt_rand(0, 255));
        }

        return $bytes;
    }

    /**
     * Known Keccak answers (the original Ethereum variant, suffix 0x01).
     *
     * @return array<string, array{0: string, 1: int, 2: string}>
     */
    public static function hashVectors(): array
    {
        return [
            'empty 224' => ['', 224, 'f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd'],
            'empty 256' => ['', 256, 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'],
            'empty 384' => ['', 384, '2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff'],
            'empty 512' => ['', 512, '0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e'],
            'abc 256' => ['abc', 256, '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'],
            'fox 256' => ['The quick brown fox jumps over the lazy dog', 256, '4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15'],
        ];
    }

    #[DataProvider('hashVectors')]
    public function test_hash_matches_known_vectors(string $input, int $bits, string $expected): void
    {
        $this->assertSame($expected, Keccak::hash($input, $bits));
    }

    /**
     * Known SHAKE answers (NIST XOFs, suffix 0x1F); output length is in bits.
     *
     * @return array<string, array{0: int, 1: int, 2: string}>
     */
    public static function shakeVectors(): array
    {
        return [
            'empty shake128/256' => [128, 256, '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26'],
            'empty shake256/512' => [256, 512, '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be'],
        ];
    }

    #[DataProvider('shakeVectors')]
    public function test_shake_matches_known_vectors(int $security, int $length, string $expected): void
    {
        $this->assertSame($expected, Keccak::shake('', $security, $length));
    }

    /**
     * Authoritative multi-block SHAKE vectors, where the output exceeds the rate and the
     * sponge is squeezed across several permutations. Generated with Python's hashlib
     * (OpenSSL) and independently verified. kornrunner/keccak cannot reproduce these: its
     * shake emits a single 200-byte state and never re-permutes, so it is only correct up
     * to the rate. Lengths are in bits.
     *
     * @return array<string, array{0: int, 1: string, 2: int, 3: string}>
     */
    public static function shakeMultiBlockVectors(): array
    {
        return [
            'shake128 empty 256B' => [128, '', 2048, '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32def58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c922a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619'],
            'shake256 empty 256B' => [256, '', 2048, '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d677231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5caaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53fb8e9eb2ea203bdc970f50ae55428a91f7f53ac266b28419c3778a15fd248d339ede785fb7f'],
            'shake128 abc 250B' => [128, 'abc', 2000, '5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc844c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca5783789a41f8611214ce612394df286a62d1a2252aa94db9c538956c717dc2bed4f232a0294c857c730aa16067ac1062f1201fb0d377cfb9cde4c63599b27f3462bba4a0ed296c801f9ff7f57302bb3076ee145f97a32ae68e76ab66c48d51675bd49acc29082f5647584e6aa01b3f5af057805f973ff8ecb8b226ac32ada6f01c1fcd4818cb006aa5b4cdb3611eb1e533c8964cacfdf31012cd3fb744d02225b988b475375faad996eb1b9176ecb0f8b2871723d6dbb804e23357e507'],
            'shake128 empty 512B' => [128, '', 4096, '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32def58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c922a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b1de33fd75081f592305f2e4526edc09631b10958f464d889f31ba010250fda7f1368ec2967fc84ef2ae9aff268e0b1700affc6820b523a3d917135f2dff2ee06bfe72b3124721d4a26c04e53a75e30e73a7a9c4a95d91c55d495e9f51dd0b5e9d83c6d5e8ce803aa62b8d654db53d09b8dcff273cdfeb573fad8bcd45578bec2e770d01efde86e721a3f7c6cce275dabe6e2143f1af18da7efddc4c7b70b5e345db93cc936bea323491ccb38a388f546a9ff00dd4e1300b9b2153d2041d205b443e41b45a653f2a5c4492c1add544512dda2529833462b71a41a45be97290b6f'],
            'shake256 abc 200B' => [256, 'abc', 1600, '483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e41385141204f329979fd3047a13c5657724ada64d2470157b3cdc288620944d78dbcddbd912993f0913f164fb2ce95131a2d09a3e6d51cbfc622720d7a75c6334e8a2d7ec71a7cc29cf0ea610eeff1a588290a53000faa79932becec0bd3cd0b33a7e5d397fed1ada9442b99903f4dcfd8559ed3950faf40fe6f3b5d710ed3b677513771af6bfe119'],
        ];
    }

    #[DataProvider('shakeMultiBlockVectors')]
    public function test_shake_matches_multi_block_vectors(int $security, string $input, int $length, string $expected): void
    {
        $this->assertSame($expected, Keccak::shake($input, $security, $length));
    }

    /**
     * Input lengths spanning each variant's rate-block boundary, where the padding is
     * most error-prone. Rates: keccak224=144, 256=136, 384=104, 512=72 bytes.
     *
     * @return array<string, array{0: int, 1: int}>
     */
    public static function hashBoundaries(): array
    {
        $rates = [224 => 144, 256 => 136, 384 => 104, 512 => 72];

        $cases = [];
        foreach ($rates as $bits => $rate) {
            foreach ([0, 1, $rate - 1, $rate, $rate + 1, 2 * $rate, 2 * $rate + 1, 5000] as $length) {
                $cases["keccak{$bits} len {$length}"] = [$bits, $length];
            }
        }

        return $cases;
    }

    #[DataProvider('hashBoundaries')]
    public function test_hash_matches_reference_at_block_boundaries(int $bits, int $length): void
    {
        $input = str_repeat('A', $length);

        $this->assertSame(Reference::hash($input, $bits), Keccak::hash($input, $bits));
    }

    /**
     * SHAKE cross-checks against kornrunner across input boundaries and output lengths.
     *
     * Output stays within the rate (<= rate bytes), the range where kornrunner is correct:
     * its shake emits a single 200-byte state and never re-permutes, so it diverges from the
     * NIST standard beyond the rate. The multi-block squeeze is covered by the authoritative
     * vectors in {@see shakeMultiBlockVectors} instead. Lengths are in bits.
     *
     * @return array<string, array{0: int, 1: int, 2: int}>
     */
    public static function shakeCases(): array
    {
        $rates = [128 => 168, 256 => 136];

        $cases = [];
        foreach ($rates as $security => $rate) {
            $inputLengths = [0, 1, $rate - 1, $rate, $rate + 1, 2 * $rate];
            // One byte, 32 bytes, and exactly one full rate block (kornrunner's upper bound).
            $outputBits = [8, 256, $rate * 8];

            foreach ($inputLengths as $inputLength) {
                foreach ($outputBits as $length) {
                    $cases["shake{$security} in {$inputLength} out {$length}"] = [$security, $inputLength, $length];
                }
            }
        }

        return $cases;
    }

    #[DataProvider('shakeCases')]
    public function test_shake_matches_reference(int $security, int $inputLength, int $length): void
    {
        $input = str_repeat('A', $inputLength);

        $this->assertSame(
            Reference::shake($input, $security, $length),
            Keccak::shake($input, $security, $length)
        );
    }

    public function test_hash_matches_reference_on_random_input(): void
    {
        foreach ([224, 256, 384, 512] as $bits) {
            for ($i = 0; $i < 10; $i++) {
                $input = $this->randomBytes(4096);

                $this->assertSame(
                    Reference::hash($input, $bits),
                    Keccak::hash($input, $bits),
                    "Mismatch for keccak{$bits}, input length ".strlen($input)
                );
            }
        }
    }

    public function test_shake_matches_reference_on_random_input(): void
    {
        foreach ([128, 256] as $security) {
            for ($i = 0; $i < 10; $i++) {
                $input = $this->randomBytes(4096);
                // Keep output within the rate, where kornrunner agrees with the NIST standard.
                $length = mt_rand(1, 136) * 8;

                $this->assertSame(
                    Reference::shake($input, $security, $length),
                    Keccak::shake($input, $security, $length),
                    "Mismatch for shake{$security}, input length ".strlen($input).", output {$length} bits"
                );
            }
        }
    }

    /**
     * Cross-check SHAKE against OpenSSL, a standard implementation independent of kornrunner
     * and built into PHP (ext-openssl), so it needs no extra dependency. openssl_digest emits
     * only the default XOF length — 16 bytes for SHAKE128, 32 for SHAKE256 — so this covers the
     * single-block range; the multi-block path is pinned by the hardcoded vectors above.
     */
    public function test_shake_matches_openssl_on_random_input(): void
    {
        foreach (['shake128' => 128, 'shake256' => 256] as $algo => $security) {
            $bytes = intdiv(strlen((string) openssl_digest('', $algo)), 2);

            for ($i = 0; $i < 10; $i++) {
                $input = $this->randomBytes(4096);

                $this->assertSame(
                    openssl_digest($input, $algo),
                    Keccak::shake($input, $security, $bytes * 8),
                    "Mismatch vs OpenSSL for {$algo}, input length ".strlen($input)
                );
            }
        }
    }

    public function test_hash_binary_output_is_raw_bytes(): void
    {
        $hex = Keccak::hash('openattestation', 256);
        $raw = Keccak::hash('openattestation', 256, true);

        $this->assertSame(32, strlen($raw));
        $this->assertSame($hex, bin2hex($raw));
    }

    public function test_shake_binary_output_is_raw_bytes(): void
    {
        $hex = Keccak::shake('openattestation', 128, 512);
        $raw = Keccak::shake('openattestation', 128, 512, true);

        $this->assertSame(64, strlen($raw));
        $this->assertSame($hex, bin2hex($raw));
    }

    public function test_hash_returns_lowercase_hex_digest(): void
    {
        $digest = Keccak::hash('openattestation', 256);

        $this->assertSame(64, strlen($digest));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $digest);
    }

    public function test_hash_rejects_unsupported_size(): void
    {
        $this->expectException(InvalidArgumentException::class);

        Keccak::hash('data', 200);
    }

    public function test_shake_rejects_unsupported_security(): void
    {
        $this->expectException(InvalidArgumentException::class);

        Keccak::shake('data', 224, 256);
    }

    public function test_shake_rejects_non_byte_aligned_length(): void
    {
        $this->expectException(InvalidArgumentException::class);

        Keccak::shake('data', 128, 100);
    }
}
