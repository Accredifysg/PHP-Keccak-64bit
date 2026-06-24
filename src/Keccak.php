<?php

namespace Accredify\Keccak;

use InvalidArgumentException;
use RuntimeException;

/**
 * Fast, dependency-free Keccak and SHAKE for 64-bit PHP.
 *
 * A drop-in replacement for the {@see \kornrunner\Keccak} API that is roughly
 * 5x faster on large inputs. It implements the original (Ethereum-style, suffix
 * 0x01) Keccak hashes at 224/256/384/512 bits and the NIST SHAKE128/SHAKE256
 * extendable-output functions (suffix 0x1F), producing byte-for-byte identical
 * digests to kornrunner/keccak on every input.
 *
 * The speed-up comes from three changes versus the reference pure-PHP fallback:
 *   1. The 1600-bit state is kept as 25 native 64-bit integers rather than pairs
 *      of 32-bit halves, so each lane operation is a single CPU instruction.
 *   2. The whole input is unpacked once with `unpack('V*', ...)` instead of
 *      slicing it 8 bytes at a time inside the absorb loop.
 *   3. Theta is fully unrolled and each Chi row is unrolled, and the lane rotations use
 *      precomputed masks so the unsigned right-shift needs no per-call arithmetic.
 *
 * Only the sponge bookkeeping (rate, padding suffix, squeeze length) varies
 * between variants; the Keccak-f[1600] permutation is identical for all of them.
 *
 * Because the whole message is unpacked up front (point 2 above), peak memory is a few
 * times the input size. This suits documents and other bounded payloads; for streaming or
 * very large (hundreds-of-MB) inputs a constant-memory hasher is a better fit.
 *
 * Requires a 64-bit build of PHP (PHP_INT_SIZE === 8); the lane arithmetic relies
 * on native 64-bit integers and the constructor-free entry points throw on 32-bit
 * platforms rather than return a wrong digest.
 */
final class Keccak
{
    /** Number of rounds in the Keccak-f[1600] permutation. */
    private const ROUNDS = 24;

    /** Width of the Keccak state in bits; the rate is derived as STATE_BITS - capacity. */
    private const STATE_BITS = 1600;

    /** Output sizes (in bits) supported by {@see hash()}. */
    private const HASH_BITS = [224, 256, 384, 512];

    /** Security strengths (in bits) supported by {@see shake()}. */
    private const SHAKE_SECURITY = [128, 256];

    /** Domain-separation suffix for the original Keccak hashes. */
    private const SUFFIX_KECCAK = 0x01;

    /** Domain-separation suffix for the NIST SHAKE functions. */
    private const SUFFIX_SHAKE = 0x1F;

    /** Per-step lane rotation offsets for the Rho-Pi step. */
    private const ROTATION_OFFSETS = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
        27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ];

    /** Destination lane index for each Rho-Pi step (the Pi permutation). */
    private const LANE_PERMUTATION = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ];

    /**
     * This is a static utility and is never instantiated.
     *
     * @codeCoverageIgnore
     */
    private function __construct() {}

    /**
     * Hash binary data with a fixed-length Keccak digest.
     *
     * @param  string  $input  Raw binary input.
     * @param  int  $bits  Digest size: 224, 256, 384 or 512.
     * @param  bool  $binaryOutput  Return raw bytes instead of a lowercase hex string.
     * @return string The digest, hex-encoded unless $binaryOutput is true.
     *
     * @throws InvalidArgumentException If $bits is not a supported size.
     */
    public static function hash(string $input, int $bits, bool $binaryOutput = false): string
    {
        if (! in_array($bits, self::HASH_BITS, true)) {
            throw new InvalidArgumentException(
                'Unsupported Keccak size '.$bits.'; expected one of 224, 256, 384, 512.'
            );
        }

        // Capacity is twice the digest size; the rest of the 1600-bit state is the rate.
        $rate = intdiv(self::STATE_BITS - 2 * $bits, 8);
        $digest = self::sponge($input, $rate, self::SUFFIX_KECCAK, intdiv($bits, 8));

        return $binaryOutput ? $digest : bin2hex($digest);
    }

    /**
     * Hash binary data with a SHAKE extendable-output function.
     *
     * @param  string  $input  Raw binary input.
     * @param  int  $security  Security strength: 128 (SHAKE128) or 256 (SHAKE256).
     * @param  int  $length  Output length in bits; must be a non-negative multiple of 8.
     * @param  bool  $binaryOutput  Return raw bytes instead of a lowercase hex string.
     * @return string The output, hex-encoded unless $binaryOutput is true.
     *
     * @throws InvalidArgumentException If $security or $length is invalid.
     */
    public static function shake(string $input, int $security, int $length, bool $binaryOutput = false): string
    {
        if (! in_array($security, self::SHAKE_SECURITY, true)) {
            throw new InvalidArgumentException(
                'Unsupported SHAKE security '.$security.'; expected 128 or 256.'
            );
        }

        if ($length < 0 || $length % 8 !== 0) {
            throw new InvalidArgumentException(
                'SHAKE output length must be a non-negative multiple of 8 bits, got '.$length.'.'
            );
        }

        $rate = intdiv(self::STATE_BITS - 2 * $security, 8);
        $output = self::sponge($input, $rate, self::SUFFIX_SHAKE, intdiv($length, 8));

        return $binaryOutput ? $output : bin2hex($output);
    }

    /**
     * Absorb the (padded) input and squeeze out the requested number of bytes.
     *
     * @param  string  $data  Raw binary input.
     * @param  int  $rate  Sponge rate in bytes (a multiple of 8).
     * @param  int  $suffix  Domain-separation byte XORed into the first pad byte.
     * @param  int  $outLen  Number of output bytes to squeeze.
     * @return string The raw output bytes.
     */
    private static function sponge(string $data, int $rate, int $suffix, int $outLen): string
    {
        // @codeCoverageIgnoreStart
        // 64-bit only; CI runs on 64-bit so this guard is not exercised in coverage.
        if (PHP_INT_SIZE !== 8) {
            throw new RuntimeException('Accredify\\Keccak\\Keccak requires a 64-bit build of PHP.');
        }
        // @codeCoverageIgnoreEnd

        $inlen = strlen($data);

        // Multi-rate padding: XOR the suffix byte at the input boundary, zero-fill to a
        // rate boundary, then set the high bit of the final rate byte. When a single byte
        // serves as both the first and last pad byte they combine (e.g. 0x01 | 0x80 = 0x81).
        $padlen = $rate - ($inlen % $rate);
        $padded = $data.str_repeat("\x00", $padlen);
        $padded[$inlen] = chr(ord($padded[$inlen]) ^ $suffix);
        $padded[strlen($padded) - 1] = chr(ord($padded[strlen($padded) - 1]) ^ 0x80);

        // Unpack the whole message once as 32-bit little-endian words (1-indexed). Two
        // consecutive words form one 64-bit lane: low word | (high word << 32).
        /** @var array<int, int> $words */
        $words = unpack('V*', $padded);
        $nwords = count($words);

        $lanes = $rate >> 3;   // rate / 8 lanes per block
        $stride = $rate >> 2;  // rate / 4 words per block

        $state = array_fill(0, 25, 0);

        // Absorb one rate-sized block at a time.
        for ($w = 0; $w < $nwords; $w += $stride) {
            for ($l = 0; $l < $lanes; $l++) {
                $state[$l] ^= $words[$w + $l * 2 + 1] | ($words[$w + $l * 2 + 2] << 32);
            }
            self::permute($state);
        }

        // Squeeze: emit the first $lanes lanes per block as little-endian bytes, running
        // the permutation again whenever more output is required (SHAKE with long output).
        $out = '';
        while (strlen($out) < $outLen) {
            for ($l = 0; $l < $lanes; $l++) {
                $out .= pack('V2', $state[$l] & 0xFFFFFFFF, ($state[$l] >> 32) & 0xFFFFFFFF);
                if (strlen($out) >= $outLen) {
                    break;
                }
            }
            if (strlen($out) < $outLen) {
                self::permute($state);
            }
        }

        return substr($out, 0, $outLen);
    }

    /**
     * The Keccak-f[1600] permutation: 24 rounds of Theta, Rho-Pi, Chi and Iota.
     *
     * @param  array<int, int>  $st  The 25-lane state, mutated in place.
     */
    private static function permute(array &$st): void
    {
        $rc = self::roundConstants();
        $masks = self::rotationMasks();
        $rot = self::ROTATION_OFFSETS;
        $piln = self::LANE_PERMUTATION;

        for ($r = 0; $r < self::ROUNDS; $r++) {
            // Theta: column parities, then fold the rotated neighbour into every lane.
            $b0 = $st[0] ^ $st[5] ^ $st[10] ^ $st[15] ^ $st[20];
            $b1 = $st[1] ^ $st[6] ^ $st[11] ^ $st[16] ^ $st[21];
            $b2 = $st[2] ^ $st[7] ^ $st[12] ^ $st[17] ^ $st[22];
            $b3 = $st[3] ^ $st[8] ^ $st[13] ^ $st[18] ^ $st[23];
            $b4 = $st[4] ^ $st[9] ^ $st[14] ^ $st[19] ^ $st[24];

            $t0 = $b4 ^ (($b1 << 1) | (($b1 >> 63) & 1));
            $t1 = $b0 ^ (($b2 << 1) | (($b2 >> 63) & 1));
            $t2 = $b1 ^ (($b3 << 1) | (($b3 >> 63) & 1));
            $t3 = $b2 ^ (($b4 << 1) | (($b4 >> 63) & 1));
            $t4 = $b3 ^ (($b0 << 1) | (($b0 >> 63) & 1));

            $st[0] ^= $t0;
            $st[5] ^= $t0;
            $st[10] ^= $t0;
            $st[15] ^= $t0;
            $st[20] ^= $t0;
            $st[1] ^= $t1;
            $st[6] ^= $t1;
            $st[11] ^= $t1;
            $st[16] ^= $t1;
            $st[21] ^= $t1;
            $st[2] ^= $t2;
            $st[7] ^= $t2;
            $st[12] ^= $t2;
            $st[17] ^= $t2;
            $st[22] ^= $t2;
            $st[3] ^= $t3;
            $st[8] ^= $t3;
            $st[13] ^= $t3;
            $st[18] ^= $t3;
            $st[23] ^= $t3;
            $st[4] ^= $t4;
            $st[9] ^= $t4;
            $st[14] ^= $t4;
            $st[19] ^= $t4;
            $st[24] ^= $t4;

            // Rho-Pi: rotate the carried lane and scatter it along the Pi permutation.
            // The mask clears the bits PHP's arithmetic `>>` sign-extends, giving an
            // unsigned rotate.
            $t = $st[1];
            for ($i = 0; $i < 24; $i++) {
                $j = $piln[$i];
                $tmp = $st[$j];
                $n = $rot[$i];
                $st[$j] = ($t << $n) | (($t >> (64 - $n)) & $masks[$i]);
                $t = $tmp;
            }

            // Chi: non-linear mixing across each row of five lanes.
            for ($j = 0; $j < 25; $j += 5) {
                $c0 = $st[$j];
                $c1 = $st[$j + 1];
                $c2 = $st[$j + 2];
                $c3 = $st[$j + 3];
                $c4 = $st[$j + 4];
                $st[$j] = $c0 ^ ((~$c1) & $c2);
                $st[$j + 1] = $c1 ^ ((~$c2) & $c3);
                $st[$j + 2] = $c2 ^ ((~$c3) & $c4);
                $st[$j + 3] = $c3 ^ ((~$c4) & $c0);
                $st[$j + 4] = $c4 ^ ((~$c0) & $c1);
            }

            // Iota: break round symmetry with the round constant.
            $st[0] ^= $rc[$r];
        }
    }

    /**
     * The unsigned-rotate masks for each Rho-Pi step, computed once.
     *
     * For a left rotation by n the carried bits arrive via `$t >> (64 - n)`, whose
     * top (64 - n) bits are sign-extended garbage. Masking with the low n bits
     * (PHP_INT_MAX >> (63 - n)) discards them. The PHP_INT_MAX form is used because
     * `(1 << n) - 1` overflows to float at n = 63.
     *
     * @return array<int, int>
     */
    private static function rotationMasks(): array
    {
        /** @var array<int, int>|null $masks */
        static $masks = null;
        if ($masks !== null) {
            return $masks;
        }

        $masks = [];
        foreach (self::ROTATION_OFFSETS as $n) {
            $masks[] = PHP_INT_MAX >> (63 - $n);
        }

        return $masks;
    }

    /**
     * The canonical Keccak round constants as signed 64-bit integers, computed once.
     *
     * Stored as hex strings and assembled from 32-bit halves so the literals stay
     * readable and never trip PHP's float promotion for values above PHP_INT_MAX.
     *
     * @return array<int, int>
     */
    private static function roundConstants(): array
    {
        /** @var array<int, int>|null $constants */
        static $constants = null;
        if ($constants !== null) {
            return $constants;
        }

        $hex = [
            '0000000000000001', '0000000000008082', '800000000000808a', '8000000080008000',
            '000000000000808b', '0000000080000001', '8000000080008081', '8000000000008009',
            '000000000000008a', '0000000000000088', '0000000080008009', '000000008000000a',
            '000000008000808b', '800000000000008b', '8000000000008089', '8000000000008003',
            '8000000000008002', '8000000000000080', '000000000000800a', '800000008000000a',
            '8000000080008081', '8000000000008080', '0000000080000001', '8000000080008008',
        ];

        $constants = [];
        foreach ($hex as $word) {
            $high = (int) hexdec(substr($word, 0, 8));
            $low = (int) hexdec(substr($word, 8, 8));
            $constants[] = $low | ($high << 32);
        }

        return $constants;
    }
}
