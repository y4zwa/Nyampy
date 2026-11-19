package dev.yazwa.nyampy.sub

import java.math.BigInteger

/**
 * X25519 public-key derivation, the one arithmetic step WARP registration needs: the
 * API wants our public key and nothing in the platform below API 33 computes it. A
 * Montgomery ladder over BigInteger is slow by cryptography's standards and instant at
 * the one call the generator makes; the alternative is a new dependency, which this is
 * not worth.
 *
 * RFC 7748, §5: the scalar is clamped, the ladder runs over bits 254..0, the u
 * coordinate is little-endian, and the field is 2^255 - 19.
 */
object X25519 {
    private val P = BigInteger.TWO.pow(255) - BigInteger.valueOf(19)
    private val A24 = BigInteger.valueOf(121665)
    private val BASE_POINT = ByteArray(32).also { it[0] = 9 }

    /** The 32-byte public key for a 32-byte private key, both raw. */
    fun publicKey(privateKey: ByteArray): ByteArray {
        require(privateKey.size == 32) { "X25519 private key must be 32 bytes, got ${privateKey.size}" }
        val scalar = privateKey.copyOf()
        scalar[0] = (scalar[0].toInt() and 248).toByte()
        scalar[31] = ((scalar[31].toInt() and 127) or 64).toByte()
        return ladder(scalar, BASE_POINT)
    }

    /** The base64 form the WARP API and WireGuard configs speak. */
    fun publicKeyBase64(privateKeyBase64: String): String =
        java.util.Base64.getEncoder().encodeToString(
            publicKey(java.util.Base64.getDecoder().decode(privateKeyBase64)),
        )

    private fun ladder(scalar: ByteArray, point: ByteArray): ByteArray {
        val k = decodeLittleEndian(scalar)
        val x1 = decodeLittleEndian(point).mod(P)
        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = x1
        var z3 = BigInteger.ONE
        var swap = 0

        for (bit in 254 downTo 0) {
            val kt = ((k.shiftRight(bit).toInt()) and 1)
            swap = swap xor kt
            if (swap == 1) {
                val tx = x2; x2 = x3; x3 = tx
                val tz = z2; z2 = z3; z3 = tz
            }
            swap = kt

            val a = x2.add(z2).mod(P)
            val aa = a.multiply(a).mod(P)
            val b = x2.subtract(z2).mod(P)
            val bb = b.multiply(b).mod(P)
            val e = aa.subtract(bb).mod(P)
            val c = x3.add(z3).mod(P)
            val d = x3.subtract(z3).mod(P)
            val da = d.multiply(a).mod(P)
            val cb = c.multiply(b).mod(P)
            val sum = da.add(cb).mod(P)
            val diff = da.subtract(cb).mod(P)
            x3 = sum.multiply(sum).mod(P)
            z3 = x1.multiply(diff.multiply(diff).mod(P)).mod(P)
            x2 = aa.multiply(bb).mod(P)
            z2 = e.multiply(aa.add(A24.multiply(e)).mod(P)).mod(P)
        }
        if (swap == 1) {
            x2 = x3
            z2 = z3
        }
        return encodeLittleEndian(x2.multiply(z2.modPow(P.subtract(BigInteger.TWO), P)).mod(P))
    }

    private fun decodeLittleEndian(bytes: ByteArray): BigInteger = BigInteger(1, bytes.reversedArray())

    private fun encodeLittleEndian(value: BigInteger): ByteArray {
        val big = value.toByteArray() // big-endian, possibly 33 bytes with a sign byte
        val trimmed = if (big.size > 32) big.copyOfRange(big.size - 32, big.size) else big
        val out = ByteArray(32)
        trimmed.reversedArray().copyInto(out, 0)
        return out
    }
}
