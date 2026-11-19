package dev.yazwa.nyampy.sub

import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Base64

/**
 * The one curve operation the registration needs, checked against the RFC's own
 * vectors: a ladder that is wrong answers the API with a key the peer will never
 * complete a handshake with, and nothing else in the app would notice.
 */
class X25519Test {
    private fun hex(value: String): ByteArray =
        value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

    @Test
    fun `the rfc 7748 vectors hold`() {
        // §6.1, Alice and Bob.
        val aliceKey = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val bobKey = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        assertEquals(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            X25519.publicKey(aliceKey).hex(),
        )
        assertEquals(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
            X25519.publicKey(bobKey).hex(),
        )
    }

    @Test
    fun `the api's base64 shape comes out the same`() {
        val privateKey = Base64.getEncoder().encodeToString(
            hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
        )
        assertEquals(
            Base64.getEncoder().encodeToString(
                hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
            ),
            X25519.publicKeyBase64(privateKey),
        )
    }
}
