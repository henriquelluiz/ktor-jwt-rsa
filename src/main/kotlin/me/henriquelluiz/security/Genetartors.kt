package me.henriquelluiz.security

import kotlinx.serialization.Serializable
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.RSAPublicKey
import java.util.*

@Serializable
data class JWK(val kty: String, val e: String, val kid: String, val n: String)

fun generateKeyPair(): Pair<PrivateKey, PublicKey> {
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    keyPairGenerator.initialize(2048)
    val keyPair = keyPairGenerator.genKeyPair()
    return Pair(keyPair.private, keyPair.public)
}

fun getPrivateKeyBase64(key: PrivateKey): String = Base64.getEncoder().encodeToString(key.encoded)

fun getPublicKeyBase64(key: PublicKey): String {
    val encodedKey = Base64.getEncoder().encodeToString(key.encoded)
    return "-----BEGIN PUBLIC KEY-----\n$encodedKey\n-----END PUBLIC KEY-----"
}

fun getPublicKeyComponents(key: RSAPublicKey): Pair<String, String> {
    return Pair(key.modulus.toString(16), key.publicExponent.toBase64URL())
}

fun normalizeAndEncode(modulus: String): String {
    val normalized = modulus.replace(":", "").replace("\\.".toRegex(), "")
    val decodedHex = normalized.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    return Base64.getUrlEncoder().withoutPadding().encodeToString(decodedHex)
}

fun BigInteger.toBase64URL(): String {
    val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(this.toByteArray())
    return if (encoded.startsWith("AA")) encoded.substring(2) else encoded
}