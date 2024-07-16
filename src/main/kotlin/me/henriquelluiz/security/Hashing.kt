package me.henriquelluiz.security

import de.mkammerer.argon2.Argon2Factory
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

fun hashPassword(password: String): String {
    val argon2 = Argon2Factory.create()
    return argon2.hash(5, 32768, 2, password.toCharArray())
}


fun hashContentHMAC(data: String): String {
    val secretKey = Files.readString(Path.of("certs/secret_key_hmac.txt"))
        ?: throw IOException("Secret key not found")

    val algorithm = "HmacSHA256"
    val mac = Mac.getInstance(algorithm)
    val secretKeySpec = SecretKeySpec(secretKey.toByteArray(), algorithm)
    mac.init(secretKeySpec)
    return mac.doFinal(data.toByteArray()).joinToString("") { "%02x".format(it) }
}

fun hashETag(data: String): String {
    return MessageDigest
        .getInstance("MD5")
        .digest(data.toByteArray())
        .joinToString("") { "%02x".format(it) }
}

fun checkPassword(hashed: String, password: String): Boolean {
    val argon2 = Argon2Factory.create()
    return argon2.verify(hashed, password.toCharArray())
}