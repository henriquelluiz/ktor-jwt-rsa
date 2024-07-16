package me.henriquelluiz.security

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import me.henriquelluiz.security.Certs.writeAPrivatePEMFile
import me.henriquelluiz.security.Certs.writeAPrivatePK8File
import me.henriquelluiz.security.Certs.writeAPublicSPKIFile
import me.henriquelluiz.security.Certs.writePublicKeyBase64InJWKS
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.interfaces.RSAPublicKey

object Certs {
    private val keys = generateKeyPair()

    fun writeAPrivatePK8File() {
        val privateKey = keys.first
        val privateKeyString = getPrivateKeyBase64(privateKey)

        val commentedPrivateKey = """
            -----BEGIN PRIVATE KEY-----
            $privateKeyString
            -----END PRIVATE KEY-----
        """.trimIndent().toByteArray()

        val certsPath = Paths.get("certs/raw/private_key.pk8")
        createFileIfItNotExists(certsPath)

        try {
            Files.write(certsPath, commentedPrivateKey)
        } catch (e: IOException) {
            e.printStackTrace()
        }
    }

    fun writeAPublicSPKIFile() {
        val publicKey = keys.second
        val publicKeyString = getPublicKeyBase64(publicKey)

        val certsPath = Paths.get("certs/raw/public_key.spki")
        createFileIfItNotExists(certsPath)

        try {
            Files.write(certsPath, publicKeyString.toByteArray())
        } catch (e: IOException) {
            e.printStackTrace()
        }
    }

    fun writePublicKeyBase64InJWKS() {
        val publicKey = keys.second as RSAPublicKey
        val components = getPublicKeyComponents(publicKey)
        val exponent = components.second
        val modulus = normalizeAndEncode(components.first)
        val jwks = listOf(
            JWK(
                kty = "RSA",
                kid = "1",
                e = exponent,
                n = modulus
            )
        )
        val jsonContent = Json.encodeToJsonElement(jwks)
        val jwksString = """{"keys": $jsonContent}"""
        val certsPath = Paths.get("certs/jwks.json")
        createFileIfItNotExists(certsPath)

        try {
            Files.write(certsPath, jwksString.toByteArray())
        } catch (e: IOException) {
            e.printStackTrace()
        }
    }

    fun writeAPrivatePEMFile() {
        val privateKey = keys.first
        val privateKeyString = getPrivateKeyBase64(privateKey)
            .replace("\\s+".toRegex(), "")

        val certsPath = Paths.get("certs/private_key.pem")
        createFileIfItNotExists(certsPath)

        try {
            Files.write(certsPath, privateKeyString.toByteArray())
        } catch (e: IOException) {
            e.printStackTrace()
        }
    }

    private fun createFileIfItNotExists(path: Path) {
        if (!Files.exists(path)) {
            Files.createFile(path)
        }
    }
}

fun main() {
    writeAPrivatePK8File()
    writeAPublicSPKIFile()
    writePublicKeyBase64InJWKS()
    writeAPrivatePEMFile()
}