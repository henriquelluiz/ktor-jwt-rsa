package me.henriquelluiz.plugins

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.response.*
import io.ktor.utils.io.errors.*
import me.henriquelluiz.security.JWTProperties
import org.koin.ktor.ext.inject
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.util.*


fun Application.configureJWT() {
    val properties by inject<JWTProperties>()

    authentication {
        jwt {
            realm = properties.realm

            verifier(properties.jwkProvider, properties.issuer) {
                acceptLeeway(3)
            }

            validate { credential ->
                if (credential.payload.getClaim("username").asString() != "") {
                    JWTPrincipal(credential.payload)
                } else {
                    null
                }
            }

            challenge { _, _ ->
                call.respond(HttpStatusCode.Unauthorized, "Token is not valid or has expired")
            }
        }
    }
}

fun generateAccessToken(
    publicKey: RSAPublicKey,
    privateKeyPath: String,
    audience: String,
    issuer: String,
    username: String,
    isAdmin: Boolean? = false
): String {
    val privateKeyString = Files.readString(Path.of(privateKeyPath)) ?: throw IOException()
    val keySpec = PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyString))
    val privateKey = KeyFactory
        .getInstance("RSA")
        .generatePrivate(keySpec) as RSAPrivateKey

    return JWT.create()
        .withAudience(audience)
        .withIssuer(issuer)
        .withClaim("username", username)
        .withClaim("admin", isAdmin)
        .withExpiresAt(Instant.now().plusSeconds(45))
        .sign(Algorithm.RSA256(publicKey, privateKey))
}
