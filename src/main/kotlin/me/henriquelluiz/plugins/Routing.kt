package me.henriquelluiz.plugins

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.http.*
import io.ktor.server.http.content.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import me.henriquelluiz.data.*
import me.henriquelluiz.security.*
import org.koin.ktor.ext.inject
import java.io.File
import java.security.interfaces.RSAPublicKey
import java.time.Instant

fun Application.configureRouting() {
    val userRepository by inject<UserRepository>()
    val tokenRepository by inject<TokenRepository>()
    val properties by inject<JWTProperties>()

    routing {
        route("/users") {
            post("/save") {
                val user = call.receive<User>()

                if (!isValidUsername(user.username)) {
                    return@post call.respond(HttpStatusCode.BadRequest)
                }

                userRepository.addUser(user)
                call.respond(
                    HttpStatusCode.OK,
                    message = "User saved successfully."
                )
            }

            authenticate {
                get("/find-by-username{username}") {
                    val principal = call.principal<JWTPrincipal>()!!

                    if (!principal.payload.getClaim("admin").asBoolean()) {
                        return@get call.respond(HttpStatusCode.Unauthorized)
                    }

                    val username = call.request.queryParameters["username"]
                        ?: return@get call.respond(HttpStatusCode.BadRequest)

                    val user = userRepository.findByUsername(username)
                        ?: return@get call.respond(HttpStatusCode.NotFound)

                    call.respond(HttpStatusCode.OK, user)
                }

                get("/delete{username}") {
                    val principal = call.principal<JWTPrincipal>()!!

                    if (!principal.payload.getClaim("admin").asBoolean()) {
                        return@get call.respond(HttpStatusCode.Unauthorized)
                    }

                    val username = call.request.queryParameters["username"]
                        ?: return@get call.respond(HttpStatusCode.BadRequest)

                    val user = userRepository.findByUsername(username)
                        ?: return@get call.respond(HttpStatusCode.NotFound)

                    if (userRepository.deleteUser(user)) {
                        call.respond(HttpStatusCode.NoContent)
                    }

                    return@get call.respond(HttpStatusCode.InternalServerError)
                }
            }
        }

        route("/auth") {
            post("/login") {
                val user = call.receive<User>()

                if (!isValidUsername(user.username)) {
                    return@post call.respond(HttpStatusCode.BadRequest)
                }

                val storedUser = userRepository.findByUsername(user.username)
                    ?: return@post call.respond(HttpStatusCode.NotFound)

                if (!checkPassword(storedUser.password, user.password)) {
                    return@post call.respond(HttpStatusCode.Unauthorized, "Password is invalid")
                }

                val publicKey = properties.jwkProvider.get("1").publicKey as RSAPublicKey

                val accessToken = generateAccessToken(
                    publicKey,
                    properties.privateKeyPath,
                    properties.audience,
                    properties.issuer,
                    storedUser.username,
                    storedUser.isAdmin
                )

                val refreshToken = hashContentHMAC(storedUser.username)
                tokenRepository.addToken(Token(storedUser.username, refreshToken, storedUser.isAdmin!!))

                call.respond(
                    HttpStatusCode.OK,
                    hashMapOf(
                        "accessToken" to accessToken,
                        "refreshToken" to refreshToken
                    )
                )
            }

            post("/refresh") {
                val refreshToken = call.receiveText()
                val storedToken = tokenRepository.getToken(refreshToken)
                    ?: return@post call.respond(HttpStatusCode.NotFound)

                if (!storedToken.isValidToken()) {
                    tokenRepository.removeToken(storedToken)
                    return@post call.respond(
                        HttpStatusCode.Forbidden,
                        "Token is invalid. Generate a new token."
                    )
                }

                val publicKey = properties.jwkProvider.get("1").publicKey as RSAPublicKey
                val accessToken = generateAccessToken(
                    publicKey,
                    properties.privateKeyPath,
                    properties.audience,
                    properties.issuer,
                    storedToken.username,
                    storedToken.isAdmin
                )
                call.respond(
                    HttpStatusCode.OK,
                    hashMapOf(
                        "accessToken" to accessToken,
                        "expiresAt" to Instant.now().plusSeconds(45).toHttpDateString()
                    )
                )
            }
        }

        staticFiles(
            remotePath = "/.well-known",
            dir = File("certs"),
            index = "jwks.json"
        )
    }
}
