package me.henriquelluiz.plugins

import com.auth0.jwk.JwkProviderBuilder
import io.ktor.server.application.*
import me.henriquelluiz.data.TokenRepository
import me.henriquelluiz.data.UserRepository
import me.henriquelluiz.security.JWTProperties
import org.koin.dsl.module
import org.koin.ktor.plugin.Koin
import java.util.concurrent.TimeUnit

fun Application.configureDI() {
    install(Koin) {
        modules(
            module {
                single {
                    val issuerProperty = environment.config.property("jwt.issuer").getString()
                    JWTProperties(
                        realm = environment.config.property("jwt.realm").getString(),
                        issuer = issuerProperty,
                        audience = environment.config.property("jwt.audience").getString(),
                        privateKeyPath = environment.config.property("jwt.privateKey").getString(),
                        jwkProvider = JwkProviderBuilder(issuerProperty)
                            .cached(10, 24, TimeUnit.HOURS)
                            .rateLimited(10, 1, TimeUnit.MINUTES)
                            .build()
                    )
                }
            },

            module {
                single { UserRepository }
                single { TokenRepository }
            }
        )
    }
}