package me.henriquelluiz.security

import com.auth0.jwk.JwkProvider

data class JWTProperties(
    val realm: String,
    val issuer: String,
    val audience: String,
    val privateKeyPath: String,
    val jwkProvider: JwkProvider
)
