package me.henriquelluiz.data

import java.time.LocalDateTime

data class Token(
    val username: String,
    val token: String,
    val isAdmin: Boolean,
    val expiresAt: LocalDateTime? = LocalDateTime.now().plusHours(1)
)

fun Token.isValidToken(): Boolean = this.expiresAt!!.isAfter(LocalDateTime.now())