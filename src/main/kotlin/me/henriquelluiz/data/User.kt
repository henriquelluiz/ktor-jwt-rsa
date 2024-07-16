package me.henriquelluiz.data

import kotlinx.serialization.Serializable

@Serializable
data class User(
    val username: String,
    var password: String,
    val isAdmin: Boolean? = false
)

data class UserSession(val username: String, val count: Int)

