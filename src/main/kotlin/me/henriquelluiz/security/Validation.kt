package me.henriquelluiz.security

fun isValidUsername(username: String): Boolean {
    val regex = Regex("[a-zA-Z0-9\\.\\+\\-_]{1,256}@[a-zA-Z0-9-]{1,64}\\.[a-zA-Z]{2,6}")
    return username.matches(regex)
}