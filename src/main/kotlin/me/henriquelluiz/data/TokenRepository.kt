package me.henriquelluiz.data

object TokenRepository {
    private val tokens = mutableSetOf<Token>()

    fun addToken(token: Token) {
        tokens.add(token)
    }

    fun removeToken(token: Token) {
        tokens.remove(token)
    }

    fun getToken(token: String): Token? {
        return tokens.firstOrNull { it.token == token }
    }
}
