package me.henriquelluiz.data

import me.henriquelluiz.security.hashPassword

object UserRepository {
    private val users = mutableSetOf<User>()

    fun addUser(user: User) {
        user.password = hashPassword(user.password)
        users.add(user)
    }

    fun findByUsername(username: String): User? = users.find { it.username == username }
    fun deleteUser(user: User) = users.remove(user)
}