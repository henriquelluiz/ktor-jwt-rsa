package me.henriquelluiz

import io.ktor.server.application.*
import io.ktor.server.netty.*
import me.henriquelluiz.plugins.*

fun main(args: Array<String>) = EngineMain.main(args)

fun Application.module() {
    configureDI()
    configureJWT()
    configureHTTP()
    configureSerialization()
    configureRouting()
}
