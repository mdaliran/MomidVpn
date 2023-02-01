package com.momid

import com.momid.plugins.configureRouting
import com.momid.plugins.configureSerialization
import io.ktor.server.application.*

fun main() {

    Captu(55553).start()




//    embeddedServer(Netty, port = 8080, host = "0.0.0.0", module = Application::module)
//        .start(wait = true)
}

fun Application.module() {
    configureSerialization()
    configureRouting()
}

