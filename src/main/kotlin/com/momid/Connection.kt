package com.momid

import java.net.SocketAddress

class Connection(var connectionId : Int, var activeTime : Long = System.currentTimeMillis(), var portMapping: ArrayList<PortMapping> = ArrayList(), var clientSocketAddress: SocketAddress? = null)

class PortMapping(var port : Int, var publicPort : Int, var activeTime: Long = System.currentTimeMillis())


