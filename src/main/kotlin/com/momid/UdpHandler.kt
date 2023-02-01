package com.momid

import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.SocketAddress
import java.net.SocketException

class UdpHandler(private val port: Int, val executor : (runnable : () -> Unit) -> Unit = { runnable -> runnable() }) {
    private val sendBuffer = ByteArray(65535)
    private val receiveBuffer = ByteArray(65535)
    private var clientAddressAndPort: SocketAddress? = null
    var socket: DatagramSocket

    init {
        try {
            socket = if (port != 0) {
                DatagramSocket(port)
            } else {
                DatagramSocket()
            }
        } catch (e: SocketException) {
            throw RuntimeException(e)
        }
    }

    constructor(executor : (runnable : () -> Unit) -> Unit = { runnable -> runnable() }) : this(0, executor) {

    }

    fun startReceiving(packetListener: PacketListener) {
        Thread {
            while (true) {
                val packet = DatagramPacket(receiveBuffer, receiveBuffer.size)
                try {
                    socket.receive(packet)
                } catch (e: IOException) {
                    e.printStackTrace()
                    println("cant receive")
                    continue
                }
                clientAddressAndPort = packet.socketAddress
                executor {
                    packetListener.onPacket(receiveBuffer.sliceArray(0 until packet.length), clientAddressAndPort!!)
                }
            }
        }.start()
    }

    fun sendPacket(packet: ByteArray, offset: Int, length: Int) {
        if (clientAddressAndPort == null) {
            println("client ip and port is unknown")
            return
        }
        val datagramPacket = DatagramPacket(packet, offset, length, clientAddressAndPort)
        try {
            socket.send(datagramPacket)
        } catch (e: IOException) {
            e.printStackTrace()
            println("cant send")
        }
    }

    fun sendPacket(packet: ByteArray, offset: Int, length: Int, clientSocketAddress: SocketAddress) {
        val datagramPacket = DatagramPacket(packet, offset, length, clientSocketAddress)
        try {
            socket.send(datagramPacket)
        } catch (e: IOException) {
            e.printStackTrace()
            println("cant send")
        }
    }

    interface PacketListener {
        fun onPacket(packet: ByteArray, socketAddress: SocketAddress)
    }
}
