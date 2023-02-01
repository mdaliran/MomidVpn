package com.momid

import org.pcap4j.core.*
import org.pcap4j.packet.*
import org.pcap4j.packet.namednumber.EtherType
import org.pcap4j.packet.namednumber.TcpPort
import org.pcap4j.packet.namednumber.UdpPort
import org.pcap4j.util.MacAddress
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.*
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeoutException
import kotlin.collections.ArrayList

public class MomidVpnServer(private val port : Int) {

    private var sourceMacAddress: MacAddress? = null
    private var destinationMacAddress: MacAddress? = null
    private var clientSourceIp: String? = "192.168.1.1"
    private val requestedIps: List<String> = ArrayList()
    private val clientSourcePorts: MutableList<Int> = ArrayList()
    private var connections = ArrayList<Connection>()
    private var availablePorts = ArrayList<Int>()
    private var connectionId = 3000000
    private var connectionIdSynchronization : Any = Any()
    private var udpHandler: UdpHandler
    private val serverSocket: ServerSocket? = null
    private val socket: Socket? = null
    private val inputStream: InputStream? = null
    private val outputStream: OutputStream? = null
    private val executor: ExecutorService = Executors.newFixedThreadPool(10)
    private var handle: PcapHandle? = null






    companion object {

    }
    
    
    
    init {
        udpHandler = UdpHandler(port)
        synchronized(availablePorts) {
            for (i in 10000 until 30000) {



                availablePorts.add(i)
            }
        }
        connections.add(Connection(0))
        connections.add(Connection(3))
        connections.add(Connection(7))
        connections.add(Connection(8))
        connections.add(Connection(10))
        connections.add(Connection(37))
        connections.add(Connection(38))
    }
    
    fun start() {
        try {
            val networkInterfaces: List<PcapNetworkInterface> = Pcaps.findAllDevs()
            for (pcapNetworkInterface in networkInterfaces) {
                System.out.println(pcapNetworkInterface.getAddresses())
                System.out.println(pcapNetworkInterface.getLinkLayerAddresses())
                for (inetAddress in pcapNetworkInterface.getAddresses()) {
                    if (inetAddress.getAddress().getHostAddress().equals("146.70.121.53")) {
                        sourceMacAddress =
                            MacAddress.getByAddress(pcapNetworkInterface.linkLayerAddresses.get(0).address)
                        println("source mac address : " + sourceMacAddress)
                    }
                }
            }
            val pcapNetworkInterface: PcapNetworkInterface =
                Pcaps.getDevByAddress(InetAddress.getByName("146.70.121.53"))
            val snapLen = 65536
            val mode: PcapNetworkInterface.PromiscuousMode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS
            val timeout = 100
            handle = pcapNetworkInterface.openLive(snapLen, mode, timeout)
            ArpRequestCaptu.arpRequest("146.70.121.1") { result -> destinationMacAddress = result }
            udpHandler.startReceiving(object : UdpHandler.PacketListener {
                override fun onPacket(packet: ByteArray, socketAddress: SocketAddress) {
                    executor.execute {
                        println("aoi")
                        processContainingPacket(
                            packet.decrypt(),
                            socketAddress
                        )
                    }
                }
            })





            removeUnusedPorts()

            while (true) {
                try {
                    val packet: Packet = handle!!.nextPacketEx
                    executor.execute {
                        changePacket(packet.get(EthernetPacket::class.java), null, null, clientSourceIp, null)
                    }
                }

                catch (exception : Exception) {





                    exception.printStackTrace()
                }
            }
        } catch (e: PcapNativeException) {
            e.printStackTrace()
        } catch (e: NotOpenException) {
            e.printStackTrace()
        } catch (e: TimeoutException) {
            e.printStackTrace()
        } catch (e: IOException) {
            e.printStackTrace()
        }
        println("aoi")
    }

    private fun processContainingPacket(containingPacket: ByteArray, clientSocketAddress: SocketAddress) {
        if (destinationMacAddress == null) {
            println("destination source is null : cant process packet")
            return
        }

        val connection = DataPacket.from(containingPacket)
        val packet = connection.data
        val connectionId = connection.connectionId
        val ipV4Packet: IpV4Packet
        
        
        
        try {
            ipV4Packet = IpV4Packet.newPacket(packet, 0, packet.size)
            
            
            val requestAddress: String = ipV4Packet.header.dstAddr.hostAddress
            println("request address $requestAddress")
            clientSourceIp = ipV4Packet.header.srcAddr.hostAddress
        } catch (e: IllegalRawDataException) {
            e.printStackTrace()
            return
        }
        if (ipV4Packet.contains(UdpPacket::class.java)) {

            val udpPacket: UdpPacket = ipV4Packet.get(UdpPacket::class.java)
            val port: Int = udpPacket.header.srcPort.valueAsInt()
            val assignedPort = clientPortToPublicPort(port, connectionId) ?: return
            assignedPort.first.clientSocketAddress = clientSocketAddress
            println("udp port $port")

            try {
                val ipPacket: IpV4Packet.Builder =
                    IpV4Packet.Builder(ipV4Packet).srcAddr(InetAddress.getByName("146.70.121.53") as Inet4Address).payloadBuilder(
                        UdpPacket.Builder(udpPacket).srcAddr(InetAddress.getByName("146.70.121.53"))
                            .dstAddr(ipV4Packet.header.dstAddr).srcPort(UdpPort.getInstance(assignedPort.second.toShort())).correctChecksumAtBuild(true)
                            .correctLengthAtBuild(true)
                    ).correctChecksumAtBuild(true).correctLengthAtBuild(true)
                //            IpV4Packet packet = IpV4Packet.newPacket(ipPacket.build().getRawData(), 0, ipPacket.build().length());
                val ethernetPacket: EthernetPacket =
                    EthernetPacket.Builder().srcAddr(sourceMacAddress).dstAddr(destinationMacAddress).payloadBuilder(ipPacket)
                        .type(EtherType.IPV4).paddingAtBuild(true).build()
//                println("${SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(Date())} packet from client going to server $ethernetPacket")
                handle?.sendPacket(ethernetPacket)
            } catch (e: PcapNativeException) {
                e.printStackTrace()
            } catch (e: NotOpenException) {
                e.printStackTrace()
            } catch (e: UnknownHostException) {
                e.printStackTrace()
            }
        }
        if (ipV4Packet.contains(TcpPacket::class.java)) {

            val tcpPacket: TcpPacket = ipV4Packet.get(TcpPacket::class.java)
            val port: Int = tcpPacket.header.srcPort.valueAsInt()
            val assignedPort = clientPortToPublicPort(port, connectionId) ?: return

            assignedPort.first.clientSocketAddress = clientSocketAddress
            println("tcp port $port")

            try {
                val ipPacket: IpV4Packet.Builder =
                    IpV4Packet.Builder(ipV4Packet).srcAddr(InetAddress.getByName("146.70.121.53") as Inet4Address).payloadBuilder(
                        TcpPacket.Builder(tcpPacket).srcAddr(InetAddress.getByName("146.70.121.53"))
                            .dstAddr(ipV4Packet.header.dstAddr).srcPort(TcpPort.getInstance(assignedPort.second.toShort())).correctChecksumAtBuild(true)
                            .correctLengthAtBuild(true)
                    ).correctChecksumAtBuild(true).correctLengthAtBuild(true)
                //                IpV4Packet packet = IpV4Packet.newPacket(ipPacket.build().getRawData(), 0, ipPacket.build().length());
                val ethernetPacket: EthernetPacket =
                    EthernetPacket.Builder().srcAddr(sourceMacAddress).dstAddr(destinationMacAddress).payloadBuilder(ipPacket)
                        .type(EtherType.IPV4).paddingAtBuild(true).build()
//                println(
//                    """
//
//
//
//    ${SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(Date())}packet from client going to server
//    $ethernetPacket
//    """.trimIndent()
//                )
                handle?.sendPacket(ethernetPacket)
            } catch (e: PcapNativeException) {
                e.printStackTrace()
            } catch (e: NotOpenException) {
                e.printStackTrace()
            } catch (e: UnknownHostException) {
                e.printStackTrace()
            }
        }
    }
    
    
    private fun changePacket(
        ethernetPacket: EthernetPacket,
        sourceIp: String?,
        sourceMac: String?,
        destinationIp: String?,
        destinationMac: String?
    ): IpV4Packet? {
        val ipV4Packet: IpV4Packet = ethernetPacket.get(IpV4Packet::class.java) ?: return null
        var clientSocketAddress : SocketAddress? = null
        var packet : IpV4Packet? = null
        if (ethernetPacket.contains(UdpPacket::class.java)) {
            val udpPacket: UdpPacket = ipV4Packet.get(UdpPacket::class.java)

            val connection = publicPortToConnection(udpPacket.header.dstPort.valueAsInt()) ?: return null
            clientSocketAddress = connection.first.clientSocketAddress
//            System.out.println("udp port " + udpPacket.header.srcPort)
            try {
                packet = IpV4Packet.Builder(ipV4Packet).dstAddr(InetAddress.getByName(destinationIp) as Inet4Address).payloadBuilder(
                    UdpPacket.Builder(udpPacket).dstAddr(InetAddress.getByName(destinationIp))
                        .srcAddr(ipV4Packet.header.srcAddr).dstPort(UdpPort.getInstance(connection.second.toShort())).correctChecksumAtBuild(true)
                        .correctLengthAtBuild(true)
                ).correctChecksumAtBuild(true).correctLengthAtBuild(true).build()
            } catch (e: UnknownHostException) {
                e.printStackTrace()
            }
        }
        if (ethernetPacket.contains(TcpPacket::class.java)) {
            val tcpPacket: TcpPacket = ipV4Packet.get(TcpPacket::class.java)
            val connection = publicPortToConnection(tcpPacket.header.dstPort.valueAsInt()) ?: return null
            clientSocketAddress = connection.first.clientSocketAddress
//            System.out.println("port " + tcpPacket.header.srcPort)
            try { 
                
                packet = IpV4Packet.Builder(ipV4Packet).dstAddr(InetAddress.getByName(destinationIp) as Inet4Address).payloadBuilder(
                    TcpPacket.Builder(tcpPacket).dstAddr(InetAddress.getByName(destinationIp))
                        .srcAddr(ipV4Packet.header.srcAddr).dstPort(TcpPort.getInstance(connection.second.toShort())).correctChecksumAtBuild(true)
                        .correctLengthAtBuild(true)
                ).correctChecksumAtBuild(true).correctLengthAtBuild(true).build()
            } catch (e: UnknownHostException) {
                e.printStackTrace()
            }
        }
        if (clientSocketAddress != null && packet != null) {
            val encryptedPacket = packet.rawData.encrypt()
            udpHandler.sendPacket(encryptedPacket, 0, encryptedPacket.size, clientSocketAddress)
        }
        return ipV4Packet
    }



    public fun clientPortToPublicPort(clientPort: Int, connectionId : Int): Pair<Connection, Int>? {

        synchronized(connections) {
            connections.find { connection ->
                connection.connectionId == connectionId
            }?.let { connection ->
                connection.activeTime = System.currentTimeMillis()
                connection.portMapping.find {
                    it.port == clientPort
                }?.let {
                    it.activeTime = System.currentTimeMillis()
                    return Pair(connection, it.publicPort)
                } ?: kotlin.run {
                    usePublicPort()?.let {
                        connection.portMapping.add(PortMapping(clientPort, it))
                        return Pair(connection, it)
                    }
                }
            }
            return null
        }
    }




    public fun usePublicPort() : Int? {
        synchronized(availablePorts) {
            return availablePorts.removeLast()
        }
    }



    public fun publicPortToConnection(publicPort : Int) : Pair<Connection, Int>? {


        synchronized(connections) {
            var port: Int = 0

//        connections.find {
//            it.portMapping.find {
//                (it.publicPort == publicPort).let { boolean ->
//                    if (boolean) {
//                        port = it.port
//                    }
//                    boolean
//                }
//            } != null
//        }.let {
//            if (it != null && port != 0) {
//                return Pair(it, port)
//            }
//            else {
//                return null
//            }
//        }


            connections.forEach { connection ->
                connection.portMapping.forEach {
                    if (it.publicPort == publicPort) {
                        return Pair(connection, it.port)
                    }
                }
            }
            return null
        }
    }


    public fun removeUnusedPorts() {

        Thread {
            while (true) {
                synchronized(connections) {
                    synchronized(availablePorts) {
                        connections.removeIf { connection ->
                            connection.portMapping.removeIf { portMapping ->
                                (System.currentTimeMillis() - portMapping.activeTime > 30000).let {
                                    if (it) {
                                        availablePorts.add(portMapping.publicPort)
                                    }
                                    it
                                }
                            }
                            System.currentTimeMillis() - connection.activeTime > 30000 && connection.connectionId != 0 && connection.connectionId != 3 && connection.connectionId != 7 && connection.connectionId != 8 && connection.connectionId != 10 && connection.connectionId != 37 && connection.connectionId != 38
                        }
                    }
                }
                Thread.sleep(30000)
            }
        }.start()
    }


    public fun createConnection(): Int {



        var id : Int
        synchronized(connectionIdSynchronization) {

            id = connectionId
            connectionId += 1
            if (connectionId > 3000000) {
                connectionId = 0
            }
        }
        synchronized(connections) {
            connections.add(Connection(id))
        }
        return id
    }

    public fun removeConnection(connectionId: Int) {

        synchronized(connections) {
            connections.removeIf {
                it.connectionId == connectionId
            }
        }
    }
}

