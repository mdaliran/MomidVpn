package com.momid

import java.nio.ByteBuffer

class DataPacket(val connectionId : Int, val data : ByteArray) {

    companion object {


        public fun from(byteArray: ByteArray): DataPacket {
            val connectionId = byteArray.sliceArray(0 until 4).toInt()
            val data = byteArray.sliceArray(4 until byteArray.size)
            return DataPacket(connectionId, data)
        }
    }

    public fun toByteArray(): ByteArray {
        return connectionId.toBytes() + data
    }
}



fun Int.toBytes(): ByteArray =
    ByteBuffer.allocate(Int.SIZE_BYTES).putInt(this).array()

fun ByteArray.toInt(): Int =
    ByteBuffer.wrap(this).int




