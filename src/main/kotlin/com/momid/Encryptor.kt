package com.momid

import org.jasypt.util.binary.BasicBinaryEncryptor


object BinaryEncryptor {
    val binaryEncryptor = BasicBinaryEncryptor()
    init {
        binaryEncryptor.setPassword("aoi")
    }
}

public fun ByteArray.encrypt(): ByteArray {
    return BinaryEncryptor.binaryEncryptor.encrypt(this)
}


public fun ByteArray.decrypt(): ByteArray {
    return BinaryEncryptor.binaryEncryptor.decrypt(this)
}
