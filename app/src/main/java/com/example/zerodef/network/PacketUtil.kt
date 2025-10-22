package com.example.zerodef.network

import java.net.InetAddress
import java.nio.ByteBuffer

private fun calculateChecksum(buffer: ByteBuffer): Short {
    var sum = 0
    val tempBuffer = buffer.duplicate()
    tempBuffer.position(0)

    while (tempBuffer.remaining() > 1) {
        sum += tempBuffer.short.toInt() and 0xFFFF
    }

    if (tempBuffer.hasRemaining()) {
        sum += (tempBuffer.get().toInt() and 0xFF) shl 8
    }

    while (sum ushr 16 > 0) {
        sum = (sum and 0xFFFF) + (sum ushr 16)
    }
    return (sum xor 0xFFFF).toShort()
}

private fun getPseudoHeader(
    sourceAddress: InetAddress,
    destinationAddress: InetAddress,
    protocol: Byte,
    transportLength: Int
): ByteBuffer {
    val pseudoHeader = ByteBuffer.allocate(12)
    pseudoHeader.put(sourceAddress.address)
    pseudoHeader.put(destinationAddress.address)
    pseudoHeader.put(0) // Reserved
    pseudoHeader.put(protocol)
    pseudoHeader.putShort(transportLength.toShort())
    pseudoHeader.flip()
    return pseudoHeader
}

fun buildUdpPacket(connection: Connection, payload: ByteBuffer): ByteBuffer {
    val payloadSize = payload.remaining()
    val udpLength = UDP_HEADER_SIZE + payloadSize
    val totalLength = IPV4_HEADER_SIZE + udpLength
    val newPacket = ByteBuffer.allocate(totalLength)

    // IP Header
    newPacket.put((4 shl 4 or 5).toByte())
    newPacket.put(0.toByte()) // Type of Service
    newPacket.putShort(totalLength.toShort())
    newPacket.putShort(0) // Identification
    newPacket.putShort(0) // Flags + Fragment Offset
    newPacket.put(64.toByte()) // TTL
    newPacket.put(Protocol.UDP.toByte)
    newPacket.putShort(0) // Checksum placeholder
    newPacket.put(connection.destAddress.address)
    newPacket.put(connection.sourceAddress.address)

    val ipHeaderForChecksum = newPacket.duplicate()
    ipHeaderForChecksum.limit(IPV4_HEADER_SIZE)
    newPacket.putShort(10, calculateChecksum(ipHeaderForChecksum))

    // UDP Header
    newPacket.putShort(connection.destPort.toShort())
    newPacket.putShort(connection.sourcePort.toShort())
    newPacket.putShort(udpLength.toShort())
    newPacket.putShort(0) // Checksum placeholder

    newPacket.put(payload)

    val udpForChecksum = newPacket.duplicate()
    udpForChecksum.position(IPV4_HEADER_SIZE)
    val pseudoHeader = getPseudoHeader(connection.destAddress, connection.sourceAddress, Protocol.UDP.toByte, udpLength)
    val checksumBuffer = ByteBuffer.allocate(pseudoHeader.remaining() + udpForChecksum.remaining())
    checksumBuffer.put(pseudoHeader)
    checksumBuffer.put(udpForChecksum)
    checksumBuffer.flip()
    newPacket.putShort(IPV4_HEADER_SIZE + 6, calculateChecksum(checksumBuffer))

    newPacket.flip()
    return newPacket
}

fun buildTcpPacket(
    connection: Connection,
    flags: Int,
    seq: Long,
    ack: Long,
    payload: ByteBuffer
): ByteBuffer {
    val payloadSize = payload.remaining()
    val tcpLength = TCP_HEADER_SIZE + payloadSize
    val totalLength = IPV4_HEADER_SIZE + tcpLength
    val newPacket = ByteBuffer.allocate(totalLength)

    // IP Header
    newPacket.put((4 shl 4 or 5).toByte())
    newPacket.put(0.toByte()) // Type of Service
    newPacket.putShort(totalLength.toShort())
    newPacket.putShort(0) // Identification
    newPacket.putShort(0) // Flags + Fragment Offset
    newPacket.put(64.toByte()) // TTL
    newPacket.put(Protocol.TCP.toByte)
    newPacket.putShort(0) // Checksum placeholder
    newPacket.put(connection.destAddress.address)
    newPacket.put(connection.sourceAddress.address)

    val ipHeaderForChecksum = newPacket.duplicate()
    ipHeaderForChecksum.limit(IPV4_HEADER_SIZE)
    newPacket.putShort(10, calculateChecksum(ipHeaderForChecksum))

    // TCP Header
    newPacket.putShort(connection.destPort.toShort())
    newPacket.putShort(connection.sourcePort.toShort())
    newPacket.putInt(seq.toInt())
    newPacket.putInt(ack.toInt())
    newPacket.putShort(((TCP_HEADER_SIZE / 4) shl 12 or flags).toShort())
    newPacket.putShort(65535.toShort()) // Window size
    newPacket.putShort(0) // Checksum placeholder
    newPacket.putShort(0) // Urgent pointer

    newPacket.put(payload)

    val tcpForChecksum = newPacket.duplicate()
    tcpForChecksum.position(IPV4_HEADER_SIZE)
    val pseudoHeader = getPseudoHeader(connection.destAddress, connection.sourceAddress, Protocol.TCP.toByte, tcpLength)
    val checksumBuffer = ByteBuffer.allocate(pseudoHeader.remaining() + tcpForChecksum.remaining())
    checksumBuffer.put(pseudoHeader)
    checksumBuffer.put(tcpForChecksum)
    checksumBuffer.flip()
    newPacket.putShort(IPV4_HEADER_SIZE + 16, calculateChecksum(checksumBuffer))

    newPacket.flip()
    return newPacket
}

val Protocol.toByte: Byte
    get() = when (this) {
        Protocol.TCP -> 6
        Protocol.UDP -> 17
        Protocol.UNKNOWN -> -1
    }