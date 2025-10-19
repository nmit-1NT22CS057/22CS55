package com.example.zerodef.network

import java.net.InetAddress
import java.nio.ByteBuffer

const val IPV4_HEADER_SIZE = 20
const val TCP_HEADER_SIZE = 20
const val UDP_HEADER_SIZE = 8

const val TCP_FLAG_SYN = 0x02
const val TCP_FLAG_ACK = 0x10
const val TCP_FLAG_PSH = 0x08
const val TCP_FLAG_FIN = 0x01
const val TCP_FLAG_RST = 0x04

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

private fun getPseudoHeader(ipHeader: IPV4Header, transportLength: Int): ByteBuffer {
    val pseudoHeader = ByteBuffer.allocate(12)
    pseudoHeader.put(ipHeader.sourceAddress.address)
    pseudoHeader.put(ipHeader.destinationAddress.address)
    pseudoHeader.put(0) // Reserved
    pseudoHeader.put(ipHeader.protocol.toByte)
    pseudoHeader.putShort(transportLength.toShort())
    pseudoHeader.flip()
    return pseudoHeader
}

fun buildUdpPacket(
    originalIpHeader: IPV4Header,
    originalUdpHeader: UDPHeader,
    payload: ByteBuffer
): ByteBuffer {
    val payloadSize = payload.remaining()
    val udpLength = UDP_HEADER_SIZE + payloadSize
    val totalLength = IPV4_HEADER_SIZE + udpLength
    val newPacket = ByteBuffer.allocate(totalLength)

    val newIpHeader = originalIpHeader.copy(
        sourceAddress = originalIpHeader.destinationAddress,
        destinationAddress = originalIpHeader.sourceAddress,
        totalLength = totalLength
    )

    // Build IP Header
    newPacket.put((4 shl 4 or 5).toByte()) // Version + IHL
    newPacket.put(newIpHeader.typeOfService.toByte())
    newPacket.putShort(newIpHeader.totalLength.toShort())
    newPacket.putShort(0) // Identification
    newPacket.putShort(0) // Flags + Fragment Offset
    newPacket.put(64.toByte()) // TTL
    newPacket.put(17) // Protocol (UDP)
    newPacket.putShort(0) // Checksum placeholder
    newPacket.put(newIpHeader.sourceAddress.address)
    newPacket.put(newIpHeader.destinationAddress.address)

    // Calculate IP checksum
    val ipHeaderForChecksum = newPacket.duplicate()
    ipHeaderForChecksum.position(0)
    ipHeaderForChecksum.limit(IPV4_HEADER_SIZE)
    val ipChecksum = calculateChecksum(ipHeaderForChecksum)
    newPacket.putShort(10, ipChecksum)

    // Build UDP Header
    newPacket.putShort(originalUdpHeader.destinationPort.toShort())
    newPacket.putShort(originalUdpHeader.sourcePort.toShort())
    newPacket.putShort(udpLength.toShort())
    newPacket.putShort(0) // UDP Checksum placeholder

    // Add payload
    val payloadDuplicate = payload.duplicate()
    while (payloadDuplicate.hasRemaining()) {
        newPacket.put(payloadDuplicate.get())
    }

    // Calculate UDP checksum
    val udpForChecksum = newPacket.duplicate()
    udpForChecksum.position(IPV4_HEADER_SIZE)
    udpForChecksum.limit(totalLength)

    val pseudoHeader = getPseudoHeader(newIpHeader, udpLength)
    val checksumBuffer = ByteBuffer.allocate(pseudoHeader.remaining() + udpForChecksum.remaining())
    checksumBuffer.put(pseudoHeader)
    checksumBuffer.put(udpForChecksum)
    checksumBuffer.flip()

    val udpChecksum = calculateChecksum(checksumBuffer)
    newPacket.putShort(IPV4_HEADER_SIZE + 6, udpChecksum)

    newPacket.flip()
    return newPacket
}

fun buildTcpPacket(
    originalIpHeader: IPV4Header,
    originalTcpHeader: TCPHeader,
    payload: ByteBuffer,
    flags: Int,
    ackNumber: Long,
    seqNumber: Long
): ByteBuffer {
    val payloadSize = payload.remaining()
    val tcpLength = TCP_HEADER_SIZE + payloadSize
    val totalLength = IPV4_HEADER_SIZE + tcpLength
    val newPacket = ByteBuffer.allocate(totalLength)

    val newIpHeader = originalIpHeader.copy(
        sourceAddress = originalIpHeader.destinationAddress,
        destinationAddress = originalIpHeader.sourceAddress,
        totalLength = totalLength
    )

    // Build IP Header
    newPacket.put((4 shl 4 or 5).toByte())
    newPacket.put(newIpHeader.typeOfService.toByte())
    newPacket.putShort(newIpHeader.totalLength.toShort())
    newPacket.putShort(0) // Identification
    newPacket.putShort(0) // Flags + Fragment Offset
    newPacket.put(64.toByte()) // TTL
    newPacket.put(6) // Protocol (TCP)
    newPacket.putShort(0) // Checksum placeholder
    newPacket.put(newIpHeader.sourceAddress.address)
    newPacket.put(newIpHeader.destinationAddress.address)

    // Calculate IP checksum
    val ipHeaderForChecksum = newPacket.duplicate()
    ipHeaderForChecksum.position(0)
    ipHeaderForChecksum.limit(IPV4_HEADER_SIZE)
    val ipChecksum = calculateChecksum(ipHeaderForChecksum)
    newPacket.putShort(10, ipChecksum)

    // Build TCP Header
    newPacket.putShort(originalTcpHeader.destinationPort.toShort())
    newPacket.putShort(originalTcpHeader.sourcePort.toShort())
    newPacket.putInt(seqNumber.toInt())
    newPacket.putInt(ackNumber.toInt())
    newPacket.putShort(((TCP_HEADER_SIZE / 4) shl 12 or flags).toShort())
    newPacket.putShort(65535.toShort()) // Window size
    newPacket.putShort(0) // Checksum placeholder
    newPacket.putShort(0) // Urgent pointer

    // Add payload
    val payloadDuplicate = payload.duplicate()
    while (payloadDuplicate.hasRemaining()) {
        newPacket.put(payloadDuplicate.get())
    }

    // Calculate TCP checksum
    val tcpForChecksum = newPacket.duplicate()
    tcpForChecksum.position(IPV4_HEADER_SIZE)
    tcpForChecksum.limit(totalLength)

    val pseudoHeader = getPseudoHeader(newIpHeader, tcpLength)
    val checksumBuffer = ByteBuffer.allocate(pseudoHeader.remaining() + tcpForChecksum.remaining())
    checksumBuffer.put(pseudoHeader)
    checksumBuffer.put(tcpForChecksum)
    checksumBuffer.flip()

    val tcpChecksum = calculateChecksum(checksumBuffer)
    newPacket.putShort(IPV4_HEADER_SIZE + 16, tcpChecksum)

    newPacket.flip()
    return newPacket
}

val Protocol.toByte: Byte
    get() = when (this) {
        Protocol.TCP -> 6
        Protocol.UDP -> 17
        Protocol.UNKNOWN -> -1
    }
