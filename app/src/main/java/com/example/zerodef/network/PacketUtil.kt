

package com.example.zerodef.network



import java.net.InetAddress

import java.net.Inet4Address

import java.net.Inet6Address

import java.nio.ByteBuffer



// --- PHASE 1: Data class to represent TCP options for clarity ---

data class TcpOptions(

    val mss: Int?,

    val windowScale: Int?,

    val sackPermitted: Boolean

)



// --- PHASE 1: Constants for TCP Options ---

private const val TCP_OPTION_KIND_EOL = 0

private const val TCP_OPTION_KIND_NOP = 1

private const val TCP_OPTION_KIND_MSS = 2

private const val TCP_OPTION_KIND_WINDOW_SCALE = 3

private const val TCP_OPTION_KIND_SACK_PERMITTED = 4



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



// --- PHASE 3: Rewritten to support both IPv4 and IPv6 pseudo headers ---

private fun getPseudoHeader(

    sourceAddress: InetAddress,

    destinationAddress: InetAddress,

    protocol: Byte,

    transportLength: Int

): ByteBuffer {

    val pseudoHeader: ByteBuffer

    if (sourceAddress is Inet4Address) {

        pseudoHeader = ByteBuffer.allocate(12)

        pseudoHeader.put(sourceAddress.address)

        pseudoHeader.put(destinationAddress.address)

        pseudoHeader.put(0) // Reserved

        pseudoHeader.put(protocol)

        pseudoHeader.putShort(transportLength.toShort())

    } else { // IPv6

        pseudoHeader = ByteBuffer.allocate(40)

        pseudoHeader.put(sourceAddress.address)

        pseudoHeader.put(destinationAddress.address)

        pseudoHeader.putInt(transportLength)

        pseudoHeader.put(ByteArray(3)) // Zeros

        pseudoHeader.put(protocol)

    }

    pseudoHeader.flip()

    return pseudoHeader

}



fun buildUdpPacket(key: ConnectionKey, payload: ByteBuffer, bufferPool: DirectBufferPool): ByteBuffer {

    val payloadSize = payload.remaining()

    val udpLength = UDP_HEADER_SIZE + payloadSize



    // --- PHASE 3: IPv6/IPv4 Agnostic ---

    val ipHeaderLength = if (key.sourceAddress is Inet4Address) IPV4_HEADER_SIZE else IPV6_HEADER_SIZE

    val totalLength = ipHeaderLength + udpLength

    val newPacket = bufferPool.borrowBuffer() // Use buffer pool

    newPacket.limit(totalLength)



    if (key.sourceAddress is Inet4Address) {

        newPacket.put((4 shl 4 or 5).toByte())

        newPacket.put(0.toByte())

        newPacket.putShort(totalLength.toShort())

        newPacket.putShort(0)

        newPacket.putShort(0)

        newPacket.put(64.toByte()) // TTL

        newPacket.put(Protocol.UDP.toByte)

        newPacket.putShort(0) // IP checksum placeholder

        newPacket.put(key.destAddress.address)

        newPacket.put(key.sourceAddress.address)

        val ipHeaderForChecksum = newPacket.duplicate()

        ipHeaderForChecksum.limit(IPV4_HEADER_SIZE)

        newPacket.putShort(10, calculateChecksum(ipHeaderForChecksum))

    } else {

        val versionTrafficFlow = (6 shl 28)

        newPacket.putInt(versionTrafficFlow)

        newPacket.putShort(udpLength.toShort())

        newPacket.put(Protocol.UDP.toByte)

        newPacket.put(64.toByte()) // Hop Limit

        newPacket.put(key.destAddress.address)

        newPacket.put(key.sourceAddress.address)

    }



    // UDP Header

    newPacket.putShort(key.destPort.toShort())

    newPacket.putShort(key.sourcePort.toShort())

    newPacket.putShort(udpLength.toShort())

    newPacket.putShort(0) // UDP checksum placeholder

    newPacket.put(payload)



    // UDP Checksum

    val udpForChecksum = newPacket.duplicate()

    udpForChecksum.position(ipHeaderLength)

    val pseudoHeader = getPseudoHeader(key.destAddress, key.sourceAddress, Protocol.UDP.toByte, udpLength)

    val checksumBuffer = ByteBuffer.allocate(pseudoHeader.remaining() + udpForChecksum.remaining())

    checksumBuffer.put(pseudoHeader)

    checksumBuffer.put(udpForChecksum)

    checksumBuffer.flip()

    newPacket.putShort(ipHeaderLength + 6, calculateChecksum(checksumBuffer))



    newPacket.flip()

    return newPacket

}



// --- REWRITTEN: buildTcpPacket now supports TCP Options, IPv6, and Buffer Pooling ---

fun buildTcpPacket(

    key: ConnectionKey,

    flags: Int,

    seq: Long,

    ack: Long,

    payload: ByteBuffer,

    tcpOptions: TcpOptions?,

    bufferPool: DirectBufferPool

): Pair<ByteBuffer, RetransmitPacket?> {



    var optionsLength = 0

    if (tcpOptions != null) {

        if (tcpOptions.mss != null) optionsLength += 4

        if (tcpOptions.windowScale != null) optionsLength += 3

        if (tcpOptions.sackPermitted) optionsLength += 2

        while (optionsLength % 4 != 0) optionsLength++ // Align to 4-byte boundary

    }

    val tcpHeaderLength = TCP_HEADER_SIZE + optionsLength

    val payloadSize = payload.remaining()



    val ipHeaderLength = if (key.sourceAddress is Inet4Address) IPV4_HEADER_SIZE else IPV6_HEADER_SIZE

    val totalLength = ipHeaderLength + tcpHeaderLength + payloadSize

    val newPacket = bufferPool.borrowBuffer()

    // --- FIX: Ensure limit is set correctly ---

    if (totalLength > newPacket.capacity()) {

        // This should not happen if bufferSize is adequate (65536)

        // But as a safeguard:

        bufferPool.returnBuffer(newPacket) // Return the small buffer

        return Pair(ByteBuffer.allocate(0), null) // Return an empty pair

    }

    newPacket.limit(totalLength)



    // --- PHASE 3: IPv4/IPv6 Header Building ---

    if (key.sourceAddress is Inet4Address) {

        newPacket.put((4 shl 4 or 5).toByte())

        newPacket.put(0.toByte())

        newPacket.putShort(totalLength.toShort())

        newPacket.putShort(0) // Identification

        newPacket.putShort(0) // Flags + Fragment Offset

        newPacket.put(64.toByte()) // TTL

        newPacket.put(Protocol.TCP.toByte)

        newPacket.putShort(0) // IP checksum placeholder

        newPacket.put(key.destAddress.address)

        newPacket.put(key.sourceAddress.address)

        val ipHeaderForChecksum = newPacket.duplicate()

        ipHeaderForChecksum.limit(IPV4_HEADER_SIZE)

        newPacket.putShort(10, calculateChecksum(ipHeaderForChecksum))

    } else {

        val versionTrafficFlow = (6 shl 28)

        newPacket.putInt(versionTrafficFlow)

        newPacket.putShort((tcpHeaderLength + payloadSize).toShort())

        newPacket.put(Protocol.TCP.toByte)

        newPacket.put(64.toByte()) // Hop Limit

        newPacket.put(key.destAddress.address)

        newPacket.put(key.sourceAddress.address)

    }



    // --- TCP Header ---

    newPacket.putShort(key.destPort.toShort())

    newPacket.putShort(key.sourcePort.toShort())

    newPacket.putInt(seq.toInt())

    newPacket.putInt(ack.toInt())

    newPacket.putShort(((tcpHeaderLength / 4) shl 12 or flags).toShort())

    newPacket.putShort(65535.toShort()) // Window size (will be scaled by WSOPT)

    newPacket.putShort(0) // TCP checksum placeholder

    newPacket.putShort(0) // Urgent pointer



    // --- PHASE 1 & 2: TCP Options Writing ---

    if (tcpOptions != null) {

        var optionsBytesWritten = 0

        if (tcpOptions.mss != null) {

            newPacket.put(TCP_OPTION_KIND_MSS.toByte())

            newPacket.put(4.toByte()); newPacket.putShort(tcpOptions.mss.toShort())

            optionsBytesWritten += 4

        }

        if (tcpOptions.windowScale != null) {

            newPacket.put(TCP_OPTION_KIND_WINDOW_SCALE.toByte())

            newPacket.put(3.toByte()); newPacket.put(tcpOptions.windowScale.toByte())

            optionsBytesWritten += 3

        }

        if (tcpOptions.sackPermitted) {

            newPacket.put(TCP_OPTION_KIND_SACK_PERMITTED.toByte())

            newPacket.put(2.toByte())

            optionsBytesWritten += 2

        }

        while (optionsBytesWritten < optionsLength) {

            newPacket.put(TCP_OPTION_KIND_NOP.toByte())

            optionsBytesWritten++

        }

    }



    if (payload.hasRemaining()) {

        newPacket.put(payload)

    }



    // --- Checksum ---

    val tcpForChecksum = newPacket.duplicate()

    tcpForChecksum.position(ipHeaderLength)

    val pseudoHeader = getPseudoHeader(key.destAddress, key.sourceAddress, Protocol.TCP.toByte, tcpHeaderLength + payloadSize)

    val checksumBuffer = ByteBuffer.allocate(pseudoHeader.remaining() + tcpForChecksum.remaining())

    checksumBuffer.put(pseudoHeader)

    checksumBuffer.put(tcpForChecksum)

    checksumBuffer.flip()

    newPacket.putShort(ipHeaderLength + 16, calculateChecksum(checksumBuffer))



    newPacket.flip()



    val consumedSequenceNumbers = if ((flags and (TCP_FLAG_SYN or TCP_FLAG_FIN)) != 0) {

        1

    } else {

        payloadSize

    }



    val retransmitPacket = if (consumedSequenceNumbers > 0 || payloadSize > 0) {

        // *** FINAL FIX: Store the PAYLOAD ONLY for data retransmissions ***

        val retransmitBuffer = ByteBuffer.allocate(payloadSize)

        retransmitBuffer.put(payload.duplicate())

        retransmitBuffer.flip()



        val dataLength = if (payloadSize > 0) payloadSize else consumedSequenceNumbers



        RetransmitPacket(seq, retransmitBuffer, System.currentTimeMillis(), dataLength,

            isSyn = (flags and TCP_FLAG_SYN) != 0, isFin = (flags and TCP_FLAG_FIN) != 0)

    } else null



    // --- FIX: Rewind original packet after creating copy ---

    newPacket.rewind()



    return Pair(newPacket, retransmitPacket)

}



val Protocol.toByte: Byte

    get() = when (this) {

        Protocol.TCP -> 6

        Protocol.UDP -> 17

        Protocol.ICMP -> 1

        Protocol.ICMPV6 -> 58

        Protocol.UNKNOWN -> -1

    }
