package com.example.zerodef.network

import java.net.InetAddress
import java.nio.ByteBuffer

enum class Protocol {
    TCP, UDP, UNKNOWN
}

interface TransportHeader {
    val sourcePort: Int
    val destinationPort: Int
    val headerLength: Int
}

data class IPV4Header(
    val version: Int,
    val ihl: Int,
    val typeOfService: Int,
    val totalLength: Int,
    val identification: Int,
    val flags: Int,
    val fragmentOffset: Int,
    val ttl: Int,
    val protocol: Protocol,
    val headerChecksum: Int,
    val sourceAddress: InetAddress,
    val destinationAddress: InetAddress
) {
    val headerLength: Int = ihl * 4
    companion object {
        fun fromByteBuffer(buffer: ByteBuffer): IPV4Header {
            if (buffer.remaining() < IPV4_HEADER_SIZE) {
                throw IllegalArgumentException("Buffer too small for IP header")
            }

            buffer.mark()

            val versionAndIhl = buffer.get().toInt() and 0xFF
            val version = versionAndIhl shr 4
            val ihl = versionAndIhl and 0x0F
            val typeOfService = buffer.get().toInt() and 0xFF
            val totalLength = buffer.short.toInt() and 0xFFFF
            val identification = buffer.short.toInt() and 0xFFFF
            val flagsAndFragmentOffset = buffer.short.toInt() and 0xFFFF
            val flags = flagsAndFragmentOffset shr 13
            val fragmentOffset = flagsAndFragmentOffset and 0x1FFF
            val ttl = buffer.get().toInt() and 0xFF
            val protocolNum = buffer.get().toInt() and 0xFF
            val protocol = when (protocolNum) {
                6 -> Protocol.TCP
                17 -> Protocol.UDP
                else -> Protocol.UNKNOWN
            }
            val headerChecksum = buffer.short.toInt() and 0xFFFF

            val sourceIp = ByteArray(4)
            buffer.get(sourceIp)
            val destIp = ByteArray(4)
            buffer.get(destIp)

            buffer.reset()

            return IPV4Header(
                version,
                ihl,
                typeOfService,
                totalLength,
                identification,
                flags,
                fragmentOffset,
                ttl,
                protocol,
                headerChecksum,
                InetAddress.getByAddress(sourceIp),
                InetAddress.getByAddress(destIp)
            )
        }
    }
}

data class TCPHeader(
    override val sourcePort: Int,
    override val destinationPort: Int,
    val sequenceNumber: Long,
    val acknowledgmentNumber: Long,
    val dataOffset: Int,
    val flags: Int,
    val windowSize: Int,
    val checksum: Int,
    val urgentPointer: Int
) : TransportHeader {
    override val headerLength: Int = dataOffset * 4

    companion object {
        fun fromByteBuffer(buffer: ByteBuffer): TCPHeader {
            if (buffer.remaining() < TCP_HEADER_SIZE) {
                throw IllegalArgumentException("Buffer too small for TCP header")
            }

            buffer.mark()

            val sourcePort = buffer.short.toInt() and 0xFFFF
            val destinationPort = buffer.short.toInt() and 0xFFFF
            val sequenceNumber = buffer.int.toLong() and 0xFFFFFFFFL
            val acknowledgmentNumber = buffer.int.toLong() and 0xFFFFFFFFL
            val dataOffsetAndFlags = buffer.short.toInt() and 0xFFFF
            val dataOffset = (dataOffsetAndFlags shr 12) and 0x0F
            val flags = dataOffsetAndFlags and 0x1FF
            val windowSize = buffer.short.toInt() and 0xFFFF
            val checksum = buffer.short.toInt() and 0xFFFF
            val urgentPointer = buffer.short.toInt() and 0xFFFF

            buffer.reset()

            return TCPHeader(
                sourcePort,
                destinationPort,
                sequenceNumber,
                acknowledgmentNumber,
                dataOffset,
                flags,
                windowSize,
                checksum,
                urgentPointer
            )
        }
    }
}

data class UDPHeader(
    override val sourcePort: Int,
    override val destinationPort: Int,
    val length: Int,
    val checksum: Int
) : TransportHeader {
    override val headerLength: Int = UDP_HEADER_SIZE
    companion object {
        fun fromByteBuffer(buffer: ByteBuffer): UDPHeader {
            if (buffer.remaining() < UDP_HEADER_SIZE) {
                throw IllegalArgumentException("Buffer too small for UDP header")
            }

            buffer.mark()

            val sourcePort = buffer.short.toInt() and 0xFFFF
            val destinationPort = buffer.short.toInt() and 0xFFFF
            val length = buffer.short.toInt() and 0xFFFF
            val checksum = buffer.short.toInt() and 0xFFFF

            buffer.reset()

            return UDPHeader(sourcePort, destinationPort, length, checksum)
        }
    }
}

class Packet(val backingBuffer: ByteBuffer) {
    val ipHeader: IPV4Header
    val transportHeader: TransportHeader?
    val payload: ByteBuffer

    init {
        try {
            backingBuffer.position(0)
            ipHeader = IPV4Header.fromByteBuffer(backingBuffer)

            transportHeader = when (ipHeader.protocol) {
                Protocol.TCP -> {
                    backingBuffer.position(ipHeader.headerLength)
                    TCPHeader.fromByteBuffer(backingBuffer)
                }
                Protocol.UDP -> {
                    backingBuffer.position(ipHeader.headerLength)
                    UDPHeader.fromByteBuffer(backingBuffer)
                }
                else -> null
            }

            // Extract payload
            val payloadStart = ipHeader.headerLength + (transportHeader?.headerLength ?: 0)
            val payloadLength = ipHeader.totalLength - payloadStart

            payload = if (payloadLength > 0 && payloadLength <= backingBuffer.remaining()) {
                val payloadArray = ByteArray(payloadLength)
                backingBuffer.position(payloadStart)
                backingBuffer.get(payloadArray)
                ByteBuffer.wrap(payloadArray)
            } else {
                ByteBuffer.allocate(0)
            }

            backingBuffer.position(0)
        } catch (e: Exception) {
            throw IllegalArgumentException("Failed to parse packet: ${e.message}")
        }
    }
}