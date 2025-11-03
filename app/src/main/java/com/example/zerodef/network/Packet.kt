
package com.example.zerodef.network



import java.net.InetAddress

import java.net.Inet4Address

import java.net.Inet6Address

import java.nio.ByteBuffer

import java.io.IOException



enum class Protocol {

    TCP, UDP, ICMP, ICMPV6, UNKNOWN

}



// --- PHASE 3: Abstracted IPHeader for IPv4/IPv6 ---

interface IPHeader {

    val version: Int

    val protocol: Protocol

    val sourceAddress: InetAddress

    val destinationAddress: InetAddress

    val headerLength: Int

    val payloadLength: Int

}



interface TransportHeader {

    val sourcePort: Int

    val destinationPort: Int

    val headerLength: Int

}



const val IPV4_HEADER_SIZE = 20

const val IPV6_HEADER_SIZE = 40

const val TCP_HEADER_SIZE = 20

const val UDP_HEADER_SIZE = 8



const val TCP_FLAG_SYN = 0x02

const val TCP_FLAG_ACK = 0x10

const val TCP_FLAG_PSH = 0x08

const val TCP_FLAG_FIN = 0x01

const val TCP_FLAG_RST = 0x04



data class IPV4Header(

    override val version: Int,

    val ihl: Int,

    val typeOfService: Int,

    val totalLength: Int,

    val identification: Int,

    val flags: Int,

    val fragmentOffset: Int,

    val ttl: Int,

    override val protocol: Protocol,

    val headerChecksum: Int,

    override val sourceAddress: InetAddress,

    override val destinationAddress: InetAddress

) : IPHeader {

    override val headerLength: Int = ihl * 4

    override val payloadLength: Int = totalLength - headerLength

    companion object {

        fun fromByteBuffer(buffer: ByteBuffer): IPV4Header {

            buffer.mark()

            val versionAndIhl = buffer.get().toInt() and 0xFF

            val version = versionAndIhl shr 4

            val ihl = versionAndIhl and 0x0F

            if (ihl < 5) throw IOException("Invalid IPv4 header length: $ihl")



            val typeOfService = buffer.get().toInt() and 0xFF

            val totalLength = buffer.short.toInt() and 0xFFFF

            val identification = buffer.short.toInt() and 0xFFFF

            val flagsAndFragmentOffset = buffer.short.toInt() and 0xFFFF

            val flags = flagsAndFragmentOffset shr 13

            val fragmentOffset = flagsAndFragmentOffset and 0x1FFF

            val ttl = buffer.get().toInt() and 0xFF

            val protocolNum = buffer.get().toInt() and 0xFF

            val protocol = intToProtocol(protocolNum)

            val headerChecksum = buffer.short.toInt() and 0xFFFF

            val sourceIp = ByteArray(4)

            buffer.get(sourceIp)

            val destIp = ByteArray(4)

            buffer.get(destIp)



            // Skip options

            if(ihl * 4 > IPV4_HEADER_SIZE) {

                buffer.position(buffer.position() + (ihl * 4 - IPV4_HEADER_SIZE))

            }

            buffer.reset()



            return IPV4Header(version, ihl, typeOfService, totalLength, identification, flags, fragmentOffset, ttl, protocol, headerChecksum, InetAddress.getByAddress(sourceIp), InetAddress.getByAddress(destIp))

        }

    }

}



// --- PHASE 3: New IPv6 Header Class ---

data class IPV6Header(

    override val version: Int,

    val trafficClass: Int,

    val flowLabel: Int,

    override val payloadLength: Int,

    override val protocol: Protocol,

    val hopLimit: Int,

    override val sourceAddress: InetAddress,

    override val destinationAddress: InetAddress

) : IPHeader {

    override val headerLength: Int = IPV6_HEADER_SIZE

    companion object {

        fun fromByteBuffer(buffer: ByteBuffer): IPV6Header {

            buffer.mark()

            val versionTrafficFlow = buffer.int

            val version = (versionTrafficFlow shr 28) and 0xF

            val trafficClass = (versionTrafficFlow shr 20) and 0xFF

            val flowLabel = versionTrafficFlow and 0xFFFFF



            val payloadLength = buffer.short.toInt() and 0xFFFF

            val nextHeader = buffer.get().toInt() and 0xFF

            val protocol = intToProtocol(nextHeader)

            val hopLimit = buffer.get().toInt() and 0xFF



            val sourceIp = ByteArray(16)

            buffer.get(sourceIp)

            val destIp = ByteArray(16)

            buffer.get(destIp)



            buffer.reset()

            return IPV6Header(version, trafficClass, flowLabel, payloadLength, protocol, hopLimit, InetAddress.getByAddress(sourceIp), InetAddress.getByAddress(destIp))

        }

    }

}



fun intToProtocol(protocolNum: Int): Protocol {

    return when (protocolNum) {

        6 -> Protocol.TCP

        17 -> Protocol.UDP

        1 -> Protocol.ICMP

        58 -> Protocol.ICMPV6

        else -> Protocol.UNKNOWN

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

    val urgentPointer: Int,

    // --- PHASE 1: Store parsed options ---

    val options: TcpOptions? = null

) : TransportHeader {

    override val headerLength: Int = dataOffset * 4



    val isSYN: Boolean get() = (flags and TCP_FLAG_SYN) != 0

    val isACK: Boolean get() = (flags and TCP_FLAG_ACK) != 0

    val isFIN: Boolean get() = (flags and TCP_FLAG_FIN) != 0

    val isRST: Boolean get() = (flags and TCP_FLAG_RST) != 0

    val isPSH: Boolean get() = (flags and TCP_FLAG_PSH) != 0



    companion object {

        fun fromByteBuffer(buffer: ByteBuffer): TCPHeader {

            buffer.mark()

            val sourcePort = buffer.short.toInt() and 0xFFFF

            val destinationPort = buffer.short.toInt() and 0xFFFF

            val sequenceNumber = buffer.int.toLong() and 0xFFFFFFFFL

            val acknowledgmentNumber = buffer.int.toLong() and 0xFFFFFFFFL

            val dataOffsetAndFlags = buffer.short.toInt() and 0xFFFF

            val dataOffset = (dataOffsetAndFlags shr 12) and 0x0F

            val headerLength = dataOffset * 4

            val flags = dataOffsetAndFlags and 0x1FF

            val windowSize = buffer.short.toInt() and 0xFFFF

            val checksum = buffer.short.toInt() and 0xFFFF

            val urgentPointer = buffer.short.toInt() and 0xFFFF



            var mss: Int? = null

            var windowScale: Int? = null

            var sackPermitted = false



            if (headerLength > TCP_HEADER_SIZE) {

                val optionsBytes = ByteArray(headerLength - TCP_HEADER_SIZE)

                if (buffer.remaining() >= optionsBytes.size) {

                    buffer.get(optionsBytes)

                    var i = 0

                    while (i < optionsBytes.size) {

                        val kind = optionsBytes[i].toInt() and 0xFF

                        if (kind == 0) break // EOL

                        if (kind == 1) { // NOP

                            i++

                            continue

                        }

                        if (i + 1 >= optionsBytes.size) break

                        val len = optionsBytes[i + 1].toInt() and 0xFF

                        if (len < 2 || i + len > optionsBytes.size) break



                        when (kind) {

                            2 -> if (len == 4) mss = ((optionsBytes[i + 2].toInt() and 0xFF) shl 8) or (optionsBytes[i + 3].toInt() and 0xFF)

                            3 -> if (len == 3) windowScale = optionsBytes[i + 2].toInt() and 0xFF

                            4 -> if (len == 2) sackPermitted = true

                        }

                        i += len

                    }

                }

            }



            buffer.reset()

            return TCPHeader(sourcePort, destinationPort, sequenceNumber, acknowledgmentNumber, dataOffset, flags, windowSize, checksum, urgentPointer, TcpOptions(mss, windowScale, sackPermitted))

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

    val ipHeader: IPHeader

    val transportHeader: TransportHeader?

    val payload: ByteBuffer



    init {

        try {

            val originalPosition = backingBuffer.position()

            val originalLimit = backingBuffer.limit()



            backingBuffer.position(0)

            val version = (backingBuffer.get(0).toInt() and 0xF0) shr 4

            ipHeader = when (version) {

                4 -> IPV4Header.fromByteBuffer(backingBuffer)

                6 -> IPV6Header.fromByteBuffer(backingBuffer)

                else -> throw IOException("Unknown IP version: $version")

            }



            backingBuffer.position(ipHeader.headerLength)

            transportHeader = when (ipHeader.protocol) {

                Protocol.TCP -> TCPHeader.fromByteBuffer(backingBuffer)

                Protocol.UDP -> UDPHeader.fromByteBuffer(backingBuffer)

                else -> null

            }



            val payloadStart = ipHeader.headerLength + (transportHeader?.headerLength ?: 0)

            var payloadLength = ipHeader.payloadLength

            if(transportHeader != null) {

                payloadLength -= transportHeader.headerLength

            }



            if (payloadLength > 0) {

                backingBuffer.position(payloadStart)

                if (payloadStart + payloadLength > originalLimit) {

                    // Truncated packet, just take what's left

                    payloadLength = originalLimit - payloadStart

                }

                if(payloadLength < 0) payloadLength = 0



                backingBuffer.limit(payloadStart + payloadLength)

                payload = backingBuffer.slice()

            } else {

                payload = ByteBuffer.allocate(0)

            }



            backingBuffer.position(originalPosition)

            backingBuffer.limit(originalLimit)



        } catch (e: Exception) {

            throw IllegalArgumentException("Failed to parse packet: ${e.message}", e)

        }

    }

}
