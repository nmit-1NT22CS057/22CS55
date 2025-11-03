
package com.example.zerodef.network



import android.util.Log

import java.nio.ByteBuffer

import java.util.LinkedList

import java.util.SortedMap

import java.util.TreeMap

import kotlin.math.max

import kotlin.math.min



enum class TCPConnectionState {

    SYN_SENT,

    SYN_RECEIVED,

    ESTABLISHED,

    FIN_WAIT_1,

    FIN_WAIT_2,

    CLOSE_WAIT,

    CLOSING,

    LAST_ACK,

    TIME_WAIT

}



data class RetransmitPacket(

    val sequenceNumber: Long,

    val buffer: ByteBuffer, // This will store the PAYLOAD only

    var sentTime: Long,

    val dataLength: Int, // For data packets, this is payload size. For SYN/FIN, it's 1.

    var retransmitCount: Int = 0,

    val isSyn: Boolean = false,

    val isFin: Boolean = false

)



// --- FINAL FIX: This class ONLY manages the Client <-> VPN connection ---

data class TCPState(

    var lastActivity: Long = System.currentTimeMillis(),



    // Sequence numbers for the Client <-> VPN connection

    var clientSeq: Long = 0, // The sequence number we expect from the client

    var clientAck: Long = 0, // The sequence number we have ACKed to the client

    var serverSeq: Long = 0, // The sequence number we are sending to the client

    var serverAck: Long = 0, // The last sequence number the client has ACKed



    var state: TCPConnectionState = TCPConnectionState.SYN_SENT,



    // Congestion Control for Client <-> VPN connection

    var clientWindowSize: Int = 65535,

    var mss: Int = 1400, // Clamped MSS

    var congestionWindow: Double = 2.0 * mss,

    var ssthresh: Int = 65535,

    var bytesInFlight: Int = 0,

    var duplicateAckCount: Int = 0,



    // RTT Estimation for Client <-> VPN (approximated)

    var retransmissionTimeout: Long = 1000L,



    // Retransmission queue for packets sent TO CLIENT

    val unacknowledgedClientPackets: SortedMap<Long, RetransmitPacket> = TreeMap(),



    // Buffer for data from server, to be sent TO CLIENT

    val receivedDataBuffer: SortedMap<Long, ByteBuffer> = TreeMap(),



    // Buffer for data from client, to be sent TO SERVER

    val pendingDataToRemote: LinkedList<ByteBuffer> = LinkedList(),



    var isKeepAlivePacketSent: Boolean = false

) {

    companion object {

        private const val MIN_RTO = 200L

        private const val MAX_RTO = 60000L

    }



    // Can we send more data to the CLIENT?

    fun canSendToClient(): Boolean {

        val effectiveWindow = min(congestionWindow, clientWindowSize.toDouble())

        return bytesInFlight < effectiveWindow

    }



    fun onPacketSentToClient(packet: RetransmitPacket) {

        synchronized(unacknowledgedClientPackets) {

            val seqConsumed = if (packet.isSyn || packet.isFin) 1 else packet.dataLength

            if (seqConsumed > 0) {

                unacknowledgedClientPackets[packet.sequenceNumber] = packet

                bytesInFlight += seqConsumed

            }

        }

    }



    // ACK received FROM CLIENT (acknowledging our download)

    fun onClientAckReceived(ackNumber: Long) {

        synchronized(unacknowledgedClientPackets) {

            if (ackNumber < clientAck) {

                return@synchronized

            }



            if (ackNumber == clientAck) {

                if (unacknowledgedClientPackets.isNotEmpty()) {

                    duplicateAckCount++

                    if (duplicateAckCount == 3) {

                        onPacketLoss(isFastRecovery = true)

                    }

                }

                return@synchronized

            }



            duplicateAckCount = 0

            val newAck = ackNumber > clientAck

            clientAck = ackNumber



            val iterator = unacknowledgedClientPackets.entries.iterator()

            var bytesAcked = 0



            while (iterator.hasNext()) {

                val entry = iterator.next()

                val packet = entry.value

                val packetEndSeq = packet.sequenceNumber + (if (packet.isSyn || packet.isFin) 1 else packet.dataLength)



                if (packetEndSeq <= ackNumber) {

                    bytesAcked += if (packet.isSyn || packet.isFin) 1 else packet.dataLength

                    iterator.remove()

                } else {

                    break

                }

            }



            if (bytesAcked > 0) {

                bytesInFlight = max(0, bytesInFlight - bytesAcked)



                if (congestionWindow < ssthresh) {

                    congestionWindow += bytesAcked

                } else {

                    congestionWindow += (mss * mss) / congestionWindow

                }

            } else if (newAck) {

                if (congestionWindow >= ssthresh) {

                    congestionWindow += (mss * mss) / congestionWindow

                }

            }

        }

    }



    fun onPacketLoss(isFastRecovery: Boolean) {

        synchronized(unacknowledgedClientPackets) {

            ssthresh = max((bytesInFlight / 2.0), 2.0 * mss).toInt()

            if (isFastRecovery) {

                congestionWindow = ssthresh.toDouble()

                Log.d("TCPState-Client", "Fast Recovery. New ssthresh=$ssthresh, cwnd=$congestionWindow")

            } else {

                congestionWindow = 1.0 * mss

                Log.w("TCPState-Client", "Timeout. New ssthresh=$ssthresh, cwnd reset to $congestionWindow")

            }

            duplicateAckCount = 0

            // We use a fixed RTO for the client side, so no exponential backoff needed

        }

    }



    fun getPacketsForClientRetransmission(now: Long, isFastRetransmit: Boolean): List<RetransmitPacket> {

        synchronized(unacknowledgedClientPackets) {

            if (isFastRetransmit) {

                return unacknowledgedClientPackets.values.firstOrNull()?.let { listOf(it) } ?: emptyList()

            }

            // Use a fixed RTO for client side

            return unacknowledgedClientPackets.values.filter { now - it.sentTime > retransmissionTimeout }

        }

    }

}
