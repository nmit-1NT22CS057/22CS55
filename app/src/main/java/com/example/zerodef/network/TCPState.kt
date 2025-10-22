package com.example.zerodef.network

enum class TCPConnectionState {
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    CLOSE_WAIT,
    LAST_ACK
}

data class TCPState(
    var lastActivity: Long = System.currentTimeMillis(),
    var clientSeq: Long = 0,
    var serverSeq: Long = 0,
    var clientAck: Long = 0,
    var state: TCPConnectionState = TCPConnectionState.SYN_SENT
)