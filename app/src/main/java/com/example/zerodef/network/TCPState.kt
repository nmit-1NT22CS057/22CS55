package com.example.zerodef.network

class TCPState {
    var clientSeq: Long = 0
    var clientAck: Long = 0
    var serverSeq: Long = 0
    var serverAck: Long = 0
}
