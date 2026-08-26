package net.rec0de.android.watchwitch.transport

import net.rec0de.android.watchwitch.Log
import net.rec0de.android.watchwitch.LongTermStorage
import net.rec0de.android.watchwitch.ServiceReferences
import net.rec0de.android.watchwitch.WatchState
import net.rec0de.android.watchwitch.alloy.AlloyController
import net.rec0de.android.watchwitch.bitmage.fromIndex
import net.rec0de.android.watchwitch.bitmage.hex
import net.rec0de.android.watchwitch.bitmage.untilIndex
import net.rec0de.android.watchwitch.ike.IKEv2Session
import net.rec0de.android.watchwitch.ike.NrlpOverUdpTransport
import net.rec0de.android.watchwitch.nwsc.NWSCManager
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress


class NrlpOverUdpService: EspTransport {

    companion object {
        const val SERVER_PORT = 0x5757
        val SERVER_HOST
            get() = ServiceReferences.bumbleHost
        const val MAX_DATAGRAM_SIZE = 10000
        const val TAG = "NRLPoverUDP"
    }



    private var socket: DatagramSocket = DatagramSocket()
    private val sendQueue = mutableListOf<DatagramPacket>()

    private var oobkey: ByteArray = byteArrayOf()

    private lateinit var transport: NrlpOverUdpTransport

    private val runnable = Runnable {
        sendBumbleHello()

        val message = ByteArray(MAX_DATAGRAM_SIZE)
        val packet = DatagramPacket(message, message.size)

        // set NWSC handler to emulate WATCH role
        //Log.d(TAG, "telling NWSC manager we are WATCH now")
        NWSCManager.weAreDevice = LongTermStorage.CONTEXT_WATCH

        //Log.d(TAG, "telling Alloy controller we are WATCH now")
        AlloyController.takeWatchRole()
        AlloyController.simulateNeverInitiate()

        while (true) {
            socket.receive(packet)

            val type = packet.data[0].toInt()
            val urgent = packet.data[1].toInt() == 1
            val data = packet.data.sliceArray(2 until packet.length)

            //Log.d(TAG, "received $type ${data.hex()}")

            when(type) {
                0x03 -> receive6LoWPAN(data)
                0x04 -> IKEDispatcher.dispatch(data, transport)
                0x32 -> {
                    WatchState.setPairingStage("ready for OOB IKEv2 init")
                    WatchState.incrementProgress()
                    ServiceReferences.startTime = java.util.Date().time
                    //Log.d(TAG, "NRLP ready for OOB IKEv2 init")
                    IKEDispatcher.readyForOOBInit(transport, oobkey)
                }
                0x33 -> {
                    Log.d(TAG, "received bluetooth OOB key: ${data.hex()}")
                    oobkey = data
                }
                0x34 -> {
                    //Log.d(TAG, "received bluetooth PIN: ${data.decodeToString()}")
                    WatchState.setBtPin(data.decodeToString().padStart(6, '0'))
                }
                0x35 -> {
                    Log.d(TAG, "NRLP ready for paired IKEv2 init")
                    IKEDispatcher.readyForInit(transport)
                }
                0x36 -> {
                    Log.d(TAG, "NRLP disconnected")
                    NWSCManager.reset()
                    WatchState.resetConnectionState()
                }
                0x64, 0x65, 0x68, 0x69 -> {
                    ServiceReferences.espDispatcher!!.receiveESP(data, null, null)
                }
                else -> Log.d(TAG, "Unhandled message type $type: ${data.hex()}")
            }
        }
    }

    private val sendThread = Runnable {
        while (true) {
            Thread.sleep(100)
            if(sendQueue.isNotEmpty()) {
                val packet = sendQueue.removeAt(0)
                socket.send(packet)
                val chunks = packet.length / 200
                Thread.sleep(chunks * 10L)
            }
        }
    }

    fun sendBumbleHello() {
        val helloData = "nrlp-hello".encodeToByteArray()
        val helloPacket = DatagramPacket(helloData, helloData.size, InetAddress.getByName(SERVER_HOST), SERVER_PORT)
        socket.send(helloPacket)
        Log.d(TAG, "sent nrlp hello")

        val preludeData = byteArrayOf(0x34) + IKEv2Session.prelude
        val sendPacket = DatagramPacket(preludeData, preludeData.size, InetAddress.getByName(SERVER_HOST), SERVER_PORT)
        socket.send(sendPacket)
        Log.d(TAG, "sent prelude ${preludeData.hex()}")

        transport = NrlpOverUdpTransport(sendPacket.address, sendPacket.port, this)
    }



    // rudimentary support for https://datatracker.ietf.org/doc/html/rfc6282#section-3
    private fun receive6LoWPAN(msg: ByteArray) {
        val iphc = msg.untilIndex(2)
        val first = iphc[0].toInt()
        val second = iphc[1].toInt()
        var inlinePointer = 2

        val pattern = (first shr 5) and 0x07
        check(pattern == 0b011) { "expected IPHC pattern 0b011 but got 0b${pattern.toString(2)}" }

        val tf = (first shr 3) and 0x03
        when(tf) {
            0b00 -> inlinePointer += 4
            0b01 -> inlinePointer += 3
            0b10 -> inlinePointer += 1
            0b11 -> {}
        }

        val nh = (first shr 2) and 0x01
        check(nh == 0) { "we don't support compressed next headers" }
        val nextHeader: Int = msg[inlinePointer].toInt()
        inlinePointer += 1

        val hlim = first and 0x03
        if(hlim == 0)
            inlinePointer += 1

        /*when(hlim) {
            0b00 -> inlinePointer += 1
            0b01 -> hopLimit = 1
            0b10 -> hopLimit = 64
            0b11 -> hopLimit = 255
        }*/

        val cid = (second and 0x80) != 0
        check(!cid) { "we don't support context identifier expressions" }

        val sac = (second and 0x40) != 0
        val sam = (second shr 4) and 0x03
        val sourceAddr: ByteArray?
        if(sac) {
            when(sam) {
                0b00 -> {
                    sourceAddr = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
                }
                0b01 -> {
                    inlinePointer += 8
                    throw Exception("Unsupported stateful lowpan compression: 0b01 - 64bit")
                }
                0b10 -> {
                    // we use 16 bits of data with a context-derived address
                    // this is usually the IPv6 address negotiated in IKEv2, with the 16 bits specifying
                    // the data protection class (0x000c or 0x000d)
                    // given we keep track of the ESP context, this information seems redundant
                    // we'll treat this as a fully elided address and fill in DPC info in receiveESP
                    inlinePointer += 2
                    sourceAddr = null
                }
                else -> {
                    // source address is fully elided.
                    // usually this would mean using the lower-level bluetooth MAC to derive the source IP
                    // but in this case it seems apple uses the negotiated IPv6 addresses from the IKEv2 handshake
                    // we use these by default, and will therefore return null here
                    sourceAddr = null
                }
            }
        }
        else {
            when(sam) {
                0b00 -> {
                    sourceAddr = msg.sliceArray(inlinePointer until inlinePointer+16)
                    inlinePointer += 16
                }
                0b01 -> {
                    sourceAddr = byteArrayOf(0xfe.toByte(), 0x80.toByte(), 0, 0, 0, 0, 0, 0) + msg.sliceArray(inlinePointer until inlinePointer+8)
                    inlinePointer += 8
                }
                0b10 -> {
                    sourceAddr = byteArrayOf(0xfe.toByte(), 0x80.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff.toByte(), 0xfe.toByte(), 0) + msg.sliceArray(inlinePointer until inlinePointer+2)
                    inlinePointer += 2
                }
                else -> {
                    // source address is fully elided.
                    // usually this would mean using the lower-level bluetooth MAC to derive the source IP
                    // but in this case it seems apple uses the negotiated IPv6 addresses from the IKEv2 handshake
                    // we use these by default, and will therefore return null here
                    sourceAddr = null
                }
            }
        }

        val m = (second and 0x08) != 0
        //check(!m) { "we don't support multicast destination addresses" }

        val dac = (second and 0x04) != 0


        val dam = second and 0x03
        val destAddr: ByteArray?

        if(dac) {
            check(!m) { "we don't support stateful destination address compression with multicast" }
            when(dam) {
                0b00-> throw Exception("reserved DAM 0b00 with DAC")
                0b01 -> {
                    inlinePointer += 8
                    throw Exception("Unsupported stateful lowpan compression: 0b01 - 64bit")
                }
                0b10 -> {
                    // matches SAC/SAM case. technically 16 bit but we pretend the address is fully elided
                    // (and reconstruct based on ESP SPI in receiveESP)
                    inlinePointer += 2
                    destAddr = null
                }
                else -> {
                    // source address is fully elided.
                    destAddr = null
                }
            }
        }
        else {
            when(dam) {
                0b00 -> {
                    destAddr = msg.sliceArray(inlinePointer until inlinePointer+16)
                    inlinePointer += 16
                }
                0b01 -> {
                    if(m) {
                        destAddr = byteArrayOf(0xff.toByte(), msg[inlinePointer], 0, 0, 0, 0, 0, 0, 0, 0, 0) + msg.sliceArray(inlinePointer + 1 until inlinePointer + 6)
                        inlinePointer += 6
                    }
                    else {
                        destAddr = byteArrayOf(0xfe.toByte(), 0x80.toByte(), 0, 0, 0, 0, 0, 0) + msg.sliceArray(inlinePointer until inlinePointer + 8)
                        inlinePointer += 8
                    }
                }
                0b10 -> {
                    if(m) {
                        destAddr = byteArrayOf(0xff.toByte(), msg[inlinePointer], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) + msg.sliceArray(inlinePointer + 1 until inlinePointer + 4)
                        inlinePointer += 4
                    }
                    else {
                        destAddr = byteArrayOf(0xfe.toByte(), 0x80.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff.toByte(), 0xfe.toByte(), 0) + msg.sliceArray(inlinePointer until inlinePointer+2)
                        inlinePointer += 2
                    }
                }
                else -> {
                    if(m) {
                        destAddr = byteArrayOf(0xff.toByte(), 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, msg[inlinePointer])
                        inlinePointer += 1
                    }
                    else {
                        // source address is fully elided.
                        // usually this would mean using the lower-level bluetooth MAC to derive the source IP
                        // but in this case it seems apple uses the negotiated IPv6 addresses from the IKEv2 handshake
                        // we use these by default, and will therefore return null here
                        destAddr = null
                    }
                }
            }
        }


        val payload = msg.fromIndex(inlinePointer)

        if(nextHeader == 0x32)
            ServiceReferences.espDispatcher!!.receiveESP(payload, sourceAddr, destAddr)
        else
            Log.d(TAG, "Unhandled 6LoWPAN next header $nextHeader: ${payload.hex()}")
    }

    // VERY stripped down to our case
    private fun wrap6LoWPAN(msg: ByteArray, nextHeader: Byte, isUrgent: Boolean, isClassC: Boolean): DatagramPacket {
        if(isClassC) {
            // traffic class & next header inline, 64 hops, stateful address compression, 16 bits each, class c
            val iphc = byteArrayOf(0x72, 0x66, 0xc0.toByte(), nextHeader, 0x00, 0x0c, 0x00, 0x0c)
            val urgentByte = if(isUrgent) 1.toByte() else 0.toByte()
            // send with NRLP type 3
            return DatagramPacket(byteArrayOf(0x03, urgentByte) + iphc + msg, msg.size+8+2, InetAddress.getByName(SERVER_HOST), SERVER_PORT)
        }
        else {
            // traffic class & next header inline, 64 hops, addresses fully elided
            val iphc = byteArrayOf(0x72, 0x33, 0xc0.toByte(), nextHeader)
            val urgentByte = if(isUrgent) 1.toByte() else 0.toByte()
            // send with NRLP type 3
            return DatagramPacket(byteArrayOf(0x03, urgentByte) + iphc + msg, msg.size+4+2, InetAddress.getByName(SERVER_HOST), SERVER_PORT)
        }
    }

    override fun sendEsp(packet: ByteArray, isClassC: Boolean) {
        //Log.d(TAG, "Encrypted ESP: ${espPacket.hex()}")
        val lowpan = false
        val isUrgent = false

        val nrlpType = (if(isClassC) 0x68 else 0x64).toByte() // ESP NRLP type with ECT1
        val urgentByte = if(isUrgent) 1.toByte() else 0.toByte()
        val packet = if(lowpan)
                wrap6LoWPAN(packet, 0x32, isUrgent, isClassC)
            else
                DatagramPacket(byteArrayOf(nrlpType, urgentByte) + packet, packet.size+2, InetAddress.getByName(SERVER_HOST), SERVER_PORT)
        rateLimitedSend(packet)
    }

    fun sendPrelude(prelude: ByteArray) {
        Log.d(TAG, "Sending new prelude: ${prelude.hex()}")
        val packet = DatagramPacket(byteArrayOf(0x34) + prelude, prelude.size+1, InetAddress.getByName(SERVER_HOST), SERVER_PORT)
        rateLimitedSend(packet)
    }

    fun start() {
        ServiceReferences.nrlpOverUdpService = this
        Thread(runnable, "nrlp-service").start()
        Thread(sendThread, "nrlp-service-send").start()
    }

    @Synchronized
    fun rateLimitedSend(packet: DatagramPacket) {
        //sendQueue.add(packet)
        socket.send(packet)
    }
}