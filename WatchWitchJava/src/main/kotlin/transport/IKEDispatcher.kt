package net.rec0de.android.watchwitch.transport

import net.rec0de.android.watchwitch.Log
import net.rec0de.android.watchwitch.Logger
import net.rec0de.android.watchwitch.ServiceReferences
import net.rec0de.android.watchwitch.alloy.AlloyController
import net.rec0de.android.watchwitch.bitmage.ByteOrder
import net.rec0de.android.watchwitch.bitmage.fromBytes
import net.rec0de.android.watchwitch.bitmage.hex
import net.rec0de.android.watchwitch.devices.Watch
import net.rec0de.android.watchwitch.ike.DeletePayload
import net.rec0de.android.watchwitch.ike.IKEMessage
import net.rec0de.android.watchwitch.ike.IKETransport
import net.rec0de.android.watchwitch.ike.IKEv2Session
import net.rec0de.android.watchwitch.ike.UDPTransport
import net.rec0de.android.watchwitch.transport.NrlpOverUdpService.Companion.TAG
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

object IKEDispatcher {
    private val ikeSessions = mutableMapOf<String, IKEv2Session>()

    fun dispatch(payload: ByteArray, transport: IKETransport) {
        val initiatorSPI = payload.sliceArray(0 until 8)
        val responderSPI = payload.sliceArray(8 until 16)
        val hexspi = initiatorSPI.hex()

        //Logger.logIKE("rcv IKE raw payload: ${payload.hex()}", 2)

        // existing session
        if(ikeSessions.containsKey(hexspi))
            ikeSessions[hexspi]!!.ingestPacket(payload)
        // fresh session
        else if(Long.fromBytes(responderSPI, ByteOrder.BIG) == 0L) {
            val session = IKEv2Session(transport, initiatorSPI)
            session.ingestPacket(payload)
            ikeSessions[hexspi] = session
        }
        // existing session that we have no memory of
        else {
            Logger.logIKE("Got orphaned IKE, sending delete", 0) // this does not seem to actually do anything
            // informational exchange
            val msg = IKEMessage(37, 0, initiatorSPI, responderSPI, isReply = false, isInitiator = false)
            msg.addPayload(DeletePayload())
            val delete = msg.assemble()
            transport.send(delete)
        }
    }

    fun readyForOOBInit(transport: IKETransport, oobkey: ByteArray) {
        // notify upstream controllers that we are about to perform initial pairing
        AlloyController.performInitialPairing()

        val session = IKEv2Session(transport, byteArrayOf(), weInitiate = true, oobkey = oobkey, weAreWatch = true)
        ikeSessions[session.initiatorSPI.hex()] = session
        session.sendSAInit(useX448 = Watch.useX448)
    }

    fun readyForInit(transport: IKETransport, forceWiFi: Boolean = false) {

        var effectiveTransport = transport
        val phoneAddr = InetAddress.getByName(ServiceReferences.phoneLocalIP)

        if(forceWiFi)
            effectiveTransport = UDPTransport(phoneAddr, ServiceReferences.phoneIkePort)

        Thread {

            if(!forceWiFi) {
                val sessionA = IKEv2Session(effectiveTransport, byteArrayOf(), weInitiate = true, weAreWatch = true, dataProtectionClass = 1)
                ikeSessions[sessionA.initiatorSPI.hex()] = sessionA
                sessionA.sendSAInit(useX448 = Watch.useX448)

                Thread.sleep(200)
            }

            val sessionC = IKEv2Session(effectiveTransport, byteArrayOf(), weInitiate = true, weAreWatch = true, dataProtectionClass = 3)
            sessionC.isWiFiSession = forceWiFi
            ikeSessions[sessionC.initiatorSPI.hex()] = sessionC
            sessionC.sendSAInit(useX448 = Watch.useX448)

            if(!forceWiFi) {
                Thread.sleep(200)

                val sessionD = IKEv2Session(effectiveTransport, byteArrayOf(), weInitiate = true, weAreWatch = true, dataProtectionClass = 4)
                ikeSessions[sessionD.initiatorSPI.hex()] = sessionD
                sessionD.sendSAInit(useX448 = Watch.useX448)
            }
        }.start()
    }
}