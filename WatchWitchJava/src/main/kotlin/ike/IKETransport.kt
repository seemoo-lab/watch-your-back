package net.rec0de.android.watchwitch.ike

import net.rec0de.android.watchwitch.Log
import net.rec0de.android.watchwitch.Logger
import net.rec0de.android.watchwitch.ServiceReferences
import net.rec0de.android.watchwitch.WatchState
import net.rec0de.android.watchwitch.bitmage.hex
import net.rec0de.android.watchwitch.nwsc.NWSCManager
import net.rec0de.android.watchwitch.transport.ESPDispatcher
import net.rec0de.android.watchwitch.transport.IKEDispatcher
import net.rec0de.android.watchwitch.transport.NrlpOverUdpService
import net.rec0de.android.watchwitch.transport.TunnelBuilder
import net.rec0de.android.watchwitch.transport.VpnConnection
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet6Address
import java.net.InetAddress

// IKE usually arrives over UDP from the watch in the WiFi case
// working towards supporting Bluetooth connections also, we also accept IKE over generic transports
// like NRLP over UDP, in which case we also have to handle ESP decryption in-house, which changes
// the tunnel setup logic as we no longer outsource to kernel ip xfrm

interface IKETransport {
    fun send(msg: ByteArray)

    fun setupTunnel(
        spiI: ByteArray,
        spiR: ByteArray,
        keyI: ByteArray,
        saltI: ByteArray,
        keyR: ByteArray,
        saltR: ByteArray,
        isClassC: Boolean
    )
}

class UDPTransport(private val socket: DatagramSocket, private val host: InetAddress, private val port: Int): IKETransport {

    private val TAG = "UDPTransport"

    constructor(host: InetAddress, port: Int) : this(DatagramSocket(), host, port) {
        Thread {
            val lmessage = ByteArray(10000)
            val packet = DatagramPacket(lmessage, lmessage.size)
            try {
                while (true) {
                    socket.receive(packet)
                    val payload = packet.data.sliceArray(0 until packet.length)
                    Log.d(TAG, "received IKE via WiFi")
                    IKEDispatcher.dispatch(payload, UDPTransport(socket, packet.address, packet.port))
                }
            } catch (e: Throwable) {
                e.printStackTrace()
            } finally {
                socket.close()
            }
        }.start()
    }

    override fun send(msg: ByteArray) {
        val packet = DatagramPacket(msg, msg.size, host, port)
        Log.d("UDPTransport", "sending IKE via WiFi to $host:$port")
        socket.send(packet)
    }

    override fun setupTunnel(
        spiI: ByteArray,
        spiR: ByteArray,
        keyI: ByteArray,
        saltI: ByteArray,
        keyR: ByteArray,
        saltR: ByteArray,
        isClassC: Boolean
    ) {
        // ip xfrm expects key and salt material in a single bytestring
        val ki = keyI + saltI
        val kr = keyR + saltR

        val thread = TunnelBuilder(host.hostAddress!!, spiI, spiR, ki, kr, isClassC)
        thread.start()
    }
}

class NrlpOverUdpTransport(private val host: InetAddress, private val port: Int, private val handlerService: NrlpOverUdpService): IKETransport {

    override fun send(msg: ByteArray) {
        Log.d("NrlpOverUDPTransport", "sending IKE via BT")
        //Logger.logIKE("snd IKE raw payload: ${msg.hex()}", 2)
        // type IKE, non-urgent
        val payload = byteArrayOf(0x04, 0x00) + msg
        val packet = DatagramPacket(payload, payload.size, host, port)
        handlerService.rateLimitedSend(packet)
    }

    override fun setupTunnel(
        spiI: ByteArray,
        spiR: ByteArray,
        keyI: ByteArray,
        saltI: ByteArray,
        keyR: ByteArray,
        saltR: ByteArray,
        isClassC: Boolean
    ) {
        Log.d("NRLPTransport", "setup tunnel")
        val secrets = ESPDispatcher.EspSecrets(spiI, spiR, keyI, keyR, saltI, saltR, isClassC, weInitiate = true)
        ServiceReferences.espDispatcher!!.registerEspSpi(secrets)

        ServiceReferences.callbackWhenAddressesAvailable {
            WatchState.setPairingStage("first ESP tunnel established")
            WatchState.incrementProgress()

            val connection = VpnConnection(
                setOf(
                    Inet6Address.getByAddress(ServiceReferences.watchsideAddressC) as Inet6Address,
                    Inet6Address.getByAddress(ServiceReferences.watchsideAddressD) as Inet6Address
                ),
                setOf(
                    Inet6Address.getByAddress(ServiceReferences.phonesideAddressC) as Inet6Address,
                    Inet6Address.getByAddress(ServiceReferences.phonesideAddressD) as Inet6Address
                ),
                setOf("net.rec0de.android.watchwitch")
            )

            ServiceReferences.vpnConnection = connection
            Thread(connection).start()

            // start the shoes mockup so we have some data going over the tunnel hopefully
            //NWSCManager.tryRequestIdscc()
        }
    }
}