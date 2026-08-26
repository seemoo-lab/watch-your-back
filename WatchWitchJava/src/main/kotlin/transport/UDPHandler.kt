package net.rec0de.android.watchwitch.transport

import net.rec0de.android.watchwitch.Logger
import net.rec0de.android.watchwitch.ike.UDPTransport
import java.net.BindException
import java.net.DatagramPacket
import java.net.DatagramSocket

class UDPHandler(private val serverPort: Int) : Thread() {
    private val maxDatagramSize = 10000
    var socket: DatagramSocket? = null
    override fun run() {
        val lmessage = ByteArray(maxDatagramSize)
        val packet = DatagramPacket(lmessage, lmessage.size)
        try {
            socket = DatagramSocket(serverPort)

            while (true) {
                socket!!.receive(packet)
                val payload = packet.data.sliceArray(0 until packet.length)
                IKEDispatcher.dispatch(payload, UDPTransport(socket!!, packet.address, packet.port))
            }
        } catch (e: Throwable) {
            if(e is BindException) {
                Logger.setError("socket already in use")
            }
            e.printStackTrace()
        }
        finally {
            socket?.close()
        }
    }

    fun kill() {
        socket?.close()
    }
}