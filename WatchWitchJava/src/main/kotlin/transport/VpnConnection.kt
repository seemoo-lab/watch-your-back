package net.rec0de.android.watchwitch.transport


import io.github.isotes.net.tun.io.TunDevice
import net.rec0de.android.watchwitch.Log
import net.rec0de.android.watchwitch.Logger
import net.rec0de.android.watchwitch.PacketLogger
import net.rec0de.android.watchwitch.ServiceReferences
import net.rec0de.android.watchwitch.WatchState
import net.rec0de.android.watchwitch.bitmage.ByteOrder
import net.rec0de.android.watchwitch.bitmage.fromBytes
import net.rec0de.android.watchwitch.bitmage.hex
import java.io.IOException
import java.net.Inet6Address


class VpnConnection(
    private val localAddresses: Set<Inet6Address>,
    private val remoteAddresses: Set<Inet6Address>,
    private val packages: Set<String>
) : Runnable {
    companion object {
        private const val TAG = "WitchVpnConnection"
        private val tun = TunDevice.open()

        fun init() {
            Log.d(TAG, "tun interface created: ${tun.name}")
            exec(listOf("sudo ip link set ${tun.name} up"))
        }

        private fun exec(cmd: List<String>) {
            Logger.logCmd(cmd.joinToString("\n"), 2)

            try {
                val runtime = Runtime.getRuntime()
                for (s in cmd) {
                    val process = runtime.exec(s)
                    process.waitFor()
                }
            } catch (e: IOException) {
                e.printStackTrace()
            } catch (e: InterruptedException) {
                e.printStackTrace()
            }
        }
    }

    private val sendBuf = mutableListOf<ByteArray>()

    override fun run() {
        Log.d(TAG, "Starting")

        WatchState.setPairingStage("VPN starting")
        WatchState.incrementProgress()

        try {

            // set up addresses and routing?
            exec(localAddresses.zip(remoteAddresses).map { "sudo ip addr add ${it.first.toString().removePrefix("/")} peer ${it.second.toString().removePrefix("/")} dev ${tun.name}" })
            //exec(localAddresses.zip(remoteAddresses).map { "sudo ip -6 route add ${it.second.toString().removePrefix("/")}/112 dev ${tun.name} src ${it.first.toString().removePrefix("/")}" })

            // send packets arriving before we set up the interface
            sendBuf.forEach { tun.write(it) }
            sendBuf.clear()

            // We keep forwarding packets till something goes wrong.
            while (true) {
                // Read the outgoing packet from the input stream.
                val packet = tun.read()

                if (packet.size() > 0) {
                    if(packet.isIpv4) {
                        Log.d(TAG, "trashing IPv4 packet")
                        continue
                    }

                    val data = packet.packet.array().sliceArray(0 until packet.size())
                    PacketLogger.logPacket(data)
                    val ipPacket = IPv6Packet.parse(data)
                    //Log.d(TAG, ipPacket.toString())

                    // use class C tunnel if destination is a class C address
                    val classC = ipPacket.destinationAddress[9] == (0x0c).toByte()

                    // support TCP and UDP for now
                    if(ipPacket.nextHeader.toInt() in setOf(6, 17)) {

                        var protocol = "UDP"
                        if(ipPacket.nextHeader.toInt() == 6) {
                            val sourcePort = Int.fromBytes(ipPacket.data.sliceArray(0 until 2), ByteOrder.BIG)
                            val destPort = Int.fromBytes(ipPacket.data.sliceArray(2 until 4), ByteOrder.BIG)
                            val flags = ipPacket.data[13].toInt()
                            val syn = if((flags and 0x02) != 0) "SYN " else ""
                            val ack = if((flags and 0x10) != 0) "ACK " else ""

                            protocol = "TCP $syn$ack($sourcePort->$destPort)"
                        }

                        //Log.d(TAG, "packet $protocol from localhost $ipPacket, ${ipPacket.data.hex()}")
                        ServiceReferences.espDispatcher?.sendESP(ipPacket.data, ipPacket.nextHeader.toInt(), classC)
                    }
                }
            }
        } finally {

        }
    }

    fun sendToLocalNetworkStack(data: ByteArray, nextHeader: Byte, sourceAddr: ByteArray, destAddr: ByteArray) {
        val packet = IPv6Packet(nextHeader, sourceAddr, destAddr, data)

        var protocol = "UDP"
        if(packet.nextHeader.toInt() == 6) {
            val sourcePort = Int.fromBytes(packet.data.sliceArray(0 until 2), ByteOrder.BIG)
            val destPort = Int.fromBytes(packet.data.sliceArray(2 until 4), ByteOrder.BIG)
            val flags = packet.data[13].toInt()
            val syn = if((flags and 0x02) != 0) "SYN " else ""
            val ack = if((flags and 0x10) != 0) "ACK " else ""

            protocol = "TCP $syn$ack($sourcePort->$destPort)"
        }

        //Log.d(TAG, "packet $protocol from remote: $packet, ${data.hex()}")
        val rendered = packet.render()
        PacketLogger.logPacket(rendered)
        tun.write(rendered)
    }
}