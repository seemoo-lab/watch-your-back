package net.rec0de.android.watchwitch

import kotlinx.coroutines.DelicateCoroutinesApi
import net.rec0de.android.watchwitch.nwsc.NWSCManager
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.BindException
import java.net.ServerSocket
import java.net.Socket


class TcpServerService {
    private val idsA = TcpServer(61314)
    private val idsB = TcpServer(61315)


    private val runnable = Runnable {
        idsA.start()
        idsB.start()

        idsA.join()
    }

    fun start() {
        Thread(runnable, "tcp-service").start()
    }
}

class TcpServer(private val port: Int) : Thread("tcp-server") {

    private lateinit var serverSocket: ServerSocket
    private var shouldRun = true

    fun kill() {
        serverSocket.close()
    }

    @OptIn(DelicateCoroutinesApi::class)
    override fun run() {
        var socket: Socket? = null
        try {
            serverSocket = ServerSocket(port)
            while (shouldRun) {
                socket = serverSocket.accept()
                val dataInputStream = DataInputStream(socket.getInputStream())
                val dataOutputStream = DataOutputStream(socket.getOutputStream())

                Logger.logIDS("IDS connect on $port: src port ${socket.port}", 0)
                Thread {
                    NWSCManager.readFromSocket(dataInputStream, dataOutputStream, port)
                }.start()
            }
        } catch (e: IOException) {
            e.printStackTrace()
            if(e is BindException) {
                Logger.setError("couldn't bind Alloy port $port")
            }
            try {
                serverSocket.close()
                socket?.close()
            } catch (ex: IOException) {
                ex.printStackTrace()
            }
        }

        Logger.logIDS("Alloy server exited", 0)
    }
}

