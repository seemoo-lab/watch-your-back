package net.rec0de.android.watchwitch

import net.rec0de.android.watchwitch.bitmage.ByteOrder
import net.rec0de.android.watchwitch.bitmage.fromHex
import net.rec0de.android.watchwitch.bitmage.toBytes
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object PacketLogger {

    private var output: BufferedOutputStream? = null

    private val sectionheader = "0a0d0d0a0000001c1a2b3c4d00010000ffffffffffffffff0000001c".fromHex()
    private val interfaceblock = "000000010000002400650000000400000002000a57617463685769746368000000000024".fromHex()

    fun init() {
        val time = SimpleDateFormat("yyyy-MM-dd-HHmm", Locale.US).format(Date())
        val name = "session-$time.pcapng"

        val file = FileOutputStream(name)

        output = BufferedOutputStream(file)

        output!!.write(sectionheader)
        output!!.write(interfaceblock)
    }

    fun logPacket(bytes: ByteArray) {
        val padding = if(bytes.size % 4 == 0) byteArrayOf() else byteArrayOf(0, 0, 0).sliceArray(0 until (4 - bytes.size % 4))
        val packetblock = ByteBuffer.allocate(28)
        packetblock.putInt(6) // block type (EPB)
        packetblock.putInt(28+4+bytes.size+padding.size) // block length
        packetblock.putInt(0) // interface id
        packetblock.putLong(System.currentTimeMillis())
        packetblock.putInt(bytes.size) // captured length
        packetblock.putInt(bytes.size) // original length

        output?.write(packetblock.array())
        output?.write(bytes)
        output?.write(padding)
        output?.write((28+4+bytes.size+padding.size).toBytes(ByteOrder.BIG))
    }

    fun flush() {
        output?.flush()
        output?.close()
        output = null
    }
}