package net.rec0de.android.watchwitch

import net.rec0de.android.watchwitch.bitmage.fromIndex
import net.rec0de.android.watchwitch.bitmage.hex
import java.io.BufferedOutputStream
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object IdsLogger {

    private var output: BufferedOutputStream? = null

    fun init() {
        val time = SimpleDateFormat("yyyy-MM-dd-HHmm", Locale.US).format(Date())
        val name = "session-$time.idslog"
        val file = FileOutputStream(name)
        output = BufferedOutputStream(file)
    }

    fun logAlloy(send: Boolean, bytes: ByteArray) {
        val dir = if(send) "snd" else "rcv"
        output?.write("$dir utun ${bytes[0].toInt()} ${bytes.fromIndex(5).hex()}\n".toByteArray(Charsets.US_ASCII))
    }

    fun logControl(send: Boolean, bytes: ByteArray) {
        val dir = if(send) "snd" else "rcv"
        output?.write("$dir utunctrl ${bytes.hex()}\n".toByteArray(Charsets.US_ASCII))
    }

    fun flush() {
        output?.flush()
        output?.close()
    }
}