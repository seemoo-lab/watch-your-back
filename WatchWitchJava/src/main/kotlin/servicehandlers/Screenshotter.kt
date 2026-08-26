package net.rec0de.android.watchwitch.servicehandlers

import net.rec0de.android.watchwitch.Logger
import net.rec0de.android.watchwitch.alloy.AlloyHandler
import net.rec0de.android.watchwitch.alloy.AlloyMessage
import net.rec0de.android.watchwitch.alloy.AlloyService
import net.rec0de.android.watchwitch.alloy.DataMessage
import net.rec0de.android.watchwitch.decoders.bplist.BPAsciiString
import net.rec0de.android.watchwitch.decoders.bplist.BPListParser
import net.rec0de.android.watchwitch.decoders.bplist.NSData
import net.rec0de.android.watchwitch.decoders.bplist.NSDict
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object Screenshotter : AlloyService {
    private var index = 1
    override val handlesTopics = listOf("com.apple.private.alloy.screenshotter")

    override fun acceptsMessageType(msg: AlloyMessage) = msg is DataMessage
    override fun acceptsLocalDeviceRole(device: AlloyService.Device) = device == AlloyService.Device.PHONE

    override fun receiveMessage(msg: AlloyMessage, handler: AlloyHandler) {
        msg as DataMessage

        if(!BPListParser.bufferIsBPList(msg.payload)){
            Logger.logIDS("[screenshotter] unexpected non-bplist message: $msg", 0)
            return
        }

        val bp = BPListParser().parse(msg.payload) as NSDict
        val imgData = bp.values[BPAsciiString("d")]!! as NSData
        saveScreenshot(imgData.value)
    }

    private fun saveScreenshot(content: ByteArray) {
        val format = SimpleDateFormat("yyyMMdd-HHmm", Locale.US)
        val timestamp = format.format(Date())
        val filename = "screenshot-$timestamp-$index.png"

        FileOutputStream(filename).use {
            it.write(content)
        }

        index += 1

        Logger.logIDS("[screenshotter] saved screenshot as $filename", 0)
    }
}