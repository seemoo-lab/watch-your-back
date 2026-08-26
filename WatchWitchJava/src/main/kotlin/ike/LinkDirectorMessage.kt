package net.rec0de.android.watchwitch.ike

import net.rec0de.android.watchwitch.ParseCompanion
import net.rec0de.android.watchwitch.bitmage.ByteOrder
import net.rec0de.android.watchwitch.bitmage.hex
import net.rec0de.android.watchwitch.bitmage.toBytes
import java.nio.ByteBuffer

class LinkDirectorMessage(val identifier: Long, val tlvs: List<LdmTlv>) {
    companion object : ParseCompanion() {
        fun parse(bytes: ByteArray): LinkDirectorMessage {
            parseOffset = 0
            val version = readInt(bytes, 1)
            check(version == 2) { "unsupported LinkDirectorMessage version $version (we expect 2)" }

            parseOffset += 1 // skip 1 unused byte
            val length = readInt(bytes, 2)

            val padding = readInt(bytes, 4)
            check(padding == 0) { "LDM has non-zero padding bytes: ${padding.toString(16)}"}

            val identifier = readLong(bytes, 8)

            check(bytes.size - parseOffset == length) { "LDM has incorrect length field: ${bytes.hex()}" }

            val tlvs = mutableListOf<LdmTlv>()
            while (parseOffset < bytes.size) {
                val type = readInt(bytes, 1)
                val tlvlen = readInt(bytes, 2)
                val value = readBytes(bytes, tlvlen)
                tlvs.add(LdmTlv(type, value))
            }

            return LinkDirectorMessage(identifier, tlvs)
        }
    }

    class LdmTlv(val type: Int, val value: ByteArray) {
        companion object {
            private val stringTypes = listOf("Invalid", "Hello", "UpdateWiFiIPv6", "UpdateWiFiIPv4", "UpdateWiFiSignature", "PreferWiFi", "DeviceLinkState", "PreferWiFiAck", "ForceWoW")
            fun typeToString(type: Int) = stringTypes[type]
        }

        override fun toString() = "${typeToString(type)}: ${value.hex()}"

        fun render(): ByteArray = byteArrayOf(type.toByte()) + value.size.toShort().toBytes(ByteOrder.BIG) + value
    }

    fun render(): ByteArray {
        val tlvBytes = tlvs.map { it.render() }.reduce { acc, bytes -> acc + bytes }

        val buf = ByteBuffer.allocate(16)
        buf.put(2) // version
        buf.put(0)
        buf.putShort(tlvBytes.size.toShort())
        buf.putInt(0) // padding
        buf.putLong(identifier)
         return buf.array() + tlvBytes
    }

    override fun toString() = "LinkDirectorMessage(${identifier}, ${tlvs.joinToString(", ")})"
}