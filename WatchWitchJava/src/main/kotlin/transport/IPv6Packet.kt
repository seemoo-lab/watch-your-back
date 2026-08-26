package net.rec0de.android.watchwitch.transport

import net.rec0de.android.watchwitch.ParseCompanion
import net.rec0de.android.watchwitch.bitmage.hex
import java.nio.ByteBuffer

class IPv6Packet(
    val trafficClass: Byte,
    val flowLabel: Int,
    val length: UShort,
    val nextHeader: Byte,
    val hopLimit: Byte,
    val sourceAddress: ByteArray,
    val destinationAddress: ByteArray,
    val data: ByteArray
)
{
    companion object : ParseCompanion() {
        fun parse(bytes: ByteArray): IPv6Packet {
            parseOffset = 0

            val version = bytes[0].toInt() and 0xF0
            check(version == 0x60){ "Expected IPv6 packet starting with 0x6 but got ${bytes.hex()}" }
            val trafficClass = (((bytes[0].toInt() and 0x0F) shl 4) or ((bytes[1].toInt() and 0xF0) shr 4)).toByte()
            val flowLabel = ((((bytes[1].toInt() and 0x0F) shl 8) or bytes[2].toInt()) shl 8) or bytes[3].toInt()
            parseOffset = 4

            val length = readInt(bytes, 2).toUShort()
            val nextHeader = bytes[parseOffset]
            parseOffset += 1
            val hopLimit = bytes[parseOffset]
            parseOffset += 1
            val sourceAddr = readBytes(bytes, 16)
            val destinationAddr = readBytes(bytes, 16)

            check(length.toInt() + parseOffset == bytes.size) { "expected IPv6 packet of $length + 40 bytes, but got ${bytes.size} bytes in buffer" }

            val data = readBytes(bytes, length.toInt())

            return IPv6Packet(trafficClass, flowLabel, length, nextHeader, hopLimit, sourceAddr, destinationAddr, data)
        }
    }

    constructor(nextHeader: Byte, sourceAddress: ByteArray, destinationAddress: ByteArray, data: ByteArray) :
            this(0, 0, data.size.toUShort(), nextHeader, 16, sourceAddress, destinationAddress, data)

    fun render(): ByteArray {
        val buf = ByteBuffer.allocate(40)

        val firstWord = (0x60 shl 24) or (trafficClass.toInt() shl 20) or (flowLabel and 0xFFFFF)
        buf.putInt(firstWord)
        buf.putShort(length.toShort())
        buf.put(nextHeader)
        buf.put(hopLimit)
        buf.put(sourceAddress)
        buf.put(destinationAddress)

        return buf.array() + data
    }

    override fun toString(): String {
        return "IPv6(len=$length, from ${sourceAddress.hex()} to ${destinationAddress.hex()}, next header $nextHeader, hops $hopLimit)"
    }
}