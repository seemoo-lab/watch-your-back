package net.rec0de.android.watchwitch.transport

import net.rec0de.android.watchwitch.ParseCompanion
import net.rec0de.android.watchwitch.Utils
import net.rec0de.android.watchwitch.bitmage.fromIndex
import net.rec0de.android.watchwitch.bitmage.hex
import java.nio.ByteBuffer

class IPv4Packet(
    val dscp: Int,
    val ecn: Int,
    val identification: UShort,
    val flags: Int,
    val fragmentOffset: Int,
    val ttl: Byte,
    val nextHeader: Byte,
    val checksum: UShort,
    val sourceAddress: Int,
    val destinationAddress: Int,
    val options: ByteArray?,
    val data: ByteArray
)
{
    companion object : ParseCompanion() {
        fun parse(bytes: ByteArray): IPv4Packet {
            parseOffset = 0

            val version = bytes[0].toInt() and 0xF0
            check(version == 0x40){ "Expected IPv4 packet starting with 0x4 but got ${bytes.hex()}" }

            // ihl gives header length in multiples of 4 bytes
            val ihl = (bytes[0].toInt() and 0x0F) * 4
            val b1 = bytes[1].toInt()
            val dscp = b1 shr 2
            val ecn = b1 and 0x03
            parseOffset = 2

            val length = readInt(bytes, 2).toUShort()
            val identification = readInt(bytes, 2).toUShort()

            val flagsFragementOffset = readInt(bytes, 2)
            val flags = (flagsFragementOffset shr 13) and 0x07
            val fragmentOffset = flagsFragementOffset and 0x1FFF

            val ttl = bytes[parseOffset]
            val protocol = bytes[parseOffset+1]
            parseOffset += 2

            val checksum = readInt(bytes, 2).toUShort()
            val sourceAddress = readInt(bytes, 4)
            val destinationAddress = readInt(bytes, 4)

            val options = if(ihl > 20) readBytes(bytes, ihl-20) else null

            val data = bytes.fromIndex(ihl)
            check(data.size == length.toInt()-ihl){ "IPv4 expected ${length.toInt()-ihl} payload bytes but got ${data.size}" }

            return IPv4Packet(dscp, ecn, identification, flags, fragmentOffset, ttl, protocol, checksum, sourceAddress, destinationAddress, options, data)
        }
    }

    constructor(nextHeader: Byte, sourceAddress: Int, destinationAddress: Int, data: ByteArray) :
            this(0, 0, 0u, 0, 0, 16, nextHeader, 0u, sourceAddress, destinationAddress, null, data)

    fun render(): ByteArray {

        val ihl = if(options != null) 5 + options.size/4 else 5
        val length = data.size + ihl * 4
        val buf = ByteBuffer.allocate(ihl*4)

        // ugly, no guardrails
        val firstWord = ((0x40 or ihl) shl 24) or (((dscp shr 2) or ecn) shl 16) or (length and 0xFFFF)
        buf.putInt(firstWord)
        buf.putShort(identification.toShort())
        buf.putShort(((flags shr 13) or fragmentOffset).toShort())
        buf.put(ttl)
        buf.put(nextHeader)
        buf.putShort(checksum.toShort())
        buf.putInt(sourceAddress)
        buf.putInt(destinationAddress)

        if(options != null)
            buf.put(options)

        return buf.array() + data
    }

    fun fastRenderWithChecksum(): ByteArray {
        val buf = ByteBuffer.allocate(20)
        buf.putShort(0x4500)
        buf.putShort((data.size+20).toShort())
        buf.putInt(0) // zero identification, flags, and fragment offset
        buf.put(ttl)
        buf.put(nextHeader)
        buf.putShort(0)
        buf.putInt(sourceAddress)
        buf.putInt(destinationAddress)

        val checksum = Utils.ipChecksum(buf.array())
        buf.putShort(10, checksum.toShort())

        return buf.array()
    }

    override fun toString(): String {
        return "IPv4(from ${sourceAddress.toString(16)} to ${destinationAddress.toString(16)}, next header $nextHeader, hops $ttl, id $identification)"
    }
}