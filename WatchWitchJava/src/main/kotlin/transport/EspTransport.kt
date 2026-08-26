package net.rec0de.android.watchwitch.transport

interface EspTransport {
    fun sendEsp(packet: ByteArray, isClassC: Boolean)
}