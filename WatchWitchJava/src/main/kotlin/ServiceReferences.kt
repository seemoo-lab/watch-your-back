package net.rec0de.android.watchwitch

import net.rec0de.android.watchwitch.bitmage.fromHex
import net.rec0de.android.watchwitch.bitmage.hex
import net.rec0de.android.watchwitch.transport.ESPDispatcher
import net.rec0de.android.watchwitch.transport.NrlpOverUdpService
import net.rec0de.android.watchwitch.transport.VpnConnection
import java.net.Inet6Address

// globally accessible references to continuously running services to allow interaction
// within same process
object ServiceReferences {

    var bumbleHost = "127.0.0.1"
    var nrlpOverUdpService: NrlpOverUdpService? = null
    var espDispatcher: ESPDispatcher? = null
    var vpnConnection: VpnConnection? = null

    var watchsideAddressC: ByteArray = "fd7465726d6e7573000c4bb0752a8bf0".fromHex()
    var watchsideAddressD: ByteArray = "fd7465726d6e7573000d4bb0752a8bf0".fromHex()
    var phonesideAddressC: ByteArray? = null
    var phonesideAddressD: ByteArray? = null
    var phonesideShoesAddress: ByteArray? = null
    var phonesideShoesPort: Int = 62742

    var preferWiFi = false
    var phoneLocalIP = "127.0.0.1"
    var phoneIkePort = 62743

    private var callbackFired = false
    private var addressesAvailableCallback: (()->Unit)? = null

    var startTime = 0L
    var endTime = 0L

    // assumes watch is always initiator
    fun setAddress(classC: Boolean, initiator: Boolean, address: ByteArray) {
        when {
            initiator && classC -> {
                watchsideAddressC = address
                val stringAddr = Inet6Address.getByAddress(address).toString().removePrefix("/")
                LongTermStorage.setAddress(LongTermStorage.LOCAL_ADDRESS_CLASS_C, LongTermStorage.CONTEXT_WATCH, stringAddr) // TODO: messy.
            }
            !initiator && classC -> {
                phonesideAddressC = address
                val stringAddr = Inet6Address.getByAddress(address).toString().removePrefix("/")
                LongTermStorage.setAddress(LongTermStorage.REMOTE_ADDRESS_CLASS_C, LongTermStorage.CONTEXT_WATCH, stringAddr) // TODO: messy.
            }
            initiator && !classC -> {
                watchsideAddressD = address
                val stringAddr = Inet6Address.getByAddress(address).toString().removePrefix("/")
                LongTermStorage.setAddress(LongTermStorage.LOCAL_ADDRESS_CLASS_D, LongTermStorage.CONTEXT_WATCH, stringAddr) // TODO: messy.
            }
            else -> {
                phonesideAddressD = address
                val stringAddr = Inet6Address.getByAddress(address).toString().removePrefix("/")
                LongTermStorage.setAddress(LongTermStorage.REMOTE_ADDRESS_CLASS_D, LongTermStorage.CONTEXT_WATCH, stringAddr) // TODO: messy.
            }
        }
        Logger.logIKE("saved ipv6 address: init $initiator classC $classC ${address.hex()}", 5)
        //Logger.logIKE("callback conditions: ${phonesideAddressC != null} ${phonesideAddressD != null} ${addressesAvailableCallback != null} fired: $callbackFired", 5)

        if(phonesideAddressC != null && phonesideAddressD != null && addressesAvailableCallback != null && !callbackFired) {
            Log.d("ServiceReferences", "addresses available, firing callback")
            addressesAvailableCallback!!.invoke()
            addressesAvailableCallback = null
            callbackFired = true
        }
    }

    fun callbackWhenAddressesAvailable(callback: (()->Unit)?) {
        //Log.d("ServiceReferences", "callback once available")
        if(phonesideAddressC != null && phonesideAddressD != null && callback != null && !callbackFired) {
            //Log.d("ServiceReferences", "already available!")
            callback.invoke()
            callbackFired = true
        }
        else {
            //Log.d("ServiceReferences", "not yet available")
            addressesAvailableCallback = callback
        }
    }
}