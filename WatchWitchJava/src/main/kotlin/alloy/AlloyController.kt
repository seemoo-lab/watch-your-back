package net.rec0de.android.watchwitch.alloy

import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import net.rec0de.android.watchwitch.IdsLogger
import net.rec0de.android.watchwitch.Logger
import net.rec0de.android.watchwitch.LongTermStorage
import net.rec0de.android.watchwitch.WatchState
import net.rec0de.android.watchwitch.devices.Watch
import net.rec0de.android.watchwitch.devices.iPhone
import net.rec0de.android.watchwitch.ike.IKEv2Session
import net.rec0de.android.watchwitch.nwsc.NWSCManager
import net.rec0de.android.watchwitch.servicehandlers.Accessibility
import net.rec0de.android.watchwitch.servicehandlers.AccountSync
import net.rec0de.android.watchwitch.servicehandlers.Anisette
import net.rec0de.android.watchwitch.servicehandlers.Baseband
import net.rec0de.android.watchwitch.servicehandlers.BluetoothRegistry
import net.rec0de.android.watchwitch.servicehandlers.ContinuityAuth
import net.rec0de.android.watchwitch.servicehandlers.CoreDuet
import net.rec0de.android.watchwitch.servicehandlers.FindMyLocalDevice
import net.rec0de.android.watchwitch.servicehandlers.IdsCredentials
import net.rec0de.android.watchwitch.servicehandlers.NetworkSync
import net.rec0de.android.watchwitch.servicehandlers.PBBridge
import net.rec0de.android.watchwitch.servicehandlers.PairedDevice
import net.rec0de.android.watchwitch.servicehandlers.PreferencesSync
import net.rec0de.android.watchwitch.servicehandlers.PushProxy
import net.rec0de.android.watchwitch.servicehandlers.Screenshotter
import net.rec0de.android.watchwitch.servicehandlers.TimeSync
import net.rec0de.android.watchwitch.servicehandlers.camera.CameraProxy
import net.rec0de.android.watchwitch.servicehandlers.health.HealthSync
import net.rec0de.android.watchwitch.servicehandlers.messaging.BulletinDistributorService
import java.io.DataOutputStream
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random

object AlloyController {

    private var output: DataOutputStream? = null
    private val instanceID = UUID.randomUUID()

    private val remoteAnnouncedChannels = mutableSetOf<String>()
    private val requestingChannels = mutableSetOf<String>()
    private val establishedChannels = mutableSetOf<String>()
    private val handlers = mutableMapOf<String,AlloyHandler>()

    private val serviceNameToLocalUUID = mutableMapOf<String, UUID>()
    private val streamIdAssociations = mutableMapOf<Int, String>()
    private val reverseStreamIdAssociations = mutableMapOf<String, Int>()

    private var neverInitiate: Boolean = false
    private var isInitialPairing: Boolean = false
    var localDeviceRole: AlloyService.Device = AlloyService.Device.PHONE

    private var numberOfRequestedChannels: Int = 0
    private var sentPairedPrelude = false

    val nextSenderSequence: AtomicInteger = AtomicInteger(29) // i think the start value is slightly random, copying from watch log

    // add custom alloy services here
    val services: Map<String, AlloyService> = listOf(
        Anisette,
        AccountSync,
        Accessibility,
        Baseband,
        BluetoothRegistry,
        BulletinDistributorService,
        CameraProxy,
        ContinuityAuth,
        CoreDuet,
        FindMyLocalDevice,
        IdsCredentials,
        PairedDevice,
        PushProxy,
        PBBridge,
        PreferencesSync,
        NetworkSync,
        TimeSync,
        HealthSync,
        Screenshotter
    ).flatMap { service -> service.handlesTopics.map { Pair(it, service) } }.toMap()

    fun usingOutput(out: DataOutputStream): AlloyController {
        output = out
        return this
    }

    /**
     * When the ids-control-channel is initialized, both parties send their hellos immediately followed by a bunch of create channel messages
     * Then both parties attempt to open actual connections for (a subset of??) the requested channels
     */
    fun init() {
        WatchState.alloyConnected.set(false)
        val hello = if(localDeviceRole == AlloyService.Device.WATCH) genWatchHello() else genPhoneHello()

        Logger.logUTUN("snd $hello", 1)
        send(hello.toBytes())

        WatchState.setPairingStage("idscc established")
        WatchState.incrementProgress()

        //val deliveryChannels = listOf("UTunDelivery-Default-Default-C", "UTunDelivery-Default-Default-D", "UTunDelivery-Default-DefaultCloud-C", "UTunDelivery-Default-DefaultCloud-D", "UTunDelivery-Default-Sync-C", "UTunDelivery-Default-Sync-D", "UTunDelivery-Default-Urgent-C", "UTunDelivery-Default-Urgent-D", "UTunDelivery-Default-UrgentCloud-C", "UTunDelivery-Default-UrgentCloud-D")
        val deliveryChannels = listOf("UTunDelivery-Default-Default-C", "UTunDelivery-Default-Default-D", "UTunDelivery-Default-Sync-C", "UTunDelivery-Default-Sync-D", "UTunDelivery-Default-Urgent-C", "UTunDelivery-Default-Urgent-D")
        numberOfRequestedChannels = deliveryChannels.size

        var portIdx = 0

        deliveryChannels.forEachIndexed { i, it ->
            val fullService = "idstest/localdelivery/$it"
            val uuid = UUID.randomUUID()
            serviceNameToLocalUUID[fullService] = uuid

            // code in IDSUTunController::startDataChannelWithDevice:genericConnection:serviceConnectorService:endpoint: suggests 61315 is used for cloud-enabled channels
            val targetPort = if(it.contains("Cloud")) 61315 else 61314

            val setupChan = SetupChannel(6, targetPort, 51314+portIdx, uuid, null, "idstest", "localdelivery", it)
            portIdx += 1
            Thread {
                Thread.sleep(100L * i)
                Logger.logUTUN("snd $setupChan", 1)
                send(setupChan.toBytes())
                requestingChannels.add(fullService)
            }.start()


            // if we're simulating the watch, initiating channels gets messy because of IP routing
            if(!neverInitiate) {
                // attempt to open an actual connection
                GlobalScope.launch {
                    delay((400 + 30*i).toLong())
                    // we may have received and accepted an incoming request for this channel in the meantime
                    if(!establishedChannels.contains(fullService)) {
                        val handler = AlloyHandler(fullService, null)
                        NWSCManager.initiateChannelAndForward(fullService, targetPort, handler)
                    }
                }
            }
        }
    }

    private fun genPhoneHello(): Hello {
        val hello = Hello("5", iPhone.OS_NAME, iPhone.OS_VERSION, iPhone.BUILD, iPhone.HW_VERSION, 0)
        hello.compatMinProtocolVersion = 15
        hello.compatMaxProtocolVersion = 16
        hello.serviceMinimumCompatibilityVersion = 10
        hello.capabilityFlags = 0x3ff
        // we re-generate this on every launch which i think causes the watch to treat us more nicely (including topics in message because we don't have mappings yet etc)
        hello.instanceID = instanceID
        hello.deviceID = LongTermStorage.getUTUNDeviceID() ?: UUID.randomUUID()
        return hello
    }

    private fun genWatchHello(): Hello {
        val hello = Hello("5", Watch.OS_NAME, Watch.OS_VERSION, Watch.BUILD, Watch.HW_VERSION, Watch.ALLOY_PROTOCOL_VERSION)
        hello.compatMinProtocolVersion = Watch.ALLOY_MIN_PROTOCOL_VERSION
        hello.compatMaxProtocolVersion = Watch.ALLOY_MAX_PROTOCOL_VERSION
        hello.serviceMinimumCompatibilityVersion = Watch.SERVICE_MIN_VERSION
        hello.capabilityFlags = Watch.CAPABILITY_FLAGS.toLong()
        hello.instanceID = instanceID
        hello.deviceID = UUID.fromString(Watch.DEVICE_ID)
        return hello
    }

    fun receive(message: ByteArray) {
        IdsLogger.logControl(false, message)
        val msg = UTunControlMessage.parse(message)

        NWSCManager.markControlChannelInitialized()

        Logger.logUTUN("rcv $msg", 0)

        when (msg) {
            is SetupChannel -> setupChannel(msg)
            is CloseChannel -> closeChannel(msg)
            is SetupEncryptedChannel -> setupEncryptedChannel(msg)
        }
    }

    private fun setupChannel(msg: SetupChannel) {
        val fullService = "${msg.account}/${msg.service}/${msg.name}"
        remoteAnnouncedChannels.add(fullService)

        if(!requestingChannels.contains(fullService)) {
            Logger.logUTUN("got request for $fullService, which we did not request - replying", 1)
            val ourUUID = serviceNameToLocalUUID.computeIfAbsent(fullService) { UUID.randomUUID()}
            val reply = SetupChannel(msg.protocol, msg.receiverPort, msg.senderPort, ourUUID, msg.senderUUID, msg.account, msg.service, msg.name)
            Logger.logUTUN("UTUN snd $reply", 0)
            send(reply.toBytes())
        }
    }

    private fun setupEncryptedChannel(msg: SetupEncryptedChannel) {
        val fullService = "${msg.account}/${msg.service}/${msg.name}"
        remoteAnnouncedChannels.add(fullService)

        if(!requestingChannels.contains(fullService)) {
            Logger.logUTUN("got request for $fullService, which we did not request - replying", 1)
            val ourUUID = serviceNameToLocalUUID.computeIfAbsent(fullService) { UUID.randomUUID()}
            
            // we don't really know how encrypted channels work since we haven't observed them in use
            // but we CAN send an appropriate reply with random values for the key material
            // (encrypted channels seem to use SRTP in some way shape or form)
            val ssrc = Random.nextInt()
            val keymat = Random.nextBytes(60)
            val reply = SetupEncryptedChannel(msg.protocol, msg.receiverPort, msg.senderPort, ourUUID, msg.senderUUID, msg.account, msg.service, msg.name, ssrc, 0, keymat)
            
            Logger.logUTUN("UTUN snd $reply", 0)
            send(reply.toBytes())
        }
    }

    private fun closeChannel(msg: CloseChannel) {
        val fullService = "${msg.account}/${msg.service}/${msg.name}"
        Logger.logUTUN("got closure of $fullService", 1)
        registerChannelClose(fullService)
    }

    fun registerChannelClose(channel: String) {
        remoteAnnouncedChannels.remove(channel)
        serviceNameToLocalUUID.remove(channel)
        establishedChannels.remove(channel)
        handlers.remove(channel)
    }

    fun registerChannelCreation(channel: String, handler: AlloyHandler) {
        handlers[channel] = handler
        establishedChannels.add(channel)

        Logger.logIDS("channels established: ${establishedChannels.size}/$numberOfRequestedChannels", 0)
        WatchState.setPairingStage("alloy channel established (${establishedChannels.size}/$numberOfRequestedChannels)")
        WatchState.incrementProgress()

        if(!sentPairedPrelude) {
            // instruct bluetooth service to use "paired" state in preludes from now on
            Logger.logIKE("switching to paired prelude", 0)
            IKEv2Session.freshPrelude(IKEv2Session.Companion.PairingState.HasCompletedPairing)
            sentPairedPrelude = true
        }


        // we'll somewhat arbitrarily say that we consider the watch to be connected when we have 3 channels open
        if(establishedChannels.size >= numberOfRequestedChannels && !WatchState.alloyConnected.getAndSet(true)) {
            // notify service handlers that remote device connected
            Thread {
                runBlocking { delay(1000) }
                if(localDeviceRole == AlloyService.Device.WATCH)
                    services.values.toSet().forEach { it.onPhoneConnect(isInitialPairing) }
                else
                    services.values.toSet().forEach { it.onWatchConnect(isInitialPairing) }
            }.start()
        }
    }

    fun shouldAcceptConnection(service: String): Boolean {
        // technically there is some mechanism for which side should accept simultaneous connection requests
        // based on the connection UUIDs, but we'll just accept everything we can for now
        return remoteAnnouncedChannels.contains(service) && !establishedChannels.contains(service)
    }

    fun getHandlerForChannel(channel: String): AlloyHandler? {
        return handlers["idstest/localdelivery/$channel"]
    }

    // get handlers for any one of the listed channels in descending order of preference
    fun getHandlerForChannel(channels: List<String>): AlloyHandler? {
        return channels.map { handlers["idstest/localdelivery/$it"] }.firstOrNull { it != null }
    }

    fun getAnyHandler(): AlloyHandler? {
        return handlers.values.firstOrNull()
    }

    fun getFreshStream(topic: String): Int {
        val id = (streamIdAssociations.keys.maxOrNull() ?: 0) + 1
        streamIdAssociations[id] = topic
        reverseStreamIdAssociations[topic] = id
        return id
    }

    fun associateStreamWithTopic(streamID: Int, topic: String, allowOverride: Boolean = false) {
        //Logger.logIDS("associating stream $streamID with topic $topic", 1)
        if(streamIdAssociations.containsKey(streamID)) {
            if(streamIdAssociations[streamID] != topic && !allowOverride) {
                Logger.logIDS("Stream ID $streamID is associated with topic ${streamIdAssociations[streamID]} but trying to rebind with $topic", 0)
                //val replacementStream = reverseStreamIdAssociations[topic] ?: getFreshStream(topic)
                //val handler = getHandlerForChannel("UTunDelivery-Default-Urgent-D")!!
                //handler.send(ServiceMapMessage(streamID, streamIdAssociations[streamID]!!, 1))
                //handler.send(ServiceMapMessage(replacementStream, topic, 1))
                return
            }
        }
        streamIdAssociations[streamID] = topic
        reverseStreamIdAssociations[topic] = streamID
    }

    fun resolveStream(streamID: Int): String? {
        //Logger.logIDS("resolving stream $streamID to topic ${streamIdAssociations[streamID]}", 1)
        return streamIdAssociations[streamID]
    }

    fun resolveTopic(topic: String): Int? {
        val res = reverseStreamIdAssociations[topic]
        //Logger.logIDS("resolving topic $topic to stream $res", 1)
        return res
    }

    private fun send(message: ByteArray) {
        IdsLogger.logControl(true, message)
        val toWatch = output!!
        toWatch.writeShort(message.size)
        toWatch.write(message)
        toWatch.flush()
    }

    fun close() {
        Logger.logUTUN("Handler closed for ids-control-channel", 1)
    }

    fun simulateNeverInitiate() {
        neverInitiate = true
    }

    fun takeWatchRole() {
        localDeviceRole = AlloyService.Device.WATCH
    }

    fun performInitialPairing() {
        isInitialPairing = true
    }
}