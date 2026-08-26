package net.rec0de.android.watchwitch.servicehandlers.camera

import net.rec0de.android.watchwitch.Log
import net.rec0de.android.watchwitch.Logger
import net.rec0de.android.watchwitch.WatchState
import net.rec0de.android.watchwitch.alloy.AlloyController
import net.rec0de.android.watchwitch.alloy.AlloyHandler
import net.rec0de.android.watchwitch.alloy.AlloyMessage
import net.rec0de.android.watchwitch.alloy.AlloyService
import net.rec0de.android.watchwitch.alloy.DataMessage
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID


object CameraProxy : AlloyService {

    private const val TAG = "CameraProxy"
    private const val TOPIC = "com.apple.private.alloy.camera.proxy"
    override val handlesTopics = listOf(TOPIC)

    private var index = 0

    override fun acceptsMessageType(msg: AlloyMessage) = msg is DataMessage
    override fun acceptsLocalDeviceRole(device: AlloyService.Device) = device == AlloyService.Device.WATCH

    override fun receiveMessage(msg: AlloyMessage, handler: AlloyHandler) {
        if(msg !is DataMessage)
            throw Exception("$TAG expects DataMessage but got $msg")

        if(msg.responseIdentifier == null) {
            handleRequest(CameraRequest.parse(msg.payload)!!, msg.messageUUID, handler)
        }
        else
            handleResponse(CameraResponse.parse(msg.payload)!!)
    }

    private fun handleResponse(response: CameraResponse) {
        Log.d(TAG, "rcv: $response")
    }

    private fun handleRequest(request: CameraRequest, uuid: UUID, handler: AlloyHandler) {
        Log.d(TAG, "rcv $request")

        when(request) {
            is CameraOpenStateChangeRequest -> sendResponse(CameraOpenStateChangeResponse(true), uuid, handler)
            is UpdateThumbnailRequest -> saveThumbnail(request.jpegData)
        }
    }

    fun openCamera() {
        sendRequest(OpenCameraRequest(listOf(0)))
    }

    fun pressShutter() {
        sendRequest(PressShutterRequest(0))
    }

    private fun sendRequest(msg: CameraRequest) {
        val handler = AlloyController.getHandlerForChannel("UTunDelivery-Default-Urgent-C")

        if(handler == null) {
            Log.d(TAG, "can't send message, no handler")
            return
        }

        Log.d(TAG, "snd: $msg")
        handler.sendData(msg.render(), TOPIC, UUID.randomUUID())
    }

    private fun sendResponse(msg: CameraResponse, responseIdentifier: UUID, handler: AlloyHandler) {
        Log.d(TAG, "snd: $msg")
        handler.sendData(msg.render(), TOPIC, UUID.randomUUID(), responseIdentifier = responseIdentifier.toString())
    }

    private fun saveThumbnail(content: ByteArray) {
        val format = SimpleDateFormat("yyyMMdd-HHmm", Locale.US)
        val timestamp = format.format(Date())
        val filename = "thumbnail-$timestamp-$index.jpeg"

        FileOutputStream(filename).use {
            it.write(content)
        }

        WatchState.addStolenInfo("img $filename")

        index += 1

        Logger.logIDS("[cameraproxy] saved thumbnail as $filename", 0)
    }
}