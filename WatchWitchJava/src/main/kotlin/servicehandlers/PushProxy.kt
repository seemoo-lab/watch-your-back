package net.rec0de.android.watchwitch.servicehandlers

import net.rec0de.android.watchwitch.Log
import net.rec0de.android.watchwitch.Logger
import net.rec0de.android.watchwitch.alloy.AlloyController
import net.rec0de.android.watchwitch.alloy.AlloyHandler
import net.rec0de.android.watchwitch.alloy.AlloyMessage
import net.rec0de.android.watchwitch.alloy.AlloyService
import net.rec0de.android.watchwitch.alloy.DataMessage
import net.rec0de.android.watchwitch.bitmage.fromHex
import net.rec0de.android.watchwitch.decoders.bplist.BPAsciiString
import net.rec0de.android.watchwitch.decoders.bplist.BPDict
import net.rec0de.android.watchwitch.decoders.bplist.BPInt
import net.rec0de.android.watchwitch.decoders.bplist.BPListParser
import net.rec0de.android.watchwitch.decoders.bplist.BPSDict
import net.rec0de.android.watchwitch.devices.Watch
import java.util.UUID

object PushProxy : AlloyService {

    private const val TOPIC = "com.apple.private.alloy.pushproxy"
    override val handlesTopics = listOf(TOPIC)
    override fun acceptsMessageType(msg: AlloyMessage) = msg is DataMessage
    override fun acceptsLocalDeviceRole(device: AlloyService.Device) = device == AlloyService.Device.WATCH
    private val TAG = "PushProxy"

    private val ppUUID = UUID.fromString("F3F0262D-920E-4656-8822-D04E6A8F5C69")

    override fun receiveMessage(msg: AlloyMessage, handler: AlloyHandler) {
        msg as DataMessage

        if(!BPListParser.bufferIsBPList(msg.payload)){
            Log.w(TAG, "unexpected non-bplist message: $msg")
            return
        }

        val bp = BPListParser().parse(msg.payload) as BPDict

        val command = (bp.values[BPAsciiString("c")]!! as BPInt).value.toInt()


        Log.d(TAG, "got command $command")

        when(command) {
            1 -> {
                // proxyManager:incomingPresenceWithGuid:token:hwVersion:swVersion:swBuild:certificate:nonce:signature:environmentName:
                val guid = bp.values[BPAsciiString("pG")]!!
                val token = bp.values[BPAsciiString("t")]!!
                val swVersion = bp.values[BPAsciiString("sv")]!!
                val hwVersion = bp.values[BPAsciiString("hw")]!!
                val swBuild = bp.values[BPAsciiString("sb")]!!
                val certificate = bp.values[BPAsciiString("ce")]!!
                val nonce = bp.values[BPAsciiString("no")]!!
                val signature = bp.values[BPAsciiString("si")]!!
                val environment = bp.values[BPAsciiString("e")]!!
            }
            2 -> {
                // proxyManager:incomingPushToken:guid:environmentName:
            }
            3 -> sendVersionInfo(handler) // proxyManagerReceivedDaemonAliveNotification:
            // 4: proxyManager:incomingFilterForGuid:environmentName:enabledTopics:ignoredTopics:opportunisticTopics:nonWakingTopics:
            // 5: proxyManager:inactiveReceivedForGuid:environmentName:
            // 6: proxyManager:receivedPush:interface:generation:guid:environmentName:
            // 7: proxyManager:receivedPushAckResponse:messageId:token:interface:generation:guid:environmentName:
            // 8: proxyManager:sendReversePush:guid:environmentName:
            // 9: proxyManager:reversePushResponse:messageGUID:messageId:guid:environmentName:
            // 10: proxyManager:expiredNonceWithServerTime:guid:environmentName:
            // 11: proxyManager:incomingMessageSize:largeMessageSize:guid:environmentName:
            // 12: proxyManager:appTokenGenerateWithTopicHash:baseToken:appId:guid:environmentName:
            // 13: proxyManager:appTokenGenerateResponse:error:guid:environmentName:
            // 14: proxyManager:isConnected:guid:environmentName:
            // 15: proxyManager:messageTracingWithStatus:topic:tracingUUID:token:guid:environmentName:
        }
    }

    private fun sendVersionInfo(handler: AlloyHandler) {
        val dict = BPSDict(mapOf(
            "c" to BPInt(1),
            "hw" to BPAsciiString(Watch.HW_VERSION),
            "sv" to BPAsciiString(Watch.OS_VERSION),
            "sb" to BPAsciiString(Watch.BUILD),
            "pG" to BPAsciiString(ppUUID.toString())
        ))
        send(dict, handler)
        onIdsCredentialsDone()
    }

    fun onIdsCredentialsDone() {
        Logger.logIDS("IdsCredentials completed, starting pushproxy init", 1)
        val handler = AlloyController.getHandlerForChannel("UTunDelivery-Default-Urgent-D")!!

        val dict = BPSDict(mapOf(
            "c" to BPInt(3)
        ))
        send(dict, handler)
        //handler.sendData("62706c6973743030da0102030405060708090a0b0c0d0e0f1011121314527047527362516351745263655273695165526877526e6f5273765f102446334630323632442d393230452d343635362d383832322d4430344536413846354336395631385338333010014f1020649a715d12ce9e6482a560d44d7fac4589747fe52ae9986fd16bbfcee5a4ce5b4f1102f7308202f33082025ca003020102020a0214311b666823e1dc64300d06092a864886f70d0101050500305a310b300906035504061302555331133011060355040a130a4170706c6520496e632e31153013060355040b130c4170706c65206950686f6e65311f301d060355040313164170706c65206950686f6e6520446576696365204341301e170d3235303332383135323931325a170d3238303332383135323931325a308183312d302b0603550403162430393645463034412d393235452d344245412d384445362d363735423630313546423036310b3009060355040613025553310b30090603550408130243413112301006035504071309437570657274696e6f31133011060355040a130a4170706c6520496e632e310f300d060355040b13066950686f6e6530819f300d06092a864886f70d010101050003818d0030818902818100ca557fa5bf87f24ec7b902d7c5ff29db2650f7b267891d5fe902e3ffb8f3e9ea4ce52b7c029fb2aee2c688b0bb920ba9779ebb5d3f56d11b111fcc890427c576b0e4b0140d920d3933b459278c72de2a22ce6d58846896df8594b17835336ac2a8b1c82c24850031e050e54cc5f8659768a4fa9919ea21d12156f81a15f487830203010001a38195308192301f0603551d23041830168014b2fe21234486956a79d581268e7310d8a74c8e74301d0603551d0e041604145a2181eba41d1dddadf7636292616e5263f293cc300c0603551d130101ff04023000300e0603551d0f0101ff0404030205a030200603551d250101ff0416301406082b0601050507030106082b060105050703023010060a2a864886f76364060a0204020500300d06092a864886f70d010105050003818100e66706745ae737ba977ab77307ab86debe6ab3763c351290335b0c20f54ebd5a50c86d57ec343458d2c30fe506a669977b8c12a17d4e9d23b796866de416f925f3af5a67484daa853f5493d451ec2fa1c7556349c25d0a6a70025c51e0d74cce836289178ef904cc14dac064e5e11102673bfd02dc1cb09930b3229e1528f1334f108201018ec69d6abd3887e40e1107724b0247a0e05ecb1d2746ffe5e5fb881c6039535ac4d623ad847127e3356c20ccb1edb096549d7045d325052beb85fa487c977f22c5bbd5ef7fefb0298537d725b16fc58af3d8b185e6284b2a433ce2673aa2efeb6aced88b92b2038a98198a66bc1fa352fd590af24d01c5c2f504b14f068a7dd65a70726f64756374696f6e585761746368352c314f10110000000196009598307944ec1194e43ece55372e332e330008001d0020002300250027002a002d002f003200350038005f00660068008b0386040b0416041f04330000000000000201000000000000001500000000000000000000000000000439".fromHex(), TOPIC, UUID.randomUUID())
        //handler.sendData("62706c6973743030d601020304050607080c0d0e0f526954526f5452704751635165526554a0a3090a0b5f104a636f6d2e6170706c652e69636c6f75642e70726573656e63652e636f6d2e6170706c652e707269766174652e616c6c6f792e77696c6c6f772d636f6d2e6170706c652e486f6d654b69745f102e636f6d2e6170706c652e69636c6f75642d636f6e7461696e65722e636f6d2e6170706c652e636f726564756574645f102e636f6d2e6170706c652e69636c6f75642d636f6e7461696e65722e636f6d2e6170706c652e7365637572697479645f102446334630323632442d393230452d343635362d383832322d44303445364138463543363910045a70726f64756374696f6eaf1016101112131415161718191a1b1c1d1e1f2021222324255f102d636f6d2e6170706c652e69636c6f75642d636f6e7461696e65722e636f6d2e6170706c652e666974636f7265645f1039636f6d2e6170706c652e69636c6f75642d636f6e7461696e65722e636f6d2e6170706c652e617373697374616e742e617373697374616e74645f1017636f6d2e6170706c652e6170706c792e736572766963655f1012636f6d2e6170706c652e666974636f7265645f1018636f6d2e6170706c652e61736b7065726d697373696f6e645f1019636f6d2e6170706c652e6163636f756e742e736572766963655f1032636f6d2e6170706c652e69636c6f75642d636f6e7461696e65722e636f6d2e6170706c652e4e616e6f52656d696e646572735f1037636f6d2e6170706c652e69636c6f75642d636f6e7461696e65722e636f6d2e6170706c652e54727573746564506565727348656c7065725f1013636f6d2e6170706c652e61707073746f7265645f1015636f6d2e6170706c652e706565727061796d656e745f1012636f6d2e6170706c652e69646d73617574685f1013636f6d2e6170706c652e73656c642e66616b655f1038636f6d2e6170706c652e69636c6f75642d636f6e7461696e65722e636f6d2e6170706c652e73656375726974792e637574746c65666973685f1037636f6d2e6170706c652e69636c6f75642d636f6e7461696e65722e636f6d2e6170706c652e41637469766974794d6f6e69746f724170705f1018636f6d2e69636c6f75642e61736b7065726d697373696f6e5f102c636f6d2e6170706c652e69636c6f75642d636f6e7461696e65722e636f6d2e6170706c652e696d6167656e745f100f636f6d2e6170706c652e70617373645f1028636f6d2e6170706c652e69636c6f75642e666d69702e766f696365617373697374616e7473796e635f1033636f6d2e6170706c652e69636c6f75642d636f6e7461696e65722e636f6d2e6170706c652e736972696b6e6f776c65646765645f1017636f6d2e6170706c652e69646d73617574686167656e745f102d636f6d2e6170706c652e69636c6f75642d636f6e7461696e65722e636f6d2e6170706c652e61766174617273645f1016636f6d2e6170706c652e616d736163636f756e747364000800150018001b001e0020002200250026002a007700a800d901000102010d01260156019201ac01c101dc01f8022d0267027d029502aa02c002fb03350350037f039103bc03f2040c043c0000000000000201000000000000002600000000000000000000000000000455".fromHex(), TOPIC, UUID.randomUUID())
        //handler.sendData("62706c6973743030d60102030405060708090a0b0c51745161527047516351655274484f1020649a715d12ce9e6482a560d44d7fac4589747fe52ae9986fd16bbfcee5a4ce5b10005f102446334630323632442d393230452d343635362d383832322d443034453641384635433639100c5a70726f64756374696f6e4f1014998c5d4c6f0bb047fc827e799bb288562a619642081517191c1e202346486f717c0000000000000101000000000000000d00000000000000000000000000000093".fromHex(), TOPIC, UUID.randomUUID())
    }

    private fun send(dict: BPDict, handler: AlloyHandler) {
        Log.d(TAG, "sending dict: $dict")
        handler.sendData(dict.renderAsTopLevelObject(), TOPIC, UUID.randomUUID())
    }
}