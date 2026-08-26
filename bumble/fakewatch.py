# Copyright 2021-2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import asyncio
import sys
import os
import logging
import struct
import threading
import time
import asyncio

from bumble.device import Device, Connection, AdvertisingData, Peer
from bumble.transport import open_transport_or_link
from bumble.att import ATT_Error, ATT_INSUFFICIENT_ENCRYPTION_ERROR
from bumble.pairing import PairingDelegate as BasePairingDelegate, PairingConfig
from bumble.smp import OobContext
from bumble.crypto import EccKey
from bumble.gatt import (
    Service,
    Characteristic,
    CharacteristicValue,
    Descriptor,
    GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR,
    GATT_MANUFACTURER_NAME_STRING_CHARACTERISTIC,
    GATT_MODEL_NUMBER_STRING_CHARACTERISTIC,
    GATT_DEVICE_INFORMATION_SERVICE,
    GATT_SERVICE_CHANGED_CHARACTERISTIC,
    GATT_GENERIC_ATTRIBUTE_SERVICE,
    GATT_CHARACTERISTIC_EXTENDED_PROPERTIES_DESCRIPTOR

)

from handlers import SeqAckChannelHandler, NRLPHandler, NearbyStubResponder, BTTSHandler

class PairingDelegate(BasePairingDelegate):
    def __init__(
        self,
        nrlp,
        io_capability: BasePairingDelegate.IoCapability = BasePairingDelegate.DISPLAY_OUTPUT_ONLY,
        local_initiator_key_distribution: BasePairingDelegate.KeyDistribution = BasePairingDelegate.DEFAULT_KEY_DISTRIBUTION,
        local_responder_key_distribution: BasePairingDelegate.KeyDistribution = BasePairingDelegate.DEFAULT_KEY_DISTRIBUTION,
    ) -> None:
        self.nrlp = nrlp
        super().__init__(
            io_capability,
            local_initiator_key_distribution,
            local_responder_key_distribution,
        )

    # fallback smp numeric comparison pairing uses hardcoded OOB data for IKEv2 auth
    async def display_number(self, number: int, digits: int = 6) -> None:
        self.nrlp.overrideOOBKey(b"Apple Watch Pairing Bluetooth PIN!")
        self.nrlp.sendBtPIN(number)
        print(f'fallback pairing passcode: {number}')
        

# padded int to hex string conversion
def phex(val, pad=2):
    fstr = "#0" + str(pad+2) + "x"
    return format(val, fstr)

def my_custom_read(connection):
    print('----- READ from', connection)
    return bytes(f'Hello {connection}', 'ascii')


def write_to_void(connection, value):
    print(f'----- WRITE from {connection}: {value}')

def push_receiver(connection, value):
    print(f'----- WRITE to AARS push characteristic from {connection}: {value}')

def nano_receiver(connection, value):
    print(f'----- WRITE to NANO characteristic from {connection}: {value}')


# Hardcode Bluetooth Key Derivation values (ephermeral public key and random value)
key = EccKey.from_private_key_bytes(
    bytes.fromhex("d7c48f3edafe91408b602f87686765814668325d0225830e1fd2b32096bd2017"),
)
oob_config = PairingConfig.OobConfig(OobContext(ecc_key=key, r=bytes.fromhex("3aa261d4f461d69d58d7e02c645abedb")), None, None)

# oob key as formatted in apple magic code to share with WatchWitch for initial IKEv2 auth
shared = oob_config.our_context.share()
oobkey = bytearray()
oobkey.append(0x72)
oobkey.extend(shared.r)
oobkey.append(0x63)
oobkey.extend(shared.c)

ourCid = 3000
nrlp = NRLPHandler(oobkey)

# -----------------------------------------------------------------------------
class Listener(Device.Listener, Connection.Listener):
    def __init__(self, device):
        self.device = device

    def on_connection(self, connection):
        print(f'=== Connected to {connection}')
        connection.listener = self
        #print(f'=== Send Magnet Version packet')
        #connection.send_l2cap_pdu(0x3a, bytearray.fromhex('09050ab3080000'))

    def on_disconnection(self, reason):
        nrlp.disconnect()
        print(f'### Disconnected, reason={reason}')

# -----------------------------------------------------------------------------
async def main() -> None:
    if len(sys.argv) < 3:
        print(
            'Usage: run_gatt_server.py <device-config> <transport-spec> '
            '[<bluetooth-address>]'
        )
        print('example: run_gatt_server.py device1.json usb:0 E1:CA:72:48:C4:E8')
        return

    print('<<< connecting to HCI...')
    async with await open_transport_or_link(sys.argv[2]) as hci_transport:
        print('<<< connected')

        # Create a device to manage the host
        device = Device.from_config_file_with_hci(
            sys.argv[1], hci_transport.source, hci_transport.sink
        )
        device.listener = Listener(device)

        # channels registered for services, elements are [remote_cid, local_cid, sid]
        l2cap_channels = []
        l2cap_sid_lookup = dict()


        def magnet_handler(handle, pdu):
            global ourCid

            we_offer = ["wp.nearby", "com.apple.terminusLink", "com.apple.terminusLink.urgent", "com.apple.ep", "com.apple.BT.TS"]
            connection = device.lookup_connection(handle)
            
            if pdu[0] == 0x09: # version info
                print('----- got version info, replying')
                #connection.send_l2cap_pdu(0x3a, bytearray.fromhex('09050ab3080000')) # watch 5
                connection.send_l2cap_pdu(0x3a, bytearray.fromhex('09050bb3180000')) # watch 7
            elif pdu[0] == 0x90: # version info
                print('----- got DID info, replying')
                connection.send_l2cap_pdu(0x3a, bytearray.fromhex('9008004c004000800e0e00'))
            elif pdu[0] == 0x01: # remote services
                length = int.from_bytes(pdu[1:3], byteorder="little")
                payload = pdu[3:]
                numServices = payload[0]
                services = []
                i = 1
                j = 0
                while j < numServices and i + 10 < len(payload):
                    lng = payload[i]
                    sid = payload[i+1:i+3]
                    flag = payload[i+3]
                    nameLng = int.from_bytes(payload[i+4:i+5], byteorder="big")
                    name = payload[i+5:i+5+nameLng].decode().strip("\x00")
                    trl = payload[-1:] if nameLng + 4 < lng else "00" # trailing byte may be omitted for implicit zero
                    i += lng + 1
                    j += 1
                    print(f"Service {sid.hex()}: {name}, flags: {phex(flag)}, trailer: 0x{trl.hex()}")
                    services.append([sid, name])
                    l2cap_sid_lookup[int.from_bytes(sid, byteorder="little")] = name

                shared = [service for service in services if service[1] in we_offer]
                response = bytearray()
                responseLen = 1 + 2*len(shared)
                response.append(0x02)
                response.extend(responseLen.to_bytes(2, byteorder='little'))
                response.append(len(shared))
                for service in shared:
                    response.extend(service[0])
                print(f'----- replying with shared services: {response.hex()}')
                connection.send_l2cap_pdu(0x3a, response)
            elif pdu[0] == 0x03: # service channel created
                length = int.from_bytes(pdu[1:3], byteorder="little")
                cid = int.from_bytes(pdu[3:5], byteorder="little")
                sid = int.from_bytes(pdu[5:7], byteorder="little")

                print(f'----- channel created for {sid} / {l2cap_sid_lookup[sid]}: {cid}')

                ourCid += 1
                response = bytearray()
                responseLen = 5
                response.append(0x04)
                response.extend(responseLen.to_bytes(2, byteorder='little'))
                response.append(0x00)
                response.extend(sid.to_bytes(2, byteorder='little'))
                response.extend(ourCid.to_bytes(2, byteorder='little'))
                print(f'----- replying with channel accept: {ourCid} {response.hex()}')
                l2cap_channels.append([cid, ourCid, sid])

                connection.send_l2cap_pdu(0x3a, response)

                if l2cap_sid_lookup[sid] == "wp.nearby":
                    nearbyHandler = NearbyStubResponder(connection, cid, sid) 
                    device.l2cap_channel_manager.register_fixed_channel(ourCid, nearbyHandler.receive)
                elif l2cap_sid_lookup[sid] == "com.apple.BT.TS":
                    handler = BTTSHandler()
                    seqAckHandler = SeqAckChannelHandler(connection, cid, sid, handler.receive)
                    device.l2cap_channel_manager.register_fixed_channel(ourCid, seqAckHandler.receive)
                    handler.send(seqAckHandler)
                else:
                    seqAckHandler = SeqAckChannelHandler(connection, cid, sid, misc_handler)                
                    device.l2cap_channel_manager.register_fixed_channel(ourCid, seqAckHandler.receive)

                    # the watch usually initiates the NRLP hello sequence immediately after accepting the channel
                    if l2cap_sid_lookup[sid] == "com.apple.terminusLink":
                        print(f'----- initiating terminus channel with prelude')
                        seqAckHandler.send(nrlp.prelude)
                        nrlp.seqack = seqAckHandler
                        nrlp.sentPrelude = True
                    elif l2cap_sid_lookup[sid] == "com.apple.terminusLink.urgent":
                        print(f'----- initiating terminus channel with prelude')
                        seqAckHandler.send(nrlp.prelude)
                        nrlp.seqack_urgent = seqAckHandler
                        nrlp.sentUrgentPrelude = True
            elif pdu[0] == 0x05: # service added
                length = int.from_bytes(pdu[1:3], byteorder="little")
                sid = int.from_bytes(pdu[3:5], byteorder="little")
                unk1 = pdu[5:6]
                nameLng = int.from_bytes(pdu[6:7], byteorder="little")
                name = pdu[7:7+nameLng].decode().strip("\x00")
                l2cap_sid_lookup[sid] = name
                print(f'----- service added: {sid}: {name}')

                if name in we_offer:
                    response = bytearray()
                    responseLen = 3
                    response.append(0x02)
                    response.extend(responseLen.to_bytes(2, byteorder='little'))
                    response.append(0x01)
                    response.extend(sid.to_bytes(2, byteorder="little"))
                    print(f'----- replying with shared services: {response.hex()}')
                    connection.send_l2cap_pdu(0x3a, response)
            elif pdu[0] == 0x06: # service removed
                length = int.from_bytes(pdu[1:3], byteorder="little")
                sid = int.from_bytes(pdu[3:5], byteorder="little")
                print(f'----- service removed {sid} / {l2cap_sid_lookup[sid]}')
                response = bytearray()
                responseLen = 3
                response.append(0x07)
                response.extend(responseLen.to_bytes(2, byteorder='little'))
                response.extend(sid.to_bytes(2, byteorder="little"))
                response.append(0x00)
                print(f'----- replying with removal accept: {response.hex()}')
                connection.send_l2cap_pdu(0x3a, response)

            else:
                print(f'----- unknown magnet rcv: {pdu.hex()}')

        def misc_handler(seqack, sid, pdu):
            service = l2cap_sid_lookup[sid]
            
            if service == "com.apple.terminusLink":
                if len(pdu) >= 33 and pdu[0] == 0x54 and pdu[1] == 0x45:
                    print(f'----- got terminus prelude {pdu.hex()}')
                    if not nrlp.sentPrelude:
                        print(f'----- replying')
                        seqack.send(nrlp.prelude)
                        nrlp.seqack = seqack
                    print(f'----- starting NRLP handler')

                    if nrlp.pairingCompleted:
                        nrlp.ready_paired()
                    else:
                        nrlp.ready()
                        nrlp.pairingCompleted = True
                else:
                    print(f"got nrlp bytes: {len(pdu)}")
                    nrlp.receive(pdu)
            elif service == "com.apple.terminusLink.urgent":
                if len(pdu) >= 33 and pdu[0] == 0x54 and pdu[1] == 0x45:
                    print(f'----- got terminus urgent prelude {pdu.hex()}')
                    if not nrlp.sentUrgentPrelude:
                        print(f'----- replying')
                        seqack.send(nrlp.prelude)
                        nrlp.seqack_urgent = seqack
                else:
                    print(f"got nrlp urgent bytes: {len(pdu)}")
                    nrlp.receiveUrgent(pdu)
            else:
                print(f'----- {service} RCV: {pdu.hex()}')


        device.l2cap_channel_manager.register_fixed_channel(0x003a, magnet_handler)

        pairing_delegate = PairingDelegate(
            nrlp,
            PairingDelegate.IoCapability.DISPLAY_OUTPUT_ONLY,
            PairingDelegate.KeyDistribution.DISTRIBUTE_ENCRYPTION_KEY | PairingDelegate.KeyDistribution.DISTRIBUTE_IDENTITY_KEY | PairingDelegate.KeyDistribution.DISTRIBUTE_LINK_KEY,
            PairingDelegate.KeyDistribution.DISTRIBUTE_ENCRYPTION_KEY | PairingDelegate.KeyDistribution.DISTRIBUTE_IDENTITY_KEY | PairingDelegate.KeyDistribution.DISTRIBUTE_LINK_KEY
        )

        device.pairing_config_factory = lambda connection: PairingConfig(
            sc=True,
            mitm=True,
            bonding=True,
            oob=oob_config,
            identity_address_type=PairingConfig.AddressType.RANDOM,
            delegate=pairing_delegate,
        )

        # Add services
        
        service_device_info = Service(
            GATT_DEVICE_INFORMATION_SERVICE,
            [
                Characteristic(
                    GATT_MANUFACTURER_NAME_STRING_CHARACTERISTIC,
                    Characteristic.Properties.READ,
                    Characteristic.READABLE,
                    'Apple Inc.',
                ),
                Characteristic(
                    GATT_MODEL_NUMBER_STRING_CHARACTERISTIC,
                    Characteristic.Properties.READ,
                    Characteristic.READABLE,
                    'Watch5,1',
                )
            ]
        )

        RELIABLE_WRITE_ENABLED = struct.pack('<H', 0x01)

        service_aars = Service(
            '9aa4730f-b25c-4cc3-b821-c931559fc196',
            [
                # AARS Device Name
                Characteristic(
                    'e168d473-8efd-4485-a1fd-b25edad4dce2',
                    Characteristic.Properties.READ,
                    Characteristic.READABLE,
                    #bytearray.fromhex('0a085761746368372c3110908602180020152801300038828028'), # Watch7,1 10.x + version info protobuf
                    bytearray.fromhex('0a085761746368352c31108680021801200f28013000'), # Watch5,1 + version info protobuf
                ),
                # AARS Push
                Characteristic(
                    '1f9636e6-ca97-4c30-bc5f-c477d6a6cf32',
                    Characteristic.Properties.WRITE | Characteristic.Properties.EXTENDED_PROPERTIES,
                    Characteristic.WRITEABLE,
                    CharacteristicValue(write=push_receiver),
                    [
                        Descriptor(
                            GATT_CHARACTERISTIC_EXTENDED_PROPERTIES_DESCRIPTOR,
                            Descriptor.READABLE,
                            RELIABLE_WRITE_ENABLED, # reliable write enabled
                        )
                    ],
                ),
                # AARS Nano
                Characteristic(
                    '5f6c6a23-8ac8-400e-810b-017134943460',
                    Characteristic.Properties.WRITE | Characteristic.Properties.READ | Characteristic.Properties.NOTIFY | Characteristic.Properties.EXTENDED_PROPERTIES,
                    Characteristic.WRITEABLE | Characteristic.READABLE,
                    CharacteristicValue(write=nano_receiver),
                    [
                        Descriptor(
                            GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR,
                            Descriptor.READABLE,
                            bytearray.fromhex('0000'),
                        ),
                        Descriptor(
                            GATT_CHARACTERISTIC_EXTENDED_PROPERTIES_DESCRIPTOR,
                            Descriptor.READABLE,
                            RELIABLE_WRITE_ENABLED, # reliable write enabled
                        ),
                    ],
                ),
            ],
        )

        service_continuity = Service(
            'd0611e78-bbb4-4591-a5f8-487910ae4366',
            [
                # Continuity Characteristic
                Characteristic(
                    '8667556c-9a37-4c91-84ed-54ee27d90049',
                    Characteristic.Properties.WRITE | Characteristic.Properties.EXTENDED_PROPERTIES | Characteristic.Properties.NOTIFY,
                    Characteristic.WRITEABLE,
                    CharacteristicValue(write=write_to_void),
                    [
                        Descriptor(
                            GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR,
                            Descriptor.READABLE,
                            bytearray.fromhex('0000'),
                        ),
                        Descriptor(
                            GATT_CHARACTERISTIC_EXTENDED_PROPERTIES_DESCRIPTOR,
                            Descriptor.READABLE,
                            RELIABLE_WRITE_ENABLED, # reliable write enabled
                        ),
                    ],

                ),
            ],
        )

        service_nearby = Service(
            '9fa480e0-4967-4542-9390-d343dc5d04ae',
            [
                # Nearby Characteristic
                Characteristic(
                    'af0badb1-5b99-43cd-917a-a77bc549e3cc',
                    Characteristic.Properties.WRITE | Characteristic.Properties.EXTENDED_PROPERTIES | Characteristic.Properties.NOTIFY,
                    Characteristic.WRITEABLE,
                    CharacteristicValue(write=write_to_void),
                    [
                        Descriptor(
                            GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR,
                            Descriptor.READABLE,
                            bytearray.fromhex('0000'),
                        ),
                        Descriptor(
                            GATT_CHARACTERISTIC_EXTENDED_PROPERTIES_DESCRIPTOR,
                            Descriptor.READABLE,
                            RELIABLE_WRITE_ENABLED, # reliable write enabled
                        ),
                    ],
                ),
            ],
        )

        service_generic_attribute = Service(
            GATT_GENERIC_ATTRIBUTE_SERVICE,
            [
                # Service Changed
                Characteristic(
                    GATT_SERVICE_CHANGED_CHARACTERISTIC,
                    Characteristic.Properties.INDICATE,
                    Characteristic.READABLE,
                    CharacteristicValue(write=write_to_void),
                    [
                        Descriptor(
                            GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR,
                            Descriptor.READABLE,
                            bytearray.fromhex('0000'),
                        )
                    ],
                ),
            ],
        )

        device.add_services([service_device_info, service_generic_attribute, service_aars, service_continuity, service_nearby])

        
        device.advertising_data = bytes(
            AdvertisingData(
                [
                    (
                        AdvertisingData.FLAGS,
                        bytes(
                            [
                                AdvertisingData.LE_GENERAL_DISCOVERABLE_MODE_FLAG
                            ]
                        ),
                    ),
                    (
                        AdvertisingData.COMPLETE_LOCAL_NAME,
                        bytes('70815D01', 'utf-8'),
                    ),
                    (
                        AdvertisingData.COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS,
                        bytearray.fromhex("96c19f5531c921b8c34c5cb20f73a49a"), # AARS service UUID (reversed) only, for some reason?
                    ),
                ]
            )
        )

        # Debug print
        for attribute in device.gatt_server.attributes:
            print(attribute)

        # Get things going
        await device.power_on()

        # Connect to a peer
        if len(sys.argv) > 3:
            target_address = sys.argv[3]
            print(f'=== Connecting to {target_address}...')
            await device.connect(target_address)
        else:
            await device.start_advertising(auto_restart=True)

        await hci_transport.source.wait_for_termination()


# -----------------------------------------------------------------------------
logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
asyncio.run(main())
