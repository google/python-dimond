# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Contains code derived from python-tikteck,
# Copyright 2016 Matthew Garrett <mjg59@srcf.ucam.org>

import random
import threading
import time

from bluepy import btle
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def hex_to_str(hex_str):
    return str(bytearray([int(n, 16) for n in hex_str]))

def encrypt(key, data):
  k = AES.new(bytes(reversed(key)), AES.MODE_ECB)
  data = reversed(list(k.encrypt(bytes(reversed(data)))))
  rev = []
  for d in data:
    rev.append(d)
  return rev
 
def generate_sk(name, password, data1, data2):
  name = name.ljust(16, chr(0))
  password = password.ljust(16, chr(0))
  key = [ord(a) ^ ord(b) for a,b in zip(name,password)]
  data = data1[0:8]
  data += data2[0:8]
  return encrypt(key, data)

def key_encrypt(name, password, key):
  name = name.ljust(16, chr(0))
  password = password.ljust(16, chr(0))
  data = [ord(a) ^ ord(b) for a,b in zip(name,password)]
  return encrypt(key, data)

def encrypt_packet(sk, address, packet):
    auth_nonce = [address[0], address[1], address[2], address[3], 0x01,
                  packet[0], packet[1], packet[2], 15, 0, 0, 0, 0, 0, 0, 0]

    authenticator = encrypt(sk, auth_nonce)

    for i in range(15):
      authenticator[i] = authenticator[i] ^ packet[i+5]

    mac = encrypt(sk, authenticator)

    for i in range(2):
       packet[i+3] = mac[i]

    iv = [0, address[0], address[1], address[2], address[3], 0x01, packet[0],
          packet[1], packet[2], 0, 0, 0, 0, 0, 0, 0]

    temp_buffer = encrypt(sk, iv)
    for i in range(15):
        packet[i+5] ^= temp_buffer[i]

    return packet

def decrypt_packet(sk, address, packet):
    iv = [address[0], address[1], address[2], packet[0], packet[1], packet[2],
          packet[3], packet[4], 0, 0, 0, 0, 0, 0, 0, 0] 
    plaintext = [0] + iv[0:15]

    result = encrypt(sk, plaintext)

    for i in range(len(packet)-7):
      packet[i+7] ^= result[i]

    return packet

class Notification(btle.DefaultDelegate):
    def __init__(self, link, callback):
        btle.DefaultDelegate.__init__(self)
        self.link = link
        self.callback = callback

    def handleNotification(self, cHandle, data):
      data = list(data)
      decrypted = decrypt_packet(self.link.sk, self.link.macdata, data)
      self.callback(self.link.mesh, decrypted)

class dimond:
  def __init__(self, vendor, mac, name, password, mesh=None, callback=None):
    self.vendor = vendor
    self.mac = mac
    self.macarray = mac.split(':')
    self.name = name
    self.password = password
    self.callback = callback
    self.mesh = mesh
    self.packet_count = random.randrange(0xffff)
    self.macdata = [int(self.macarray[5], 16), int(self.macarray[4], 16), int(self.macarray[3], 16), int(self.macarray[2], 16), int(self.macarray[1], 16), int(self.macarray[0], 16)]

  def set_sk(self, sk):
    self.sk = sk

  def connect(self):
    self.device = btle.Peripheral(self.mac, addrType=btle.ADDR_TYPE_PUBLIC)
    self.notification = self.device.getCharacteristics(uuid="00010203-0405-0607-0809-0a0b0c0d1911")[0]
    self.control = self.device.getCharacteristics(uuid="00010203-0405-0607-0809-0a0b0c0d1912")[0]
    self.pairing = self.device.getCharacteristics(uuid="00010203-0405-0607-0809-0a0b0c0d1914")[0]

    data = [0] * 16
    random_data = get_random_bytes(8)
    for i in range(8):
      data[i] = random_data[i]
    enc_data = key_encrypt(self.name, self.password, data)
    packet = [0x0c]
    packet += data[0:8]
    packet += enc_data[0:8]
    try:
      self.pairing.write(bytes(packet), withResponse=True)
      time.sleep(0.3)
      data2 = self.pairing.read()
    except:
      raise Exception("Unable to connect")

    self.sk = generate_sk(self.name, self.password, data[0:8], data2[1:9])

    if self.callback is not None:
      self.device.setDelegate(Notification(self, self.callback))
      self.notification.write(bytes([0x1]), withResponse=True)
      thread = threading.Thread(target=self.wait_for_notifications)
      thread.daemon = True
      thread.start()

  def wait_for_notifications(self):
      while True:
          try:
            self.device.waitForNotifications(-1)
          except btle.BTLEInternalError:
            # If we get the response to a write then we'll break
            pass

  def send_packet(self, target, command, data):
    packet = [0] * 20
    packet[0] = self.packet_count & 0xff
    packet[1] = self.packet_count >> 8 & 0xff
    packet[5] = target & 0xff
    packet[6] = (target >> 8) & 0xff
    packet[7] = command
    packet[8] = self.vendor & 0xff
    packet[9] = (self.vendor >> 8) & 0xff
    for i in range(len(data)):
      packet[10 + i] = data[i]
    enc_packet = encrypt_packet(self.sk, self.macdata, packet)
    self.packet_count += 1
    if self.packet_count > 65535:
      self.packet_count = 1

    # BLE connections may not be stable. Spend up to 10 seconds trying to
    # reconnect before giving up.
    initial = time.time()
    while True:
      if time.time() - initial >= 10:
        raise Exception("Unable to connect")
      try:
        response = self.control.write(bytes(enc_packet))
        break
      except:
        self.connect()
