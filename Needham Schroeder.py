__author__ = 'dkay'
#! /usr/bin/python
import socket
import sys
import json
import random, base64
from Crypto.Cipher import ARC4
import struct

def hextranslate(s):
        res = ""
        for i in range(len(s)/2):
                realIdx = i*2
                res = res + chr(int(s[realIdx:realIdx+2],16))
        return res

key = 'ebb018bda209debbc45e7700dc0e99b5'
key_bin =  hextranslate(key)


def get_secret(blob, session_key):
        enc = ARC4.new(session_key)

        blob = "\0\0\0" + chr(len(blob)) + blob
        sock1=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address1 = (('localhost', 5453))
        sock1.connect(server_address1)
        sock1.sendall(blob)

        l = struct.unpack('>I', sock1.recv(4))[0]
        serv_reply = json.loads(enc.encrypt(sock1.recv(l)))

        serv_reply['nonce'] = int(serv_reply['nonce']) - 1
        secret_msg11 = enc.encrypt(json.dumps(serv_reply))
        secret_msg22 ='\0\0\0' + chr(len(secret_msg11)) + secret_msg11
        sock1.sendall(secret_msg22)
        l = struct.unpack('>I', sock1.recv(4))[0]
        msg = json.loads(enc.encrypt(sock1.recv(l)))
        print "secret:", msg['secret']

try:
        needham = ['secret', 'stolen_secret']

        for method in needham:
                if method == 'secret':
                        enc_server = ARC4.new(key_bin)
                        sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        server_address = (('localhost', 5452))
                        sock.connect(server_address)
                        # Send data
                        message = '\0\0\0G{"client_id": "tranquilsection", "server_id": "secret", "nonce": 56646}'
                        sock.sendall(message)
                        l = struct.unpack('>I', sock.recv(4))[0]
                        data = json.loads(enc_server.encrypt(sock.recv(l)))
                        sock.close()
                        session_key = base64.b64decode(data['session_key'])
                        blob = base64.b64decode(data['blob'])
                else:
                        f = open('/home/network-auth/blob', 'r')
                        blob = f.read()
                        f.close()
                        f = open('/home/network-auth/key', 'r')
                        session_key = f.read()
                        f.close()

                get_secret(blob, session_key)

except socket.error, e:
        print "Connection error: %s" % e
        #sys.exit(1)
finally:
        print >>sys.stderr, 'closing socket'
        sock.close()