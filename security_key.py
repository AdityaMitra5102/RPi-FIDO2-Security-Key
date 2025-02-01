#!/usr/bin/python3

############################### Key Management ################################
import os
import uuid
import cbor2

file_path="/etc/fido2_security_key/keys.secret"

current_keys={}

while True:
    print("Reading crypto file")
    try:
        if not os.path.exists(file_path):
            empty_keys={}
            with open(file_path,'wb') as file:
                x=cbor2.dumps(empty_keys)
                file.write(x)


        with open(file_path,'rb') as file:
            cbin=file.read()
            current_keys=cbor2.loads(cbin)

        break
    except:
        pass

print('Keys loaded')

def gen_keys(rpid, userid, userentity):
    secret=str(uuid.uuid4())
    pvtkey, _ =genCryptoKeys(secret)
    credid=uuid.uuid4().bytes+'_cryptane'.encode()
    if rpid in current_keys:
        current_rp=current_keys[rpid]
        for key in current_rp:
            cred=current_rp[key]
            if cred['userid']==userid:
                credid=key

    key={}
    key[credid]={}
    key[credid]['pvtkey']=pvtkey
    key[credid]['userid']=userid
    key[credid]['userentity']=userentity
    keyentity={}
    keyentity['id']=credid
    keyentity['type']='public-key'
    key[credid]['publickeyentity']=keyentity
    if rpid not in current_keys:
        current_keys[rpid]={}
    current_keys[rpid].update(key)
    file=open(file_path, 'wb')
    x=cbor2.dumps(current_keys)
    file.write(x)
    file.close()
    return credid, pvtkey
    
def check_key_exists(rpid, cred_id):
    return rpid in current_keys and cred_id in current_keys[rpid]

def check_key_entity_exists(rpid, entity):
    return check_key_exists(rpid, entity['id'])

def get_key(rpid, cred_id):
    if not check_key_exists(rpid, cred_id):
        return None
    return current_keys[rpid][cred_id]

def get_all_keys(rpid):
    if rpid in current_keys:
        return current_keys[rpid]
    return None
    
def get_cred_entity(rpid, cred_id):
    if not check_key_exists(rpid, cred_id):
        return None
    return current_keys[rpid][cred_id]['publickeyentity']

############################### Cryptographic Operations ######################
from hashlib import sha256
from ecdsa import SigningKey, VerifyingKey, NIST256p
from cryptography import x509 
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.backends import default_backend
import datetime



def genCryptoKeys(secret_string):
    hash_of_secret = sha256(secret_string.encode()).digest()
    private_key = SigningKey.from_string(hash_of_secret[:32], curve=NIST256p)
    public_key = private_key.get_verifying_key()
    pvtkeystr= private_key.to_string().hex()
    pubkeystr= public_key.to_string().hex()
    return pvtkeystr, pubkeystr

def to_cose_key(pvtkey):
    private_key_bytes = bytes.fromhex(pvtkey)
    private_key = SigningKey.from_string(private_key_bytes, curve=NIST256p)
    public_key = private_key.get_verifying_key()
    pubkeystr= public_key.to_string().hex()
    public_key_bytes=bytes.fromhex(pubkeystr)
    x = public_key_bytes[:32]
    y = public_key_bytes[32:]
    cose_key= {
        1:2,
        3:-7,
        -1:1,
        -2:x,
        -3:y,
    }
    cose_encoded=cbor2.dumps(cose_key)
    return cose_encoded

def get_algo():
    return -7

def sign_challenge(pvtkey, challenge):
    private_key_bytes = bytes.fromhex(pvtkey)
    private_key = SigningKey.from_string(private_key_bytes, curve=NIST256p)
    private_key_bytes=private_key.to_der()    
    private_key = load_der_private_key(private_key_bytes, password=None, backend=default_backend())
    signature = private_key.sign(
        challenge,
        ec.ECDSA(hashes.SHA256())
    )
    return signature 

def gen_certificate(pvtkey):
    private_key_bytes = bytes.fromhex(pvtkey)
    private_key = SigningKey.from_string(private_key_bytes, curve=NIST256p)
    private_key_bytes=private_key.to_der()    
    private_key = load_der_private_key(private_key_bytes, password=None, backend=default_backend())
    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"WB"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Kolkata"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"AdityaMitra"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"example.com"),
    ])
    builder = builder.subject_name(name)
    builder = builder.issuer_name(name)
    builder = builder.public_key(public_key)
    builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(days=1))
    builder = builder.not_valid_after(datetime.datetime.today() + datetime.timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    return cert_der

def hash_data(data):
    return sha256(data).digest()

############################### Authenticator API #############################


aaguid_str='4d41190c-7beb-4a84-8018-adf265a6352d'


def authenticatorGetInfo():
    authenticatorInfo={}
    authenticatorInfo[1]=['FIDO_2_0', 'FIDO_2_1_PRE']
    authenticatorInfo[2]=['credProtect']
    authenticatorInfo[3]=uuid.UUID(aaguid_str).bytes
    options={}
    options['rk']=False
    options['plat']=False
    options['up']=True
    options['clientPin']=False
    options['uv']=True
    authenticatorInfo[4]=options
    authenticatorInfo[5]=1200
    authenticatorInfo[6]=[1]
    authenticatorInfo[7]=8
    authenticatorInfo[8]=128
    authenticatorInfo[9]=['usb']
    authenticatorInfo[10]=[{'alg': -8, 'type': 'public-key'}]
    return authenticatorInfo, 0

def authenticatorMakeCredential(payload):
    clientDataHash=payload[1]
    rp=payload[2]
    user=payload[3]
    pubKeyCredParams=payload[4]

    userid=user['id']

    rpid=rp['id']

    if 5 in payload:
        excludeList=payload[5]
        for exclude in excludeList:
            if check_key_entity_exists(rpid, exclude):
                return '', 0x19
    

    
    rpidhash=hash_data(rpid.encode())
    
    cred_id, pvtkey=gen_keys(rpid, userid, user)
    
    flags=(0x45).to_bytes(1,'big')
    signCount=(4).to_bytes(4,'big')

    aaguid=uuid.UUID(aaguid_str).bytes
    credentialIdLength=(len(cred_id)).to_bytes(2, 'big')
    credentialId=cred_id
    credentialPublicKey=to_cose_key(pvtkey)

    attestedCredendialData=aaguid+credentialIdLength+credentialId+credentialPublicKey

    authData=rpidhash+flags+signCount+attestedCredendialData

    fmt='packed'

    tosign=authData+clientDataHash
    attstmt={}
    attstmt['alg']=get_algo()
    attstmt['sig']=sign_challenge(pvtkey, tosign)
    attstmt['x5c']=[gen_certificate(pvtkey)]

    attestationobj={}
    attestationobj[1]=fmt
    attestationobj[2]=authData
    
    attestationobj[3]=attstmt

    return attestationobj, 0

signatures=[]


assertptr=0
assertiontime=0

def authenticatorGetAssertion(payload):
    global signatures, assertiontime, assertptr
    
    signatures=[]
    signkeys=[]
    signum=0
    rpid=payload[1]
    clientDataHash=payload[2]
    allowList=[]
    if 3 in payload:
        allowList=payload[3]

    rpidhash=hash_data(rpid.encode())
    flags=(0x5).to_bytes(1, 'big')
    signCount=(4).to_bytes(4,'big')

    authdata=rpidhash+flags+signCount
    tosign=authdata+clientDataHash

    if allowList ==[]:
        all_keys=get_all_keys(rpid)
        
        for key in all_keys:
            allowList.append(all_keys[key]['publickeyentity'])

    else:
        finlist=[]
        for cred in allowList:
            if check_key_entity_exists(rpid, cred):
                finlist.append(cred)
        allowList=finlist

    numberOfCredentials=len(allowList)

    if numberOfCredentials==0:
        assertptr=0
        assertiontime=0
        return '', 0x2e

    c=0
    for cred in allowList:
        credid=cred['id']
        key=get_key(rpid, credid)
        pvtkey=key['pvtkey']
        sig=sign_challenge(pvtkey, tosign)
        user=key['userentity']

        assertobj={}
        assertobj[1]=cred
        assertobj[2]=authdata
        assertobj[3]=sig
        assertobj[4]=user
        if c==0:
            assertobj[5]=numberOfCredentials
        c=c+1
        signatures.append(assertobj)

    assertiontime=int(time.time())
    assertptr=1
    return signatures[0],0

def authenticatorGetNextAssertion():
    global signatures, assertiontime, assertptr
    if assertptr==0 or assertptr>len(signatures) or int(time.time())-assertiontime>30 :
        assertptr=0
        signatures=[]
        assertiontime=0
        return '',0x30

    assertiontime=int(time.time())
    sig=signatures[assertptr]
    assertptr=assertptr+1
    return sig, 0



############################## CTAP2 #########################################
full_data={}

def CTAPHID_CBOR(channel, payload):
    command=0x10
    cbor_command=payload[0]
    cbor_command_bytes=payload[0:1]
    show(cbor_command_bytes, 'CBOR Command')
    cbor_payload=payload[1:]
    success=0
    if cbor_command==0x04:
        reply_payload, success=authenticatorGetInfo()
    if cbor_command==0x01:
        reply_payload, success=authenticatorMakeCredential(cbor2.loads(cbor_payload))
    if cbor_command==0x02:
        reply_payload, success=authenticatorGetAssertion(cbor2.loads(cbor_payload))
    if cbor_command==0x08:
        reply_payload, success=authenticatorGetNextAssertion()

    if success==0:
        reply=(0).to_bytes(1,'big')
        reply=reply+cbor2.dumps(reply_payload)
        bcnt=len(reply)
        to_send=preprocess_send_data(channel, command, bcnt, reply)
        send_data(to_send)
    else:
        reply=success.to_bytes(1,'big')
        bcnt=len(reply)
        to_send=preprocess_send_data(channel, command, bcnt, reply)


def make_channel_id():
    import random
    value=random.randint(1, 0xfffffffe)
    return value.to_bytes(4, 'big')

def CTAPHID_INIT(channel, payload):
    if channel==0xffffffff:
        channel_new=make_channel_id()
    else:
        channel_new=channel
        if channel in full_data:
            full_data.pop(channel)
    command=0x06
    bcnt=17
    data=payload 
    data=data+channel_new 
    data=data+(2).to_bytes(1, 'big') 
    data=data+(1).to_bytes(1, 'big') 
    data=data+(0).to_bytes(1, 'big') 
    data=data+(1).to_bytes(1, 'big') 
    data=data+(13).to_bytes(1, 'big') 

    to_send=preprocess_send_data(channel, command, bcnt, data)
    send_data(to_send)

def CTAPHID_PING(channel, payload):
    command=0x01
    bcnt=len(payload)
    to_send=preprocess_send_data(channel, command, bcnt, payload)
    send_data(to_send)

def CTAPHID_CANCEL(channel, payload):
    command=0x11
    bcnt=0
    to_send=preprocess_send_data(channel, command, bcnt, b'')
    send_data(to_send)

def CTAPHID_WINK(channel, payload):
    command=0x08
    bcnt=0
    print("Authenticator wink")
    to_send=preprocess_send_data(channel, command, bcnt, b'')
    send_data(to_send)

def CTAPHID_ERROR(channel, error_code):
    command=0x3f
    bcnt=1
    data=(error_code).to_bytes(1, 'big')
    to_send=preprocess_send_data(channel, command, bcnt, data)
    send_data(to_send)

def CTAPHID_KEEPALIVE(channel, status):
    command=0x3b
    bcnt=1
    data=status.to_bytes(1, 'big')
    to_send=preprocess_send_data(channel, command, bcnt, data)
    send_data(to_send)

import threading

task_thread = None
stop_event = threading.Event()

import time
def send_keepalive(channel, payload):
    global task_thread, stop_event
    while not stop_event.is_set():
        time.sleep(0.08)
        CTAPHID_KEEPALIVE(channel, payload)
        


def start_keepalive(channel, payload):
    global task_thread, stop_event
    if task_thread and task_thread.is_alive():
        return
    stop_event.clear()
    task_thread = threading.Thread(target=send_keepalive, args=(channel, payload))
    task_thread.start()

def stop_keepalive():
    global task_thread, stop_event
    if task_thread and task_thread.is_alive():
        stop_event.set()
        task_thread.join()
    
def run_commands(channel, command, bcnt, payload):
    if command==0x06:
        CTAPHID_INIT(channel, payload)
    if command==0x01:
        CTAPHID_PING(channel, payload)
    if command==0x11:
        CTAPHID_CANCEL(channel, payload)
    if command==0x08:
        CTAPHID_WINK(channel, payload)
    if command==0x10:
        CTAPHID_CBOR(channel, payload)


########################################### Low Level Implementation #######################################

def process_packet(packet):
    channel=packet[0:4]
    if channel.hex()=='00000000':
        channel=bytes.fromhex('ffffffff')
    cstr=channel.hex()
    show(channel, 'channel')
    byte4=packet[4]
    if byte4>0x7f:
        print("Command packet")
        command=packet[4] & 0x7f
        command=command.to_bytes(1, 'big')
        show(command, 'CMD')
        bcnt_bytes=packet[5:7]
        show(bcnt_bytes, "BCNT")
        bcnt=int.from_bytes(bcnt_bytes, 'big')
        print("Payload size ", bcnt)
        num_pack=calc_num_packets(bcnt)

        seqnum=-1
        payload=packet[7:]
        
        full_data[cstr]=[None]*(num_pack+2)
        full_data[cstr][0]=command
        full_data[cstr][1]=bcnt

    else:
        print("Sequence packet")
        seq=packet[4:5]
        show(seq, "SEQ")
        seqnum=packet[4]
        payload=packet[5:]
    
    seqnum=seqnum+3
    full_data[cstr][seqnum]=payload
    process_transcation(channel)



def show(packet, dat=""):
    print(dat, " "," ".join(packet.hex()[i:i+2] for i in range(0, len(packet.hex()), 2)),)
    print()

def show_string(packet):
    print("Showing packet string ",packet.decode('utf-8', 'replace'))

def preprocess_send_data(channel, command, bcnt, payload):
    show(payload, 'Pre process')
    num_pack=calc_num_packets(bcnt)
    first_packet_size=64-7
    other_packet_size=64-5
    packet_list=[None]*num_pack
    if (bcnt<=first_packet_size):
        packet_list[0]=payload
    else:
        packet_list[0]=payload[:first_packet_size]
        payload=payload[first_packet_size:]
        i=1
        while len(payload)>0:
            packet_list[i]=payload[:other_packet_size]
            payload=payload[other_packet_size:]
            i=i+1

    last_pack=num_pack-1
    last_size=other_packet_size
    if last_pack==0:
        last_size=first_packet_size
    
    if(len(packet_list[last_pack])<last_size):
        pad=last_size-len(packet_list[last_pack])
        packet_list[last_pack]=packet_list[last_pack]+b'\x00'*pad

    full_packets=[None]*num_pack
    first_packet=channel
    first_packet=first_packet+(command | 0x80).to_bytes(1, 'big')
    first_packet=first_packet+bcnt.to_bytes(2, 'big')
    first_packet=first_packet+packet_list[0]
    full_packets[0]=first_packet

    for i in range(1, len(packet_list)):
        packet=channel
        packet=packet+(i-1).to_bytes(1, 'big')
        packet=packet+packet_list[i]
        full_packets[i]=packet

    return full_packets

def send_data(preprocessed_data):
    indicator_on()
    for x in preprocessed_data:
        show(x, "Sending packet")
        port.write(x)
        time.sleep(0.001)
    indicator_off()


def calc_num_packets(bcnt):
    first_packet_size=64-7
    other_packet_size=64-5
    num_pack=1
    bcnt=bcnt-first_packet_size
    if bcnt<0:
        bcnt=0
    num_pack=num_pack+(bcnt // other_packet_size)
    bcnt=bcnt % other_packet_size
    if bcnt>0:
        num_pack=num_pack+1
        bcnt=0
    return num_pack

def process_transcation(channel):
    cstr=channel.hex()
    data=full_data[cstr]
    if None in data:
        return 
    payload=data[2]
    i=3
    while i<len(data):
        payload=payload+data[i]
        i=i+1
    bcnt=data[1]
    payload=payload[:bcnt]
    command=int.from_bytes(data[0], 'big')
    run_commands(channel, command, bcnt, payload)

####################GPIO Pins##################################
import RPi.GPIO as GPIO

led=16
GPIO.setmode(GPIO.BCM)
GPIO.setup(led, GPIO.OUT)

def indicator_on():
    GPIO.output(led, GPIO.HIGH)

def indicator_off():
    GPIO.output(led, GPIO.LOW)

############################Initializing port #########################

port=None
portname='/dev/hidg0'
while True:
    try:
        port=open(portname, 'rb+')
        print('Port opened')
        break
    except PermissionError as e:
        time.sleep(1)
    except:
        time.sleep(1)

indicator_on()
time.sleep(2)
indicator_off()

###################Runner code####################

if __name__=='__main__':
    while True:
        packet=port.read(64)
        if packet==None:
            continue
        show(packet, 'Full packet')
        process_packet(packet)