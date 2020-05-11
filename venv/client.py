import socket
from datetime import datetime
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# CLIENT CONSTANTS
SERVER = socket.gethostbyname(socket.gethostname())
PORT = 1337
ADDR = (SERVER, PORT)
HEADER = 8
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "con-res 0xFE"
DDOS_MESSAGE = "can you handle this?"
LAST_MESSAGE_TIME = datetime.now()

# READ CONFIG FOR CONSTANT VALUES
config = open("opt.config", "r")

KEEP_ALIVE = False
if config.readline().replace("KEEP_ALIVE : ","").strip() == "True":
    KEEP_ALIVE = True

DDOS_ACTIVE = False
if config.readline().replace("DDOS_ACTIVE : ","").strip() == "True":
    DDOS_ACTIVE = True

DDOS_AMOUNT = int(config.readline().replace("DDOS_AMOUNT : ", ""))

config.close()

# SOCKET VARIABLE
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def send(msg):
    # Define a new variable and encode it to bytes with given FORMAT constant
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    client.send(send_length)
    client.send(message)
    LAST_MESSAGE_TIME = datetime.now()

def receive_msg():
    # Define a variable from the received header, which must be equal (in bytes) to the HEADER constant
    # Decode the received bytestream with the defined FORMAT constant
    msg_length = client.recv(HEADER).decode(FORMAT)
    # Checks not null (if msg_length is not null)
    if msg_length:
        # Set the msg_length variable equal to int typecast of the received (and decoded) bytes.
        msg_length = int(msg_length)
        return client.recv(msg_length).decode(FORMAT)

def listen():
    while True:
        try:
            msg = receive_msg()
        except ConnectionResetError:
            break
        if msg == DISCONNECT_MESSAGE:
            # Protocol response to disconnect
            send("con-res 0xFF")
            client.close()
            break
        print(msg)
        # Simply for performance
        time.sleep(0.1)

def talk():
    global LAST_MESSAGE_TIME
    while True:
        print("[INPUT]:")
        msg = input()
        send(msg)
        LAST_MESSAGE_TIME = datetime.now()

def heartbeat():
    global LAST_MESSAGE_TIME
    while KEEP_ALIVE:
        # Checks if time since last message is more than 3 seconds
        time_since_last_message = datetime.now() - LAST_MESSAGE_TIME
        if time_since_last_message.total_seconds() > 3:
            try:
                send("con-h 0x00")
                LAST_MESSAGE_TIME = datetime.now()
            except ConnectionResetError:
                print("Lost connection to server")
                break
        # Simply for performance
        time.sleep(0.1)

def DDOS():
    while DDOS_ACTIVE:
        send(DDOS_MESSAGE)
        time.sleep(1/DDOS_AMOUNT)

# Start of Client
def connect_to_server():
    # Client tries to connect to server
    # If connection is refused, it tries again 1 second later
    while True:
        print(f"Attempting to connect to {SERVER} on port {PORT}")
        try:
            client.connect(ADDR)
            print("Connected to server socket")

            # NORMAL CONNECTION
            init_handshake()

            # "HACK" CONNECTION
            # bypass_handshake()
            break
        except ConnectionRefusedError:
            print(f"Connection was refused, server may be down or on a different address")
            print("Trying again in 1 sec...")
            time.sleep(1)

# Asks server if the client ip can join
def init_handshake():
    # Handshake step 1
    send(socket.gethostbyname(socket.gethostname()))
    print(f"Sending request to join from [{socket.gethostbyname(socket.gethostname())}]")
    reply_msg = receive_msg()
    print(f"[SERVER] {reply_msg}")
    if reply_msg.__contains__("accept"):
        # Handshake step 3
        send("accept")
        listen_thread = threading.Thread(target=listen).start()
        heartbeat_thread = threading.Thread(target=heartbeat).start()
        ddos_thread = threading.Thread(target=DDOS).start()
        talk()

    elif reply_msg.__contains__("deny"):
        # Handshake step 3
        send("deny")
        print("Connection denied")
        client.close()

# Doesn't ask if ip can join. Just sends "accept"
def bypass_handshake():
    send("accept")
    listen_thread = threading.Thread(target=listen).start()
    heartbeat_thread = threading.Thread(target=heartbeat).start()
    ddos_thread = threading.Thread(target=DDOS).start()
    talk()

connect_to_server()