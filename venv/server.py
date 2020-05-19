import socket
import threading
from datetime import datetime
import time
import re

# SERVER CONSTANTS
PORT = 1337
# Since this is run locally, I can use this to get my local ip address
SERVER_IP = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER_IP, PORT)
# Number of bytes for the incoming headers
HEADER = 8
FORMAT = 'utf-8'
# SOCKET VARIABLE
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(ADDR)

# READ CONFIG FOR CONSTANT VALUES
config = open("opt.config", "r")

lines = config.readlines()
for line in lines:
    if (line.startswith("MAX_PACKETS")):
        MAX_PACKETS = int(line.replace("MAX_PACKETS : ", ""))

config.close()

def log(conn, str):
    # "a" for append
    log = open("handshakes.log", "a")
    log.write(f"[{conn}] {datetime.now()} {str}\n")
    log.close()

def start_server():
    # Listen on the server socket
    server_socket.listen()
    print(f"{datetime.now()} [LISTENING] Server is listening on {SERVER_IP}")
    while True:
        conn, addr = server_socket.accept()
        # Receive first message from client
        client_request_msg = receive_msg(conn)
        log(addr, client_request_msg)

        if client_request_msg.startswith("com-0") and valid_IP(client_request_msg.replace("com-0 ", "")):
            # Send accept message if it's not / Handshake step 2
            reply_message = f"com-0 accept {SERVER_IP}"
            send(conn, reply_message)
            # Log handshake step 2
            log(ADDR, reply_message)
            client_reply_message = receive_msg(conn)
            # Log handshake step 3
            log(addr, client_reply_message)
            print(f"[CLIENT]: {client_reply_message}")
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()
            # Minus 1 because of main thread
            print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")
        else:
            # Send deny message if it is not correct IP / Handshake step 2
            reply_message = f"com-0 deny {SERVER_IP}"
            send(conn, reply_message)
            # Log handshake step 1
            log(ADDR, reply_message)
            print(f"[CLIENT]: {receive_msg(conn)}")

def valid_IP(string):
    try:
        # Check for valid IP address
        socket.inet_aton(string)
        return True
    except socket.error:
        return False

def send(conn, msg):
    # Define a new variable and encode it to bytes with given FORMAT constant
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    conn.send(send_length)
    conn.send(message)
    LAST_SENT_MESSAGE_TIME = datetime.now()

def receive_msg(conn):
    # Define a variable from the received header, which must be equal (in bytes) to the HEADER constant
    # Decode the received bytestream with the defined FORMAT constant
    msg_length = conn.recv(HEADER).decode(FORMAT)
    # Checks not null (if msg_length is not null)
    if msg_length:
        # Set the msg_length variable equal to int typecast of the received (and decoded) bytes.
        msg_length = int(msg_length)
        return conn.recv(msg_length).decode(FORMAT)

def handle_client(conn, addr):
    msg_count = 0
    print(f"{threading.currentThread()} started")
    print(f"{datetime.now()} [NEW CONNECTION] {addr} connected.")

    # Start main messaging loop
    while True:
        # Reset the socket timeout to 4 seconds, at the beginning of each loop.
        # If no message is received within time, connection is timed out.
        conn.settimeout(4)
        try:
            msg = receive_msg(conn)
            # If the received message does not match the tolerance disconnect reply
            # or the heartbeat message "con-h 0x00"
            # then we print to console.
            if msg != "con-res 0xFF" and msg != "con-h 0x00":
                print(f"[{addr}] {msg}")
                # If the received message count minus the last sent message is not 1, then raise exception
                # I use re.search to look between the two substrings "msg-" and "=" for the count
                received_msg_count = int(re.search('msg-(.*)=', msg).group(1))
                if received_msg_count - msg_count != 1 and received_msg_count != 0 and received_msg_count !=1:
                    raise ConnectionRefusedError
                # Set the new message count to the received plus 1
                msg_count = received_msg_count + 1
                
                send(conn, f"res-{msg_count}=I am server")

        # This code is then run in the case of a timeout
        except socket.timeout:
            send(conn, "con-res 0xFE")
            receive_msg(conn)
            print(f"{datetime.now()} [{addr}] was disconnected due to inactivity")
            break
        # This code is run if the client terminates the connection
        except ConnectionResetError:
            print(f"{datetime.now()} [{addr}] terminated the connection")
            break
        except ConnectionRefusedError:
            send(conn, "con-res 0xFE")
            print(f"{datetime.now()} [{addr}] sent illegal message count")
            break

        # Making sure the thread doesn't handle more than MAX_PACKETS per sec
        time.sleep(1/MAX_PACKETS)

start_server()