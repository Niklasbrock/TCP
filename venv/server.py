import socket
import threading
from datetime import datetime
import time

# SERVER CONSTANTS
PORT = 1337
# Since this is run locally, I can use this to get my local ip address
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
# Number of bytes for the incoming headers
HEADER = 8
FORMAT = 'utf-8'
DISCONNECT_MESSAGE = "con-res 0xFE"
CONNECTED_IP = set()
CONNECTED_SOCKETS = set()
MSG_COUNT = 0
# SOCKET VARIABLE
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(ADDR)

def log(conn, str):
    # "a" for append
    log = open("handshakes.log", "a")
    log.write(f"[{conn}] {datetime.now()} {str}\n")
    log.close()

def start_server():
    # Listen on the server socket
    server_socket.listen()
    print(f"{datetime.now()} [LISTENING] Server is listening on {SERVER}")
    while True:
        conn, addr = server_socket.accept()
        # Receive first message from client
        client_request_msg = receive_msg(conn)
        log(addr, client_request_msg)
        # Check if client IP addr is already connected TODO: doesnt work, loop through set instead.
        if CONNECTED_IP.__contains__(client_request_msg):
            # Send deny message if it is / Handshake step 2
            reply_message = f"com-{MSG_COUNT} deny {addr[0]}"
            send(conn, reply_message)
            # Log handshake step 1
            log(ADDR, reply_message)
            print(f"[CLIENT]: {receive_msg(conn)}")
        else:
            # Send accept message if it's not / Handshake step 2
            reply_message = f"com-{MSG_COUNT} accept {addr[0]}"
            send(conn, reply_message)
            # Log handshake step 2
            log(ADDR, reply_message)
            client_reply_message = receive_msg(conn)
            # Log handshake step 3
            log(addr, client_reply_message)
            print(f"[CLIENT]: {client_reply_message}")
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")


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
    global MSG_COUNT
    print(f"{threading.currentThread()} started")

    # Add IP addr to CONNECTED_IP set
    CONNECTED_IP.add(addr)

    # Add Socket to CONNECTED_SOCKETS set
    CONNECTED_SOCKETS.add(conn)
    print(f"{datetime.now()} [NEW CONNECTION] {addr} connected.")

    # Start main messaging loop
    while True:
        # Reset the socket timeout to 4 seconds, at the beginning of each loop.
        # If no message is received within time, connection is timed out.
        conn.settimeout(4)
        try:
            msg = receive_msg(conn)
        # This code is then run in the case of a timeout
        except socket.timeout:
            send(conn, "You have been kicked due to inactivity")
            send(conn, DISCONNECT_MESSAGE)
            receive_msg(conn)
            CONNECTED_IP.discard(addr)
            CONNECTED_SOCKETS.discard(conn)
            print(f"{datetime.now()} [{addr}] was disconnected due to inactivity")
            break
        # This code is run if the client terminates the connection
        except ConnectionResetError:
            CONNECTED_IP.discard(addr)
            CONNECTED_SOCKETS.discard(conn)
            print(f"{datetime.now()} [{addr}] terminated the connection")
            break

        # If the received message does not match the DISCONNECT_MESSAGE constant
        # or the heartbeat message "con-h 0x00"
        # then we print to console, and send the received message to other connected clients.
        if msg != DISCONNECT_MESSAGE and msg != "con-h 0x00":
            print(f"[{addr}] msg-{MSG_COUNT}={msg}")
            for conns in CONNECTED_SOCKETS:
                # Making sure not to send the message back to the sender.
                if conns != conn:
                    send(conns, f"[{addr}] msg-{MSG_COUNT}={msg}")

        # Incrementing the message count, including the responses from server.
        # Ignoring the heartbeat messages.
        if msg != "con-h 0x00":
            MSG_COUNT += 1
            send(conn, f"res-{MSG_COUNT}=I am server")
            MSG_COUNT += 1

start_server()