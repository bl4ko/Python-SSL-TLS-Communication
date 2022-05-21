import socket
import ssl
import struct
import sys
import threading
import json
import os
from datetime import datetime

PORT = 5432
HEADER_LENGTH = 2
FORMAT = 'utf-8'

def setup_SSL_context(commonName: str) -> ssl.SSLContext:
    """Create SSLContext object with client certs on paths publicKeyPath, privateKeyPath.

    Args:
        publicKeyPath (str): path to the public key file
        privateKeyPath (str): path to the private key file

    Returns:
        ssl.SSLContext: wrapper object with predefined SSL attributes
    """
    try:
        # use only TLS, not SSL
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        # require certificate 
        context.verify_mode = ssl.CERT_REQUIRED
        # Load a private key and Corresponding certificate
        context.load_cert_chain(certfile=f"{commonName}.crt", keyfile=f"{commonName}.key")
        # Load a set of "certification authority" certificates used to validate other peer's 
        # certificates. 
        context.load_verify_locations('server.crt')
        # Set the cipher (encryption method)
        context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
        return context
    except FileNotFoundError:
        print(f">> The certifcate files {commonName}.crt, {commonName}.key were not found.\n>> Please make sure that you have generated your keys using ./cer-gen.sh <commonName> script")
        sys.exit("[System] Exiting ...")


def receive_fixed_length_msg(sock: ssl.SSLSocket, msglen: int) -> bytes: 
    """Read msglen number of bytes from socket and return merged result.

    Args:
        sock (ssl.SSLSocket): socket from which we read
        msglen (int): number of bytes to read

    Raises:
        RuntimeError: Couldn't read from socket

    Returns:
        bytes: bytes read
    """
    message = b''
    while len(message) < msglen:
        # read bytes
        chunk = sock.recv(msglen - len(message))  
        if chunk == b'':
            os._exit(1) # server connection has been broken (exit the program from thread)
        message = message + chunk  
    return message

def receive_message(sock: ssl.SSLSocket) -> dict[str, str]:
    """Read from socket sock, and return string read.

    Args:
        sock (ssl.SSLSocket): socket to be read from

    Returns:
        dict: Message in a dict format read the from socket sock
    """
    # First we read the header 
    header = receive_fixed_length_msg(sock, HEADER_LENGTH)  
    # Convert bytes in header to determine message length
    message_length = struct.unpack("!H", header)[0]  

    message = None
    if message_length > 0:  
        encoded_message = receive_fixed_length_msg(sock, message_length)  
        decoded_message_json = encoded_message.decode(FORMAT)
        message = json.loads(decoded_message_json)
    return message

def curTime() -> str:
    """Returns current time in format Hours:Minutes:Seconds

    Returns:
        str: currenttime (H:M:S)
    """
    return datetime.now().strftime("%H:%M:%S")

def send_message(sock: ssl.SSLSocket, mType: str, mText: str, mTarget: str = None) -> None:
    """Build (depending on given arguments) and send the message to the socket sock.

    Args:
        sock (ssl.SSLSocket): socket to be sent to
        mType (str): Message Type
        mText (str): Message Text (content)
        mTarget (str): Message Target
    """
    message = {
        "mType": mType,
        "mText": mText,
        "mTarget": mTarget,
        "mTime": curTime() 
    }
    # Encode message_body
    json_string = json.dumps(message)
    encoded_message_body = json_string.encode(FORMAT)  

    # Encode message_header
    # first two bytes of a mssage = header (in header we write the length of the data) 
    # metoda pack "!H" : !=network byte order, H=unsigned short
    encoded_message_header = struct.pack("!H", len(encoded_message_body))

    encoded_message = encoded_message_header + encoded_message_body 
    # Send all the data to the sock
    sock.sendall(encoded_message)

# Separete message receiver
def message_receiver():
    while True:
        msg_received = receive_message(sock)
        if len(msg_received) > 0:  # ce obstaja sporocilo
            print(f"[{msg_received['mTime']}] {msg_received['mAuthor']}: {msg_received['mText']}")


# Connect to the server
if __name__ == "__main__": 

    # read user common_name for certificate
    common_name = input("User commonname [] > ") 
    while True:
        if (common_name != ""):
            break
    
    print("[SYSTEM] connecting to chat server ...")
    # setup SSL connection parameters
    my_ssl_ctx = setup_SSL_context(common_name)
    # wrap an existing socket and return an instance of SSLSocket (with parameters set up)
    sock = my_ssl_ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    # Connect to a remote socket at address: "localhost", at port: PORT
    try: 
        sock.connect(("localhost", PORT))
    except ConnectionRefusedError as conn_err:
        sys.exit(conn_err)

    print("[SYSTEM] connected!")

    print("\n-- INFO -------------------------------------------------------------------\n\
    >> To send PUBLIC messages, type a message and hit enter.\n\
    >> To send PRIVATE messages, start a message with @{{username}} {{yourMessage}} and hit enter\n")

    # zazeni message_receiver funkcijo v loceni niti
    thread = threading.Thread(target=message_receiver)
    thread.daemon = True
    thread.start()

    # wait for the user input and then send it to the server
    while True:
        try:
            user_message = input("")
            mType = "" # message type
            targetUser = None # target user
            if (user_message == ""):
                continue
            if (user_message.startswith("@")):
                targetUser = user_message.split(" ")[0][1:]
                user_message = ' '.join(user_message[1:].split(" ")[1:])
                mType = "PRIVATE"
            else:
                mType = "PUBLIC"
            send_message(sock, mType, user_message, targetUser)
        except KeyboardInterrupt:
            sys.exit()
        except Exception as e:
            print(e)

