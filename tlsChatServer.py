import signal
import socket
import struct
import threading
import ssl
import json         
from datetime import datetime

HEADER_LENGTH = 2  # Header consists the legnth of the message 
SERVER = 'localhost' # Alternative: socket.gethostbyname(socket.gethostname())
PORT = 5432 
ADDR = (SERVER, PORT)
FORMAT = 'utf-8'
# Global variable for maping client_usernames to corresponding sockets
username2socket = {} 


def setup_SSL_context(certPath: str = "./server_certs", clientsCertPath: str = "./client_certs") -> ssl.SSLContext:
    """Create SSLContext object to manage settings and certificates which are inherited by SSL socket (through SSLContext.wrap_socket())

    Returns:
        ssl.SSLContext: SSLContext object 
    """
    # use only TLS, not SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    # require certificate 
    context.verify_mode = ssl.CERT_REQUIRED
    # Load a private key and Corresponding certificate
    context.load_cert_chain(certfile=f"{certPath}/server.crt", keyfile=f"{certPath}/server.key")
    # Load a set of "certification authority" certificates used to validate other peer's 
    # certificates. 
    context.load_verify_locations(f"{clientsCertPath}/clients.pem")
    # Set the cipher (encryption method)
    context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
    return context


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
        chunk = sock.recv(msglen - len(message))  
        # recv ends with an empty string if the connection is closed/error
        if chunk == b'':
            raise RuntimeError("socket connection broken")
        message = message + chunk  
    return message


def receive_message(sock: ssl.SSLSocket) -> dict[str, str]:
    """Read from socket sock, and return json-dict read.

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

def send_message(sock: ssl.SSLSocket, mType: str, mAuthor: str, mText: str, mTarget: str = None) -> None:
    """Build (depending on given arguments) and send the message to the socket sock.

    Args:
        sock (ssl.SSLSocket): socket to be sent to
        mType (str): Message Type,
        mAuthor (str): Message Sender 
        mText (str): Message Text (content)
        mTarget (str): Message Target
    """
    message = {
        "mType": mType,
        "mText": mText,
        "mAuthor": mAuthor,
        "mTarget": mTarget,
        "mTime": curTime() 
    }
    # Encode message_body
    json_string = json.dumps(message)
    encoded_message_body = json_string.encode(FORMAT)  

    # Encode message_header
    # first two bytes of a mssage = header (in header we write the length of the data) 
    # method pack "!H" : !=network byte order, H=unsigned short
    encoded_message_header = struct.pack("!H", len(encoded_message_body))

    encoded_message = encoded_message_header + encoded_message_body 
    # Send all the data to the sock
    sock.sendall(encoded_message)


def verifyClientName(client_socket: ssl.SSLSocket) -> str:
    client_username = None 
    #  We find client_username in >>commonName<< field 
    cert = client_socket.getpeercert()
    for field in cert['subject']:
        for key, value in field:
            if key == 'commonName':
                client_username = value
    if (client_username):
        with threading.Lock():
            username2socket[client_username] = client_socket
    return client_username


# Each client has own thread running client_thread
def client_thread(client_sock: ssl.SSLSocket, client_addr: tuple[str, int]) -> None:
    """Each client gets his own thread Thread for communication.

    Args:
        client_sock (ssl.SSLSocket): socket from which client is connected
        client_addr (socket._RetAddress): address of client socket
    """

    # Verify client_username from SSLContext (chek if it is in server.certs)
    client_username = verifyClientName(client_sock)
    if (not client_username):
        send_message(client_sock, "VALIDATION_ERR", "SERVER", "username can't be validated", client_username)
        client_sock.close()
        return

    print("[SERVER] connected with " + client_addr[0] + ":" + str(client_addr[1]))
    print("[SERVER] we now have " + str(len(username2socket)) + " clients")
    print(f'Established SSL connection with: {client_username}')

    try:
        while True:  
            msg_received = receive_message(client_sock)
            # check if msg has been received
            if not msg_received:  
                break

            # Acknowledge that the message from user has been received
            print("[RKchat] [" + client_addr[0] + ":" + str(client_addr[1]) + "] : " + str(msg_received))

            if (msg_received["mType"] == "PRIVATE"):
                if (not msg_received["mTarget"]):
                    send_message(client_sock, "PRIVATE", client_username, "message wasn't send: mTarget wasn't defined")
                elif (msg_received["mTarget"] not in username2socket):
                    send_message(client_sock, "PRIVATE", "SERVER", "message target doesn't exist. Try again.")
                else:
                    send_message(username2socket[msg_received["mTarget"]], "PRIVATE", client_username, msg_received["mText"], msg_received["mTarget"])
            
            if (msg_received["mType"] == "PUBLIC"):
                for username in username2socket:
                    send_message(username2socket[username], "PUBLIC", client_username, msg_received['mText'])

    except Exception as e:
        print(e)

    # User has ended with communication
    with threading.Lock():
        del username2socket[client_username]
        for socket in username2socket.values():
            send_message(socket, "PUBLIC", "SERVER", f"{client_username} has left the chat :(")
    print(f"[SERVER] we now have {len(username2socket)} clients")
    client_sock.close()


if __name__ == '__main__':
    # Setup a SSL/TLS properties of a socket into --> SSLContext (object)
    my_ssl_ctx = setup_SSL_context()
    # Create a socket:  
    #       addres family:  AF_INET (ipv4 address)
    #       socket kind:    SOCK_STREAM (this means a TCP socket)
    socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Wrap a socket into context, and make it secure --> SSLSocket (object)
    server_socket = my_ssl_ctx.wrap_socket(socket)
    server_socket.bind(ADDR) # bind socket to an (IPaddress, PORT)
    # Enable a server to accept connections. arg 1: number of unaccepted connections that the system will allow before refusing new connections
    server_socket.listen(1) 
    print(f"[SERVER] Server is listening on {SERVER}:{PORT} ...")

    while True:
        try:
            # Wait for a new connection to the server 
            client_socket, client_addr = server_socket.accept() # blocking line

            # When a new connection is setup, we create a thread and run it in a separate
            thread = threading.Thread(target=client_thread, args=(client_socket, client_addr))
            # deamon threads automatically die when main thread is terminated
            thread.daemon = True # https://stackoverflow.com/questions/2564137/how-to-terminate-a-thread-when-main-program-ends ()
            thread.start()

        except KeyboardInterrupt:
            break
    
    with threading.Lock():
        for socket in username2socket.values():
            print("[SERVER] closing server socket ....")
            send_message(socket, "PUBLIC", "SERVER", "closing server socket.")
    server_socket.close()



