import socket
import hashlib
import sys

BUFFER_SIZE = 4096

def generate_signature(message, secret_key):
    '''Generate SHA256 signature for a message with a secret key.'''
    combined = message + secret_key.encode('ascii')
    return hashlib.sha256(combined).hexdigest()

def unescape_message(message):
    '''Handle unescaping of special characters in the message.'''
    return message.replace("\\.", ".").replace("\\\\", "\\")

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 server.py <listen-port> <key-file>")
        sys.exit(1)

    PORT, key_filename = int(sys.argv[1]), sys.argv[2]

    with open(key_filename, 'r') as key_file:
        keys = [line.strip() for line in key_file]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', PORT))
        s.listen()
        print(f"Server started and listening on port {PORT}...")
        
        conn, addr = s.accept()
        with conn:
            hello_message = conn.recv(BUFFER_SIZE).decode('ascii').strip()
            print(f"Received from client: {hello_message}")
            if hello_message != "HELLO":
                print("Error: Expected HELLO message")
                conn.close()
                sys.exit(2)
            conn.sendall(b"260 OK\r\n")

            sha256_hash = hashlib.sha256()

            while True:
                line = conn.recv(BUFFER_SIZE).decode('ascii').strip()
                if line == ".":
                    break

                print(f"Received from client: {line}")
                unescaped_line = unescape_message(line)
                sha256_hash.update(unescaped_line.encode('ascii'))

            for key in keys:
                signature = generate_signature(sha256_hash.digest(), key)
                conn.sendall(b"270 SIG\r\n")
                conn.sendall((signature + "\r\n").encode('ascii'))

                response = conn.recv(BUFFER_SIZE).decode('ascii').strip()
                print(f"Received {response} from client.")
                if response not in ["PASS", "FAIL"]:
                    print("Error: Expected PASS or FAIL")
                    conn.close()
                    sys.exit(3)
                conn.sendall(b"260 OK\r\n")

if __name__ == "__main__":
    main()
