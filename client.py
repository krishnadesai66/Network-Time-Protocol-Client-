import socket
import sys
import hashlib

BUFFER_SIZE = 4096

def verify_signature(data, signature, key_file):
    '''Verify the signature of data with a provided key file.'''
    with open(key_file, 'r') as f:
        keys = [line.strip() for line in f]
        for key in keys:
            expected_signature = hashlib.sha256(data.encode('ascii') + key.encode('ascii')).hexdigest()
            if expected_signature == signature:
                return True
    return False

def main():
    if len(sys.argv) != 5:
        print("Usage: python3 client.py <server-ip> <server-port> <message-file> <key-file>")
        sys.exit(1)

    HOST, PORT, message_filename, key_filename = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(b"HELLO\r\n")

        response = s.recv(BUFFER_SIZE).decode('ascii').strip()
        print(f"Received {response} from server.")

        if response != "260 OK":
            print("Error: Expected 260 OK")
            sys.exit(2)

        print("Preparing to send DATA...")
        s.sendall(b"DATA\r\n")

        with open(message_filename, 'r') as f:
            for line in f:
                print(f"Sent message: {line.strip()}")
                s.sendall((line + "\r\n").encode('ascii'))

        s.sendall(b".\r\n")

        sig_response = s.recv(BUFFER_SIZE).decode('ascii').strip()
        if sig_response != "270 SIG":
            print("Error: Expected 270 SIG")
            sys.exit(3)

        signature = s.recv(BUFFER_SIZE).decode('ascii').strip()
        if verify_signature(response, signature, key_filename):
            s.sendall(b"PASS\r\n")
        else:
            s.sendall(b"FAIL\r\n")

        response = s.recv(BUFFER_SIZE).decode('ascii').strip()
        if response != "260 OK":
            print("Error: Expected 260 OK")
            sys.exit(4)

if __name__ == "__main__":
    main()
