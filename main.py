import socket
import threading
import os
import hashlib

BUFFER_SIZE = 1024
TCP_PORT = 5000
UDP_PORT = 5001

def calculate_file_hash(filename):
    """Calculate the hash of a file for integrity verification."""
    hash_sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(BUFFER_SIZE), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def tcp_server():
    """Start the TCP server to handle file transfers."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", TCP_PORT))
    server.listen(5)
    print(f"[TCP SERVER] Listening on port {TCP_PORT}...")

    while True:
        conn, addr = server.accept()
        print(f"[TCP SERVER] Connection established with {addr}")
        threading.Thread(target=handle_tcp_client, args=(conn,)).start()

def handle_tcp_client(conn):
    """Handle file transfer requests from a TCP client."""
    try:
        command = conn.recv(BUFFER_SIZE).decode()
        if command.startswith("UPLOAD"):
            filename = command.split()[1]
            with open(filename, 'wb') as f:
                while True:
                    data = conn.recv(BUFFER_SIZE)
                    if not data:
                        break
                    f.write(data)
            print(f"[TCP SERVER] File '{filename}' received successfully.")

        elif command.startswith("DOWNLOAD"):
            filename = command.split()[1]
            if os.path.exists(filename):
                conn.send("FILE_FOUND".encode())
                with open(filename, 'rb') as f:
                    while True:
                        chunk = f.read(BUFFER_SIZE)
                        if not chunk:
                            break
                        conn.send(chunk)
                print(f"[TCP SERVER] File '{filename}' sent successfully.")
            else:
                conn.send("FILE_NOT_FOUND".encode())
    except Exception as e:
        print(f"[TCP SERVER] Error: {e}")
    finally:
        conn.close()

def udp_server():
    """Start the UDP server to handle file transfers."""
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("0.0.0.0", UDP_PORT))
    print(f"[UDP SERVER] Listening on port {UDP_PORT}...")

    while True:
        data, addr = server.recvfrom(BUFFER_SIZE)
        command = data.decode()
        if command.startswith("UPLOAD"):
            filename = command.split()[1]
            with open(filename, 'wb') as f:
                while True:
                    data, addr = server.recvfrom(BUFFER_SIZE)
                    if data == b"END":
                        break
                    f.write(data)
            print(f"[UDP SERVER] File '{filename}' received successfully from {addr}.")

        elif command.startswith("DOWNLOAD"):
            filename = command.split()[1]
            if os.path.exists(filename):
                server.sendto("FILE_FOUND".encode(), addr)
                with open(filename, 'rb') as f:
                    while True:
                        chunk = f.read(BUFFER_SIZE)
                        if not chunk:
                            break
                        server.sendto(chunk, addr)
                server.sendto(b"END", addr)
                print(f"[UDP SERVER] File '{filename}' sent successfully to {addr}.")
            else:
                server.sendto("FILE_NOT_FOUND".encode(), addr)

def tcp_client():
    """Connect to the TCP server and transfer files."""
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_ip = input("Enter the server IP: ")
    client.connect((server_ip, TCP_PORT))

    command = input("Enter command (UPLOAD <filename> / DOWNLOAD <filename>): ")
    client.send(command.encode())

    if command.startswith("UPLOAD"):
        filename = command.split()[1]
        if os.path.exists(filename):
            with open(filename, 'rb') as f:
                while True:
                    chunk = f.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    client.send(chunk)
            print("[TCP CLIENT] File uploaded successfully.")
        else:
            print("[TCP CLIENT] File not found.")

    elif command.startswith("DOWNLOAD"):
        response = client.recv(BUFFER_SIZE).decode()
        if response == "FILE_FOUND":
            filename = command.split()[1]
            with open(filename, 'wb') as f:
                while True:
                    data = client.recv(BUFFER_SIZE)
                    if not data:
                        break
                    f.write(data)
            print("[TCP CLIENT] File downloaded successfully.")
        else:
            print("[TCP CLIENT] File not found on server.")

    client.close()

def udp_client():
    """Connect to the UDP server and transfer files."""
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_ip = input("Enter the server IP: ")

    command = input("Enter command (UPLOAD <filename> / DOWNLOAD <filename>): ")
    client.sendto(command.encode(), (server_ip, UDP_PORT))

    if command.startswith("UPLOAD"):
        filename = command.split()[1]
        if os.path.exists(filename):
            with open(filename, 'rb') as f:
                while True:
                    chunk = f.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    client.sendto(chunk, (server_ip, UDP_PORT))
            client.sendto(b"END", (server_ip, UDP_PORT))
            print("[UDP CLIENT] File uploaded successfully.")
        else:
            print("[UDP CLIENT] File not found.")

    elif command.startswith("DOWNLOAD"):
        data, _ = client.recvfrom(BUFFER_SIZE)
        response = data.decode()
        if response == "FILE_FOUND":
            filename = command.split()[1]
            with open(filename, 'wb') as f:
                while True:
                    data, _ = client.recvfrom(BUFFER_SIZE)
                    if data == b"END":
                        break
                    f.write(data)
            print("[UDP CLIENT] File downloaded successfully.")
        else:
            print("[UDP CLIENT] File not found on server.")

def main():
    mode = input("Select mode (server/client): ").lower()
    protocol = input("Select protocol (TCP/UDP): ").upper()

    if mode == "server":
        if protocol == "TCP":
            tcp_server()
        elif protocol == "UDP":
            udp_server()
    elif mode == "client":
        if protocol == "TCP":
            tcp_client()
        elif protocol == "UDP":
            udp_client()

if __name__ == "__main__":
    main()
