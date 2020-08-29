import socket
import sys
import ipaddress
import os
import argparse

import string
import random
import hashlib

# My attempt at non-urine coding.

parser = argparse.ArgumentParser(description='Download Or Host Files over the Internet.')
# Default Message
parser.add_argument('-host', help='Host a file from this PC', action='store_true')
parser.add_argument('file', help='The file to send or receive into, depending on the mode.')
# HOST MODE
parser.add_argument('-client', help='Download a file from another PC.', action='store_true')
parser.add_argument('-ip', help='Remote PC IP', required='-client' in sys.argv)
parser.add_argument('-p', help='Connection Password', required='-client' in sys.argv)
# CLIENT MODE

args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])

if args.host:
    hash = hashlib.sha512()
    letters = string.ascii_letters
    random_pass = (''.join(random.choice(letters) for i in range(11)))
    hashed_random = random_pass.encode('utf-8')
    hash.update(hashed_random)
    hex_dig = hash.digest()

    # generate random authentication password (not very hard but sufficient lol)
    try:
        host_name = socket.gethostname()
        host_ip = socket.gethostbyname(host_name)
        with open(args.file, 'rb') as file:
            sending = file.read()
            # Open the file in binary mode
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("Attempting to bind to socket...")
        try:

            s.bind((host_ip, 50000))
            s.listen(1)
            print("Success!")
            print("Details for client:\n", "Host: ", host_ip, "\nPort: 50000", "Password: ", random_pass)
            print("Waiting for connections...")
            while True:
                c, addr = s.accept()
                print("Got connection from", addr)
                pass_recv = c.recv(2048)
                stringdata = pass_recv

                if stringdata == hex_dig:
                    print("Pass Accepted.")
                    print("Sending.....")
                    c.sendall(sending)
                    print("Send Completed!")
                    c.shutdown(socket.SHUT_RDWR)
                    c.close()
                    file.close()
                    sys.exit(0)
                else:
                    c.shutdown(socket.SHUT_RDWR)
                    c.close()
                    file.close()
                    print("Client pass failed!")

        except socket.error:
            print("Socket bind failed!")
            sys.exit(1)

        except KeyboardInterrupt:
            sys.exit(0)

    except FileNotFoundError:
        print("File not Found!")

if args.client:
    try:
        ipaddress.ip_address(args.ip)
        print("Creating Socket")
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((args.ip, 50000))
        print("Creating Socket Success!")
        hash = hashlib.sha512()
        drypass = args.p
        encoded = drypass.encode('utf-8')
        hash.update(encoded)
        hex_dig = hash.digest()
        conn.send(hash.digest())

        with open(args.file, 'wb') as f:
            print("Created New File!")
            while True:
                print('Receiving Data...')
                data = conn.recv(1024)
                if not data:
                    break
                f.write(data)
            f.close()

            print("Wrote data!")
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
            sys.exit(0)

    except ValueError:
        print("Invalid IP!")
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
    except BrokenPipeError:
        print("Remote host disconnected!")
        conn.close()
    except TimeoutError:
        print("Connection Attempt Timed out!")
        conn.close()
    except ConnectionRefusedError:
        print("Host is not receiving!")
        conn.close()






