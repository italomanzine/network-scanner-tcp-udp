import socket
import sys
import argparse
import jwt
from datetime import datetime
import json

# Chave privada para assinar os tokens JWT
private_key = """-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDWm4AWAq/Fy9Eo0RFqCqziqF9oJ1f6vBtDzHswMCBpLRwAqW19
wjMK6kgPppzl0wxd0m4NfTF+qrTMQpGZ3/VURhLYOytISjioHfYdqV4n8LhQeQ9k
BF2lPjCCJDKGesbeXQyS8yVd8lRzRfr1Zd4hN4hHm5dw9dFPq8MzsfHTQQIDAQAB
AoGAa8gVcNGLR/LCyyJ8+G+py8oM6L+Gz3ZYOabGrZ4DdxmNlS5HJ4G9QvgqK2O2
0ufKjuWd6USh4IHR8To1oXZgFeidU7V8lTXEJYjMvU4To8RVB2+1v1IYiE42ayw5
eXWkEdX/JGndYwdQFfWtA81TjOLvVH9X80ZD+8c6Ih+tisECQQD+WUe5yfxOG5gT
3b5l5SoZnOJtYj1nXHe96FrOXX/McnZ4EMX2B6v4emEcmZKum5lukU1G6cDsbjjW
0yNO+1b5AkEA4r43o3x6hWfcXhGL6/SOHz8frCktWZ/fZZEaL5IgpdCcZ2ovcH4W
kbnAe+0ytiR8aORUGSufbwsUCqCfoGJd3QJAGhA4G+W88CZrcP0XhE9Fsyf+mRfJ
H9RRN3uzxW0VYXcXVDiP6yVH/8ds8WltA3aeWbLl9OrQLmBD/Ls4mL36bwJAdbo4
waAeiYFjQ8ktTOOU5a6o0zotPDDbkeXcHjr6lB0I76GhODbWlunDgXVbdsN8/fLJ
LlIRfEzFf4H1FrJGBQJBAID7UmZ8YTRhoexXW7pEskfGWvG7NYHZW4Xu8c2y/5c4
zLYOxQDn0zTS5CVnYjAr7sIptprlh3wyH/9c2w7QAlI=
-----END RSA PRIVATE KEY-----"""

# Chave secreta para descriptografar o algoritmo HS256
secret_key = "dec7557-socket-udp-with-jwt"

def create_jwt_payload(group, seq_number, seq_max, matricula):
    payload = {
        "group": group,
        "seq_number": seq_number,
        "seq_max": seq_max,
        "matricula": matricula
    }
    return payload

def sign_jwt(payload):
    token = jwt.encode(payload, private_key, algorithm="RS256")
    return token.decode("utf-8")

def verify_jwt(token):
    try:
        decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"])
        return decoded_token
    except jwt.InvalidTokenError:
        return None

def send_payload_udp(host_ip, port, payload):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)

    sock.sendto(payload.encode('utf-8'), (host_ip, port))

    try:
        data, addr = sock.recvfrom(1024)
        response = data.decode('utf-8')
        return response
    except socket.timeout:
        return None
    finally:
        sock.close()

def save_response_to_file(response, is_signature_valid):
    with open('responses.txt', 'a') as file:
        file.write(f'Response: {response}\n')
        file.write(f'Signature Valid: {is_signature_valid}\n')

def scan_ports(transport_type, host_ip, ports, group, matriculas):
    result_file = open(f'{transport_type}_scan_results.txt', 'w')

    if transport_type.lower() == 'tcp':
        socket_type = socket.SOCK_STREAM
    elif transport_type.lower() == 'udp':
        socket_type = socket.SOCK_DGRAM
    else:
        print("Tipo de transporte inválido. Por favor, escolha entre 'tcp' ou 'udp'.")
        return

    seq_number = 1
    seq_max = 3

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket_type)
        sock.settimeout(1)

        if transport_type.lower() == 'udp':
            for matricula in matriculas:
                payload = create_jwt_payload(group, seq_number, seq_max, matricula)
                token = sign_jwt(payload)
                response = send_payload_udp(host_ip, port, token)

                if response is not None:
                    decoded_token = verify_jwt(response)
                    if decoded_token is not None:
                        save_response_to_file(response, True)
                        print(f'Received valid response from {host_ip}:{port} - {response}')
                        next_number = decoded_token.get('next_number', None)
                        if next_number is not None:
                            seq_number = next_number
                    else:
                        save_response_to_file(response, False)
                        print(f'Received response with invalid signature from {host_ip}:{port} - {response}')
                else:
                    save_response_to_file('No response', False)
                    print(f'No response received from {host_ip}:{port}')

            continue

        result = sock.connect_ex((host_ip, port))

        if result == 0:
            result_file.write(f'{transport_type}/{port}: Open\n')
        else:
            result_file.write(f'{transport_type}/{port}: Closed\n')

        sock.close()

    result_file.close()
    print(f'Resultados do escaneamento salvos em {transport_type}_scan_results.txt')

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('Uso: python networkScanner.py [tcp|udp] [host_ip] [porta1,porta2,porta3]')
        sys.exit(1)

    transport_type = sys.argv[1]
    host_ip = sys.argv[2]
    ports = [int(porta) for porta in sys.argv[3].split(',')]
    group = "JAVALI"
    matriculas = ["16104677", "20102083", "20204027"]

    scan_ports(transport_type, host_ip, ports, group, matriculas)
