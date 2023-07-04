import socket
import sys
import argparse
import jwt
from datetime import datetime
import json

# Chave privada para assinar os tokens JWT
private_key = """-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCXtF3ydONKD+klB0DGzb4inW5Qp1m59H7shXvKpXhQDHJKOt61
vS+wVO5LYLL/PdH74T+XUHUddw0BU1ZqT1c+raMV78jWljaGWC3Lt/GBGAfY9Wmj
iUlYU8qwRvhK9Gxvo9782ZU2K1ArOt9lzyspX/wsTVWn8n4yhkKePoYb2QIDAQAB
AoGAASwlL7sEiK1/zUf1kbPEXOsfj6MDeALyOiy77LCDsgaumXFECF6KcE/vuYhp
Sby2Ez7F6Yr3JL+nS5PTzqWHVJMgCiO0d7BIU5xwyzFW3gXRbiytQnLmYe8cjaPV
XEGcC74bjTx0K6puDHjytm4yswB0lS0LN2nFKdDFEgBNtkECQQDUJOKkgO69j4g1
a2C3s8k9FUvwKaruTUpODiibQD9MhWu9HDt9r7pQmTTNDgFGwGYYjMMY20FZPWRa
XcNZrbVRAkEAtxDk1DK7Pfu0tqVJ0/xVtVER5O+LWh9EGzk+cNYSv0CNDEQ5ZUtE
dYU6KHsGkXMAW5wTN9FbO7XE2tSLWj/8CQJBANKLhRCFEey6jhGOb2ACo//mqgZC
JG378XoEXVKv8eKtLB907KoyBLTHSPsWIjgo7WsCEQMTYAkEgBuboSzY1PECQA3m
SnmSIIVkRyRXCHQABMHvldw8E+iT1yf6ALOwjVvYGt2DkJgQTvJdWz0XmjgQ80YB
Y7QpQTQXaQr0eGAx24ECQEJv4t2ma2drkIizABmpvpYnzrPLObrR9BS53q8kNV+/
cwhfBi5SUZgHJJk0NIwxBF701B3v01TMG2n+bW+8Ar4=
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

# def sign_jwt(payload):
#     token = jwt.encode(payload, private_key, algorithm="RS256")
#     return token.decode("utf-8")

def sign_jwt(payload):
    token = jwt.encode(payload, private_key, algorithm="RS256")
    return token


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
    try:
        payload_response = response
        # Descriptografe o payload usando a chave secreta
        decoded_payload = jwt.decode(payload_response, secret_key, algorithms=["HS256"])
        # O payload descriptografado estará disponível na variável decoded_payload
    except jwt.InvalidTokenError:
        print("Token inválido")
    with open('responses.txt', 'a') as file:
        file.write(f'Response: {response}\n\n')
        file.write(f'Decoded payload response: {decoded_payload}\n\n')
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

    seq_number = 0
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
