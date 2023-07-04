import socket
import sys
import argparse
import jwt
import rsa
import hashlib
import json
import time

def create_jwt_token(payload, private_key):
    token = jwt.encode(payload, private_key, algorithm='RS256')
    return token

def verify_jwt_token(token, public_key):
    try:
        decoded_token = jwt.decode(token, public_key, algorithms=['RS256'])
        return decoded_token
    except jwt.InvalidTokenError:
        return None

def format_public_key(public_key):
    pem_key = public_key.save_pkcs1().decode()
    formatted_key = f"-----BEGIN RSA PUBLIC KEY-----\n{pem_key}\n-----END RSA PUBLIC KEY-----"
    return formatted_key

def format_private_key(private_key):
    pem_key = private_key.save_pkcs1().decode()
    formatted_key = f"-----BEGIN RSA PRIVATE KEY-----\n{pem_key}\n-----END RSA PRIVATE KEY-----"
    return formatted_key

def scan_ports(transport_type, host_ip, ports, token):
    # Abrir o arquivo para salvar os resultados
    result_file = open(f'{transport_type}_scan_results.txt', 'w')

    # Verificar o tipo de transporte (TCP ou UDP)
    if transport_type.lower() == 'tcp':
        socket_type = socket.SOCK_STREAM
    elif transport_type.lower() == 'udp':
        socket_type = socket.SOCK_DGRAM
    else:
        print("Tipo de transporte inválido. Por favor, escolha entre 'tcp' ou 'udp'.")
        return
    
    # Varredura de portas
    for port in ports:
        # Criar um socket TCP ou UDP
        sock = socket.socket(socket.AF_INET, socket_type)
        sock.settimeout(1)
        if transport_type.lower() == 'udp':
            request_payload = token.encode()
            sock.sendto(request_payload, (host_ip, port))
            try:
                response = sock.recvfrom(1024)
                response_data = response[0].decode('utf-8')
                if response_data == token:
                    result_file.write(f'{transport_type}/{port}: Open\n')
                else:
                    result_file.write(f'{transport_type}/{port}: Closed\n')
            except socket.timeout:
                result_file.write(f'{transport_type}/{port}: Filtered | Closed\n')
            except Exception:
                pass            
            continue
        
        result = sock.connect_ex((host_ip, port))   # server host, server port
        
        # Verificar se a porta está aberta ou fechada
        if result == 0:
            result_file.write(f'{transport_type}/{port}: Open\n')
        else:
            result_file.write(f'{transport_type}/{port}: Closed\n')
        
        # Fechar o socket
        sock.close()
    
    # Fechar o arquivo de resultados
    result_file.close()
    print(f'Resultados do escaneamento salvos em {transport_type}_scan_results.txt')

def send_request(transport_type, host_ip, port, token):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if transport_type.lower() == 'udp' else socket.SOCK_STREAM)
    sock.settimeout(5)
    
    if transport_type.lower() == 'udp':
        sock.sendto(token.encode(), (host_ip, port))
        try:
            response = sock.recvfrom(1024)
            print(f'Resposta do servidor: {response[0].decode()}')

            # Verificar a assinatura do token JWT recebido
            public_key_pem = """
            -----BEGIN PUBLIC KEY-----
            MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgAUkZlGHN9yUvMhy7BpkydNkX
            xvJ58DkITY/xpTDXirOTk7iJ7orxOrkQq9lMY7dK/QkeJzbrTtuz2EmbnvNfEIyF
            rCIT1BV8Dfbxhhrxbdl9CRCSnpsFuIOSDNYufdbQpZJxYJ14lMoT3DhI+L4gktZf
            ea28bkujA0YV4Qn8ZwIDAQAB
            -----END PUBLIC KEY-----
            """

            public_key = rsa.PublicKey.load_pkcs1(public_key_pem)

            verified_payload = verify_jwt_token(response[0].decode(), public_key)
            if verified_payload:
                print("Token JWT válido. Payload verificado:")
                print(verified_payload)
                result_file = open('resposta_bruta.txt', 'w')
                result_file.write(f'Resposta bruta: {response[0].decode()}\n')
                result_file.write("Verificação da assinatura: OK\n")
                result_file.close()
            else:
                print("Token JWT inválido.")
                result_file = open('resposta_bruta.txt', 'w')
                result_file.write(f'Resposta bruta: {response[0].decode()}\n')
                result_file.write("Verificação da assinatura: NOT_OK\n")
                result_file.close()
        except socket.timeout:
            print('Tempo limite atingido. Não foi possível receber uma resposta do servidor.')
        except Exception as e:
            print(f'Ocorreu um erro ao receber a resposta: {str(e)}')
    else:
        try:
            sock.connect((host_ip, port))
            sock.sendall(token.encode())
            response = sock.recv(1024)
            print(f'Resposta do servidor: {response.decode()}')

            # Verificar a assinatura do token JWT recebido
            public_key_pem = """
            -----BEGIN PUBLIC KEY-----
            MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgAUkZlGHN9yUvMhy7BpkydNkX
            xvJ58DkITY/xpTDXirOTk7iJ7orxOrkQq9lMY7dK/QkeJzbrTtuz2EmbnvNfEIyF
            rCIT1BV8Dfbxhhrxbdl9CRCSnpsFuIOSDNYufdbQpZJxYJ14lMoT3DhI+L4gktZf
            ea28bkujA0YV4Qn8ZwIDAQAB
            """

            public_key = rsa.PublicKey.load_pkcs1(public_key_pem)

            verified_payload = verify_jwt_token(response.decode(), public_key)
            if verified_payload:
                print("Token JWT válido. Payload verificado:")
                print(verified_payload)
                result_file = open('resposta_bruta.txt', 'w')
                result_file.write(f'Resposta bruta: {response.decode()}\n')
                result_file.write("Verificação da assinatura: OK\n")
                result_file.close()
            else:
                print("Token JWT inválido.")
                result_file = open('resposta_bruta.txt', 'w')
                result_file.write(f'Resposta bruta: {response.decode()}\n')
                result_file.write("Verificação da assinatura: NOT_OK\n")
                result_file.close()
        except socket.timeout:
            print('Tempo limite atingido. Não foi possível receber uma resposta do servidor.')
        except Exception as e:
            print(f'Ocorreu um erro ao receber a resposta: {str(e)}')
        finally:
            sock.close()

def main():
    parser = argparse.ArgumentParser(description='TCP/UDP client')
    parser.add_argument('--transport', type=str, choices=['tcp', 'udp'], help='Transport protocol (TCP/UDP)')
    parser.add_argument('--ip', type=str, help='Server IP address')
    parser.add_argument('--port', type=int, help='Server port')
    parser.add_argument('--token', type=str, help='Token de resposta JWT')

    args = parser.parse_args()

    transport_type = args.transport
    host_ip = args.ip
    port = args.port
    token = args.token

    if not transport_type or not host_ip or not port or not token:
        print("Por favor, forneça o tipo de transporte (--transport), o IP do servidor (--ip), a porta (--port) e o token JWT de resposta (--token).")
        return

    # Verificar a assinatura do token JWT recebido
    public_key_pem = """
    -----BEGIN PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgAUkZlGHN9yUvMhy7BpkydNkX
    xvJ58DkITY/xpTDXirOTk7iJ7orxOrkQq9lMY7dK/QkeJzbrTtuz2EmbnvNfEIyF
    rCIT1BV8Dfbxhhrxbdl9CRCSnpsFuIOSDNYufdbQpZJxYJ14lMoT3DhI+L4gktZf
    ea28bkujA0YV4Qn8ZwIDAQAB
    """

    public_key = rsa.PublicKey.load_pkcs1(public_key_pem)

    verified_payload = verify_jwt_token(token, public_key)
    if verified_payload:
        print("Token JWT válido. Payload verificado:")
        print(verified_payload)
        result_file = open('resposta_bruta.txt', 'w')
        result_file.write(f'Token JWT: {token}\n')
        result_file.write("Verificação da assinatura: OK\n")
        result_file.close()
    else:
        print("Token JWT inválido.")
        result_file = open('resposta_bruta.txt', 'w')
        result_file.write(f'Token JWT: {token}\n')
        result_file.write("Verificação da assinatura: NOT_OK\n")
        result_file.close()

    # Enviar mensagem para o próximo aluno
    print("Enviar a mensagem do próximo aluno aqui...")

if __name__ == '__main__':
    main()
