import socket
import sys
import argparse

def scan_ports(transport_type, host_ip, ports):
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
            request_payload = b"Javali"
            sock.sendto(request_payload, (host_ip, port))
            try:
                response = sock.recvfrom(1024)
                response_data = response[0].decode('utf-8')
                if response_data == 'Javali':
                    result_file.write(f'{transport_type}/{port}: Open\n')
                    result_file.write(f'Resposta: {response}')
                # else:
                #     result_file.write(f'{transport_type}/{port}: Closed\n')
                print(f'Resposta : {response}')
                result_file.write(f'Resposta: {response}')
            except socket.timeout:
                result_file.write(f'{transport_type}/{port}: Filtered | Closed\n')
            except Exception: pass            
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

if __name__ == '__main__':
    # Verificar os argumentos da linha de comando
    if len(sys.argv) != 4:
        print('Uso: python networkScanner.py [tcp|udp] [host_ip] [porta1,porta2,porta3]')
        sys.exit(1)
    
    # Obter os parâmetros da linha de comando
    transport_type = sys.argv[1]
    host_ip = sys.argv[2]
    ports = [int(porta) for porta in sys.argv[3].split(',')]
    
    # Executar a varredura de portas
    scan_ports(transport_type, host_ip, ports)
