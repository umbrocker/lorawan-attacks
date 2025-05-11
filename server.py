import socket

def connection(HOST='127.0.0.1', PORT=12345)->tuple:
    """
    Socket-tel létrehoz egy szerver oldali service-t
    
    Bemenet:
        HOST -- interfész IP
        PORT -- hallgatózó port
    Visszatérési érték:
        (server_socket, client) -- szerver socket, kliens socket
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)  # maximum 1 kliens

    print(f"[+] Szerver fut {HOST}:{PORT} címen, várok kapcsolódást...")

    client = server_socket.accept()
    print(f"[+] Kapcsolódott: {client[1]}")
    
    return (server_socket, client)

def main():    
    server_socket, client = connection()
    client_socket, addr = client

    while True:
        # Várunk az üzenetre
        data = client_socket.recv(1024).decode('utf-8')
        if not data:
            print("[-] Kliens bontotta a kapcsolatot.")
            break

        print(f"[Kliens]: {data}")

        if data.strip().upper() == "EXIT":
            print("[!] Kliens kilépett.")
            break

        # Küldünk választ
        message = input("[Te]: ")
        client_socket.send(message.encode('utf-8'))

        if message.strip().upper() == "EXIT":
            print("[!] Kiléptél.")
            break
    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    main()
