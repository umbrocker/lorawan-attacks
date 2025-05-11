import socket

#SERVER_IP = '127.0.0.1'
#PORT = 12345

def connection(SERVER_IP='127.0.0.1', PORT=12345):
    """Sockettel létrehoz egy kliens oldali service-t
    Paraméterek:
        SERVER_IP -- szerver IP
        PORT -- szerver port
    Visszatér:
        client_socket -- kliens socket

    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, PORT))

    print(f"[+] Csatlakoztál a szerverhez {SERVER_IP}:{PORT}")
    return client_socket

def main():

    client_socket = connection()

    while True:
        # Küldünk üzenetet
        message = input("[Te]: ")
        client_socket.send(message.encode('utf-8'))

        if message.strip().upper() == "EXIT":
            print("[!] Kiléptél.")
            break

        # Várunk válaszra
        data = client_socket.recv(1024).decode('utf-8')
        if not data:
            print("[-] Szerver bontotta a kapcsolatot.")
            break

        print(f"[Szerver]: {data}")

        if data.strip().upper() == "EXIT":
            print("[!] Szerver kilépett.")
            break

    client_socket.close()

if __name__ == "__main__":
    main()
