import json
import os
import binascii

def main():
    """
    Fő eljárás, a program belépési pontja.
    """
    clear_screen()
    # a json-né alakított hálózati forgalom megadása
    json_file = "output.json"      
    # itt tölti be és alakítja át megfelelő formátumra a json-t
    data = load_json(json_file)
    # ez a function szedi ki a payloadot a json-ből
    gateway_ids, full_packets, data_strings = analyze_bytes(data)

def analyze_bytes(data)->tuple:
    """
    Függvény, mely kiszedi a gateway ID-t, és a payload-ot az UDP csomagokból.

    Bemenet:
        data (dict): a json fájlból betöltött hálózati forgalom
    Visszatérési érték:
        (gws, fdts, dtss) (tuple): 3 lista - gateway ID-k, teljes payload-ok, csak a "data" rész
    """
    # üres lista a gateway ID-knak
    gws = []
    # üres lista a teljes payload-oknak
    fdts = []
    # üres lista csak a "data" résznek
    dtss = []
    for d in data:
        try:
            # biztonsági ellenőrzés, hogy tényleg a megfelelő UDP csomagokat elemezze a szkript
            if d["_source"]["layers"]["udp"]["udp.dstport"] == "1700"  \
            or d["_source"]["layers"]["udp"]["udp.srcport"] == "1700":
                # az UDP csomagból az "érdekes" adatok parszolása és kigyűjtése
                gw, dt_string, full_dt = data_parser(d["_source"]["layers"]["data"]["data.data"])
                # a teljes payload hozzáadása a listához 
                fdts.append(full_dt)
                # ha a gateway ID még nem szerepel a listában, az új hozzáadása
                if gw not in gws:
                    gws.append(gw)
                # ha van "data" része a payloadnak, azt emeljük ki
                if dt_string not in dtss and dt_string != None:
                    dtss.append(dt_string)
        except:
            continue
    return (gws, fdts, dtss)

def data_parser(data: str)->tuple:
    """
    Függvény, mely kiszedi a számomra "érdekes" részeket.

    Bemenet:
        data (str): a json formátumú hálózati forgalomból kiszedett UDP payload
    Visszatérési érték:
        (new_gw, data_string, fd) (tuple): 3 lista - gateway ID-k, teljes payload-ok, csak a "data" rész
    """
    # a hexadecimális formában kiszedett adatok parszolása bájt formátumra
    readable_bytes = bytes.fromhex(''.join(data.split(':')))
    # az első néhány bájt az első "{"" előtt a gateway ID
    # ezzel megkeressük az első {-t
    gw_end_index = readable_bytes.find(b"{")
    # ha van találat, akkor olyan csomagot találtunk, amit érdemes elemezni
    if gw_end_index != -1:
        # teljes payload lementése
        fd = json.loads(readable_bytes[gw_end_index:].decode())
        # bájtok átalakítása hex-xé, hogy össze lehessen hasonlítani a chirpstackben, 
        # illetve a lorawanban lévő gateway ID-val
        new_gw = binascii.hexlify(readable_bytes[:gw_end_index])
        # a "data" szekciót keresem a payloadban
        start_index = readable_bytes.find(b"data")
        # a "data" után a } keresése
        stop_index = readable_bytes[start_index:].find(b"}")
        # ha megvan
        if  start_index != -1:
            # a megfelelő adatok kiszedése
            data_string = readable_bytes[start_index:(start_index+stop_index)].decode().split('"')[2]
        else:
            # azért, hogy ne fusson hibára, ha nincs "data" rész a payloadban
            data_string = None
        # parszolt bájtok visszaadása
        print(f'Teljes payload: {fd}')
        print(f'Gateway ID: {new_gw}')
        print(f'Data: {data_string}')
        return (new_gw, data_string, fd)

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
            data = f.read()
        return json.loads(data)
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