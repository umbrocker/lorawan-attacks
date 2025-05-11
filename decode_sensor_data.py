import binascii

def decode_e5mini_payload(hex_payload: str):
    """
    Dekódolja az E5-mini által küldött 22 bájtos LoRa payloadot.
    
    Bemenet:
        hex_payload (string): a nyers dekódolt payload (22 byte)

    Visszatérési érték:
        dict: kulcs-érték párok a szenzor adataival olvasható formában
    """
    # hex string byte kóddá alakítása
    payload_bytes = binascii.unhexlify(hex_payload)

    # hossz ellenőrzés
    if len(payload_bytes) < 22:
        raise ValueError("A payload túl rövid (legalább 22 byte kell)")

    # dekódolás 2 byte-onként megfelelő offset-től
    def dcd(index):
        offset = index * 2
        return int.from_bytes(payload_bytes[offset:offset+2], byteorder='big')

    # kezdő offset
    ino = 0
    return {
        "StationId":    str(f"{dcd(ino)}"),
        "Temperature":  str(f"{dcd(ino + 1) / 10.0} Celsius"),
        "Humidity":     str(f"{dcd(ino + 2) / 10.0}%"),
        "CO2":          str(f"{dcd(ino + 3)} ppm"),
        "PM1.0":        str(f"{dcd(ino + 4)} ug/m^3"),
        "PM2.5":        str(f"{dcd(ino + 5)} ug/m^3"),
        "Pressure":     str(f"{dcd(ino + 6) / 10.0} Kpa"),
        "Intensity":    str(f"{dcd(ino + 7) / 10.0}%"),
        "Lux":          str(f"{dcd(ino + 8) / 10.0} Lux"),
        "Battery":      str(f"{dcd(ino + 9)}%"),
    }


def encode_e5mini_payload(data):
    """
    Az E5-mini által várt LoRa payload összeállítása 11 darab 2-byte mezőből (big endian).
    
    Bemenet:
        data (dict): kulcs-érték párok a következő mezőkkel:
            - StationId (int)
            - Temperature (float)
            - Humidity (float)
            - CO2 (int)
            - PM1.0 (int)
            - PM2.5 (int)
            - Pressure (float)
            - Intensity (float)
            - Lux (float)
            - Battery (int)

    Visszatérési érték:
        bytes: 22 byte hosszú kódolt payload
    """
    
    # enkódolás 2 byte-onként
    def enc(val, scale=1.0):
        scaled = round(val * scale)
        return scaled.to_bytes(2, byteorder='big')

    payload = b''.join([
        enc(data["StationId"]),
        enc(data["Temperature"], 10.0),
        enc(data["Humidity"], 10.0),
        enc(data["CO2"]),
        enc(data["PM1.0"]),
        enc(data["PM2.5"]),
        enc(data["Pressure"], 10.0),
        enc(data["Intensity"], 10.0),
        enc(data["Lux"], 10.0),
        enc(data["Battery"]),
        enc(0),  # 11. mező: padding (az eredeti payload 22 byte, nem 20)
    ])

    return payload