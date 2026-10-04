"""Writes customers.json: 50 made-up bank customers. Every value is random; no real person's data.

    python3 make_customers.py

Identifiers follow the public format only. The Ghana Card check digit is random, not computed.
"""
import json
import random
from pathlib import Path

random.seed(2026)

FIRST = ["Ama", "Kofi", "Akosua", "Kwame", "Abena", "Yaw", "Adwoa", "Kwabena", "Esi", "Kojo",
         "Afia", "Kwesi", "Efua", "Fiifi", "Araba", "Nii", "Naa", "Selorm", "Dzifa", "Alhassan"]
LAST = ["Mensah", "Boateng", "Owusu", "Asante", "Osei", "Appiah", "Agyemang", "Amoah", "Addo",
        "Tetteh", "Lamptey", "Quaye", "Adjei", "Darko", "Ansah", "Agbeko", "Mahama", "Yeboah"]
MOMO_PREFIX = ["024", "054", "055", "059", "020", "050", "026", "056", "027", "057"]
CITY = {"GA": "Accra", "AK": "Kumasi", "CC": "Cape Coast", "NT": "Tamale"}


def digits(n):
    return "".join(random.choice("0123456789") for _ in range(n))


names = random.sample([f"{f} {l}" for f in FIRST for l in LAST], 50)
customers = []
for name in names:
    area = random.choice(list(CITY))
    customers.append({
        "name": name,
        "ghana_card": f"GHA-{digits(9)}-{digits(1)}",
        "momo_number": random.choice(MOMO_PREFIX) + digits(7),
        "ssnit": random.choice("ABCDEFGH") + digits(12),
        "digital_address": f"{area}-{digits(3)}-{digits(4)}",
        "city": CITY[area],
        "balance_ghs": round(random.uniform(50, 25000), 2),
    })

Path(__file__).with_name("customers.json").write_text(json.dumps(customers, indent=2) + "\n")
print(f"wrote {len(customers)} customers")
