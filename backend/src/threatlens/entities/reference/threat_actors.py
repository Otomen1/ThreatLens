"""Seed catalog of well-known threat actors and their aliases.

Numbered ``APT\\d+`` groups are also recognized structurally by the detector;
this catalog resolves named aliases (e.g. "Cozy Bear" -> "APT29") and groups
without an APT designation. ``THREAT_ACTORS`` maps a lowercased alias to its
canonical display name.
"""

from __future__ import annotations

# canonical -> aliases
_ACTORS: dict[str, list[str]] = {
    "APT28": [
        "Fancy Bear",
        "Sofacy",
        "Sednit",
        "Pawn Storm",
        "STRONTIUM",
        "Forest Blizzard",
        "Fighting Ursa",
    ],
    "APT29": ["Cozy Bear", "The Dukes", "Nobelium", "Midnight Blizzard", "Cozy Duke", "UNC2452"],
    "APT30": [],
    "APT32": ["OceanLotus", "SeaLotus", "Cobalt Kitty"],
    "APT33": ["Elfin", "Peach Sandstorm", "Refined Kitten"],
    "APT34": ["OilRig", "Helix Kitten", "Cobalt Gypsy"],
    "APT37": ["Reaper", "ScarCruft", "Ricochet Chollima"],
    "APT38": ["BlueNoroff", "Stardust Chollima"],
    "APT39": ["Chafer", "Remix Kitten"],
    "APT40": ["Leviathan", "TEMP.Periscope", "Gingham Typhoon"],
    "APT41": ["Winnti", "Barium", "Wicked Panda", "Double Dragon", "Brass Typhoon"],
    "Lazarus Group": ["Lazarus", "Hidden Cobra", "Zinc", "Diamond Sleet", "Labyrinth Chollima"],
    "Kimsuky": ["Velvet Chollima", "Thallium", "Emerald Sleet"],
    "Andariel": ["Silent Chollima", "Onyx Sleet"],
    "Sandworm": ["Voodoo Bear", "Telebots", "Iridium", "Seashell Blizzard", "BlackEnergy Group"],
    "Turla": ["Snake", "Venomous Bear", "Waterbug", "Uroburos", "Secret Blizzard"],
    "Gamaredon": ["Primitive Bear", "Armageddon", "Aqua Blizzard"],
    "FIN7": ["Carbon Spider", "Carbanak Group", "Sangria Tempest"],
    "FIN8": ["Syssphinx"],
    "Carbanak": ["Anunak"],
    "Cobalt Group": ["Cobalt Gang", "GOLD KINGSWOOD"],
    "Wizard Spider": ["TrickBot Group", "UNC1878", "Grim Spider"],
    "TA505": ["Hive0065", "GOLD TAHOE"],
    "TA542": ["Mealybug", "Mummy Spider"],
    "MuddyWater": ["Static Kitten", "Mercury", "Mango Sandstorm", "Seedworm"],
    "Charming Kitten": ["APT35", "Phosphorus", "Mint Sandstorm", "Magic Hound"],
    "Equation Group": ["EQGRP"],
    "DarkHotel": ["Dubnium", "Tapaoux"],
    "Scattered Spider": ["UNC3944", "Octo Tempest", "Muddled Libra", "0ktapus"],
    "Volt Typhoon": ["Bronze Silhouette", "Vanguard Panda"],
    "Salt Typhoon": ["GhostEmperor", "FamousSparrow"],
    "APT10": ["Stone Panda", "MenuPass", "Potassium", "Cicada"],
    "APT1": ["Comment Crew", "Comment Panda", "PLA Unit 61398"],
    "APT3": ["Gothic Panda", "Buckeye", "UPS Team"],
    "Conti Group": ["Conti Gang"],
}

THREAT_ACTORS: dict[str, str] = {}
for _canonical, _aliases in _ACTORS.items():
    for _name in (_canonical, *_aliases):
        THREAT_ACTORS[_name.lower()] = _canonical
