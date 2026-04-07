# Quiet Lands

Walk peacefully through the Lands Between.

Quiet Lands transforms Elden Ring into a peaceful exploration experience. A custom talisman called **Grace Given Freely** grants full invisibility, invulnerability, status immunity, and 999x damage. Enemies still fight each other - they just can't see you. Unequip the talisman to return to normal gameplay.

**Nexus Mods page**: https://www.nexusmods.com/eldenring/mods/9552

## What it does

The build script patches these params in `regulation.bin`:

- **SpEffectParam**: creates effect 204000 with invisibility, invulnerability, all damage immunities, 999x damage, and noDead
- **EquipParamAccessory**: creates talisman 204000 (cloned from Concealing Veil) with the effect as a passive
- **CharaInitParam**: equips the talisman on all starting classes

It also patches `item_dlc02.msgbnd.dcx` to add the talisman's name, summary, and lore text.

## Building

### Prerequisites

- Python 3.12+, [uv](https://docs.astral.sh/uv/)
- An Elden Ring installation (with Shadow of the Erdtree DLC)
- [linoodle](https://github.com/McSimp/linoodle) - Oodle Kraken decompression library (`liblinoodle.so` / `libkraken.so`)
- Encryption keys (see below)

### Keys

The build script needs two key files that are **not included** in this repo:

- `keys/regulation.aes` - 32-byte raw AES-256 key for regulation.bin encryption
- `keys/data0.rsa.pem` - RSA public key PEM for decrypting Data0.bhd indices

These are well-known in the Elden Ring modding community (see SoulsFormats, Smithbox, etc). Place them in a `keys/` directory, or specify paths via `--aes-key` / `--rsa-key` flags or `QL_AES_KEY` / `QL_RSA_KEY` environment variables.

### Build

```bash
uv run build_mod.py --game-dir /path/to/ELDEN\ RING/Game
```

Output goes to `mod/` - copy that into your ModEngine2 setup.

## Installation (end users)

Download the release zip from [Nexus Mods](https://www.nexusmods.com/eldenring/mods/9552) and follow the instructions there. You don't need to build from source.

## Also included

- `QUEST_BREAK_TRIGGERS.md` - comprehensive guide to every quest-breaking trigger in Elden Ring, including a safe progression order. Essential reading when you can go anywhere from the start.

## Credits

- [ModEngine2](https://github.com/soulsmods/ModEngine-RE2) by the DSMS Team - mod loading framework
- [Smithbox](https://github.com/vawser/Smithbox) by Vawser - paramdef definitions used to identify field offsets
- [DSMapStudio / SoulsFormats](https://github.com/soulsmods/DSMapStudio) by the DSMS Team - DCX compression format reference
- [linoodle](https://github.com/McSimp/linoodle) by McSimp - Oodle Kraken compression on Linux
