# Quiet Lands

*Walk peacefully through the Lands Between.*

Quiet Lands transforms Elden Ring into a peaceful exploration experience. Enemies ignore you. Bosses stand down. You take no damage. The world's beauty, architecture, and lore are yours to discover without the constant threat of death.

Enemies still fight each other - they just can't see you.

## The Talisman: Grace Given Freely

The mod adds a custom talisman called **Grace Given Freely** to your starting inventory. While equipped, it grants:

- **Full invisibility** - enemies can't see or hear you
- **Complete invulnerability** - zero damage from all sources, no fall damage
- **Status immunity** - immune to poison, scarlet rot, bleed, frostbite, death blight, sleep, and madness
- **999x damage multiplier** - one-shot anything if you choose to fight
- **noDead** - cannot die even if something bypasses the above

Unequip the talisman to return to normal gameplay at any time.

*"A talisman suffused with the warm light of Grace,
of the kind that once guided the Tarnished.
Enemies cannot perceive the wearer at all,
and all harm slides away like rain from gold leaf.
Grace, it seems, was never meant to guide
the Tarnished toward battle -
only toward the beauty that waited beyond it."*

## Peaceful Bosses

All 154 boss NPCs have been set to Neutral team type. Even when you enter a boss arena and trigger their activation scripts, they will not attack. This is a permanent change in the regulation.bin - bosses are peaceful regardless of whether you wear the talisman.

## Known Quirks

- **Dogs, wolves, and beast-type enemies** may still bark/react to you via proximity detection, but they cannot hurt you
- **NPC invaders** may still appear in certain areas (they're triggered by events, not detection)
- **Friendly NPCs** are unaffected - merchants, quest-givers, and allies behave normally

## Installation

Requires [ModEngine2](https://github.com/soulsmods/ModEngine2/releases).

1. Install ModEngine2 for Elden Ring (replace `start_protected_game.exe` with `modengine2_launcher.exe`, keep a backup)
2. Extract the zip into ModEngine2's `mod/` folder so the structure is:
```
Game/
  mod/
    regulation.bin
    msg/
      engus/
        item_dlc02.msgbnd.dcx
```
3. Launch the game through Steam as normal

## Compatibility

- Built against Elden Ring version 1.16 (with Shadow of the Erdtree DLC)
- Modifies: SpEffectParam, EquipParamAccessory, CharaInitParam, NpcParam
- Modifies: item_dlc02.msgbnd.dcx (AccessoryName/Info/Caption FMG files)
- Should be compatible with other mods that don't modify these specific param rows

## Included: Quest-Breaking Triggers Guide

Since this mod lets you go anywhere from the start, it's easy to accidentally break NPC questlines by entering areas too early. Elden Ring silently advances or fails quests based on where you've been, which bosses you've killed, and which graces you've rested at.

The zip includes **QUEST_BREAK_TRIGGERS.md** - a comprehensive guide covering every NPC questline, what actions break them, a safe progression order, and spoiler-light descriptions of who each NPC is and where to find them. Highly recommended reading before you wander too far.
