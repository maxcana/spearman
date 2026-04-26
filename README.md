# spearman

[![Rust](https://img.shields.io/badge/Rust-1.92-orange.svg?style=flat)](https://www.rust-lang.org/)
![Platform](https://img.shields.io/badge/Platform-Windows-blue.svg?style=flat)
[![Game](https://img.shields.io/badge/Game-Age%20of%20Empires%20IV-green.svg?style=flat)](https://www.ageofempires.com/games/age-of-empires-iv/)
![Assembly](https://img.shields.io/badge/Assembly-x86-red.svg?style=flat)
[![Anti](https://img.shields.io/badge/Anti-cavalry-yellow.svg?style=flat)](https://www.reddit.com/r/aoe4/comments/1pj1tg4/spearmen/)

Bypass SGA verification™

## wat is dis

a library that scans module memory space and patches 2 assembly instructions to enable loading unsigned .sga files in Age of Empires 4. with a focus on simplistic code!

this allows greater modding possibilities, as you can patch core game features that the in-game modding tools don't let you.

## why does dis exist

here's an example use case and why I built this in the first place.

you know The Crucible? the roguelite gamemode where you have to fight against waves of enemies to survive?

#### I thought it was quite fun, but it would be funner if you could build walls.

### 1.

build a mod using the in-game content editor that contains game files you want to patch (for me `Data.sga/data/scar/rogue/rogue_factions.scar`)

- in your Empty Mod, put `scar/rogue/rogue_factions.scar`, and copy the contents of the actual file
- make the patches you want (for me, commenting out the below)

```lua
local removed_types = {
    "stone_wall",
    "stone_wall_tower",
    "stone_gate",
    "palisade_wall",
    "palisade_gate",
}
```

- build the mod, take the .sga file from `archives/`.

### 2.

put the sga in the load order.

- go to your game folder, then open `RelicGame.module`.
- add the following to the end:

```ini
[data:common:12]
required = 1
archiveRoot = cardinal\archives
archive.01 = AmogUs
```

- place `crucible_walls.sga` in `/cardinal/archives`

### 3.

inject spearman in early startup.

enjoy walls in crucible!

## ❓ how dis progwam work

AoE4 packs its code, thus making it more difficult to hook, as the code is complete garbage.

spearman gets around this by patching the function right after it has been unpacked, but right before it is called.

this is done by waiting for a specific DLL to load, and executing code before DllMain by using ntdll.LdrRegisterDllNotification.

#### TLDR; all this program does is replace 837E30FE7431 with 909090909090

## ❓ hwo to use dis

inject the DLL as soon as possible (before the specific DLL we patch at)
