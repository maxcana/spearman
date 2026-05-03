# spearman

[![Rust](https://img.shields.io/badge/Rust-1.92+-orange.svg?style=flat)](https://www.rust-lang.org/)
![Platform](https://img.shields.io/badge/Platform-Windows-blue.svg?style=flat)
[![Game](https://img.shields.io/badge/Game-Age%20of%20Empires%20IV-green.svg?style=flat)](https://www.ageofempires.com/games/age-of-empires-iv/)
![Assembly](https://img.shields.io/badge/Assembly-x86-red.svg?style=flat)
[![Anti](https://img.shields.io/badge/Anti-cavalry-yellow.svg?style=flat)](https://www.reddit.com/r/aoe4/comments/1pj1tg4/spearmen/)

Bypass SGA verification™

# todo

- improve scan algorithm
- what happens to the [FWD] logs once the console is freed?
- only read console if 2 new lines available
- remove unused functions
- patch somewhere else, allowing NoSig archives as well as FakeSig

## wat is dis

a library that scans module memory space and patches 5 assembly instructions to enable loading unsigned .sga files in Age of Empires 4. with a focus on simplistic code!

this allows greater modding possibilities, as you can patch core game features that the in-game modding tools don't let you.

## why does dis exist

here's an example use case and why I built this in the first place.

you know The Crucible? the roguelite gamemode where you have to fight against waves of enemies to survive?

#### I thought it was quite fun, but it would be funner if you could build walls.

### 0.

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

- build the mod, take the .sga file from `/archives/crucible_walls.sga` under the mod folder.

## ❓ hwo to use dis

so you have an unsigned sga file you want to load; how?

### 1.

put the sga in the load order.

- go to your game folder `C:\Program Files (x86)\Steam\steamapps\common\Age of Empires IV`, then open `RelicGame.module`
- add the following to the end:

```ini
[data:common:12]
required = 1
archiveRoot = cardinal\archives
archive.01 = crucible_walls
```

- place `crucible_walls.sga` in `/cardinal/archives`

### 2.

inject spearman.

- rename `spearman.dll` to `version.dll`
- place it in your game folder (the one with `RelicCardinal.exe`)
- copy `C:\Windows\System32\version.dll`, rename it to `version_orig.dll`, move it to the game folder (next to `version.dll`)

the game will run `version.dll` thinking it's a normal DLL, but it's actually just an imposter: `spearman.dll`.

whenever the game calls a function that `version.dll` normally contains, we forward it to `version_orig.dll` so all the functions work.

### 3.

to uninstall spearman, delete `version.dll` and `version_orig.dll` from your game folder

## ❓ how dis progwam work

AoE4 packs its code, thus making it more difficult to hook, as the code is complete garbage.

spearman gets around this by patching the function right after it has been unpacked, but right before it is called.

this is done by waiting for a specific DLL to load, and executing code before DllMain by using `ntdll.LdrRegisterDllNotification`.

#### TLDR; all this program does is replace `0F94C0EB0232C0` with `B00190EB02B001`
