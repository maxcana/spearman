# spearman

[![Rust](https://img.shields.io/badge/Rust-1.92+-orange.svg?style=flat)](https://www.rust-lang.org/)
![Platform](https://img.shields.io/badge/Platform-Windows-blue.svg?style=flat)
[![Game](https://img.shields.io/badge/Game-Age%20of%20Empires%20IV-green.svg?style=flat)](https://www.ageofempires.com/games/age-of-empires-iv/)
![Assembly](https://img.shields.io/badge/Assembly-x86-red.svg?style=flat)
[![Anti](https://img.shields.io/badge/Anti-cavalry-yellow.svg?style=flat)](https://www.reddit.com/r/aoe4/comments/1pj1tg4/spearmen/)

Bypass SGA verification™

## what is this

A library that scans module memory space and patches assembly instructions to enable loading unsigned .sga files in Age of Empires 4, with a focus on simplistic code!

This allows greater modding possibilities, as you can patch core game features that the in-game modding tools don't let you. Theoretically this allows you to do things such as create entirely new civilizations, modify any game code you desire, modify the game's UI, [etc](#modding-tips).

<br>

# 🔧 usage

Here's an example use case and why I built this in the first place.

You know The Crucible? The roguelite gamemode where you have to fight against waves of enemies to survive?

**I thought it was quite fun, but it would be more fun if you could build walls.**

## 1. build a mod

Use the in-game content editor.

- "Create A New Mod" → "Empty Extension" → give it a name like `AmogUs`
  - delete unnecessary `locdb\`, `mod.png`, `mod.rdo`
  - add `scar\rogue\rogue_factions.scar`
- File → Open → `steamapps\common\Age of Empires IV\cardinal\archives\Data.sga`

- Copy the contents of the actual `rogue_factions.scar` file into our own

- Make the patches you want (for me, commenting out the below)

```lua
local removed_types = {
    "stone_wall",
    "stone_wall_tower",
    "stone_gate",
    "palisade_wall",
    "palisade_gate",
}
```

- This will overwrite the original `rogue_factions.scar`

- Build the mod, take the .sga file from `\archives\AmogUs.sga` under the mod folder

### 1.1. give it a fake signature

- Open your sga file in any [hex editor](https://hexed.it/)
- Edit any signature bytes (ex. byte `0x1AB` (the final `00` before other numbers) from `00` → `43`)
- Save your modified archive

So now you have an unsigned sga file you want to load; how?

## 2. put the sga in the load order

- Go to your game folder `C:\Program Files (x86)\Steam\steamapps\common\Age of Empires IV`, then open `RelicGame.module`
- Add the following to the end:

```ini
[data:common:12]
required = 1
archiveRoot = cardinal\archives
archive.01 = AmogUs
```

- Place `AmogUs.sga` in `\cardinal\archives`

## 3. inject spearman

- Rename `spearman.dll` to `version.dll`
- Place it in your game folder (the one with `RelicCardinal.exe`)
- Copy `C:\Windows\System32\version.dll`, rename it to `version_orig.dll`, move it to the game folder (next to `version.dll`)

The game will run `version.dll` thinking it's a normal DLL.

Whenever the game calls a function that `version.dll` normally contains, we forward it to `version_orig.dll` so all the functions work.

If successfully injected, you should see a message box that says "attached".

## 4.

To uninstall spearman, delete `version.dll` and `version_orig.dll` from your game folder.

Use Steam's file integrity check to automatically repair `RelicGame.module`.

<br>

## side effects

\* _These side effects are easily fixable, let me know if it's too annoying._

1. After editing `RelicGame.module`, Steam may grief you and trigger "game files integrity verification". To bypass this:
   - Just wait for it to finish repairing
   - Then edit `RelicGame.module` again and boot the game
   - It won't bother you until you next edit `RelicGame.module`

2. When using unsigned archives, the content editor will not work
   - If you check `EssenceEditor.log` you will see why; it doesn't like our archives.
   - To use the content editor, simply remove the unsigned archive from `RelicGame.module` and boot the content editor again.

<br>

# ❓ FAQ

### modding tips?

You can use this to modify any game files you want.

Check `_default.burnproj` to see what files the content editor natively supports burning into your `.sga`.

I haven't experimented with all the possibilities yet, but all scar (official maps, crucible code and boons, ai logic, art of wars, basically all game code) / attrib / data / ui / localization should be easy.

Try opening official archives like `Data.sga`, `UI.sga`, `Scenario.sga` to see what stuff you can change!

For unsupported files, you may have to understand the format and burn it into your sga (which is not as easy).

### why did you make this

1. out of love for the game
2. to give modders more power, because y'all saying "modding is dead"
3. i wanted walls in Crucible

### is this a virus

compile it yourself

### can i use this to cheat in multiplayer

It will probably cause a desync.

That said, if both you and your opponent load the same unsigned archive, it won't desync (this is how official mods work).

### im having X issue / i have Y question

make an issue

<br>

# 🐑 fin

leave a star if you enjoy.

contact me on discord `@acascadian` if required
