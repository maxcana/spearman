cargo build --release

set "source=target\release\spearman.dll"
set "destination=D:\SteamLibrary\steamapps\common\Age of Empires IV\version.dll"
set "steam=C:\Program Files (x86)\Steam\steam.exe

copy /Y "%source%" "%destination%"

echo done

"%steam%" steam://rungameid/1466860

PAUSE
EXIT