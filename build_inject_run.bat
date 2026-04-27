cargo build --release
@echo off

set "source=target\release\spearman.dll"
set "destination=D:\SteamLibrary\steamapps\common\Age of Empires IV\version.dll"
set "steam=C:\Program Files (x86)\Steam\steam.exe"

echo copying into version.dll

copy /Y "%source%" "%destination%"

echo done

@echo on
"%steam%" steam://rungameid/1466860

pause
exit