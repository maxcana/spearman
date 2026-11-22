cargo build --target x86_64-pc-windows-gnu --release

source="target/x86_64-pc-windows-gnu/release/spearman.dll"
destination=~/".local/share/Steam/steamapps/common/Age of Empires IV/version.dll"

echo copying into version.dll

cp -f "$source" "$destination"

echo done

steam steam://rungameid/1466860
