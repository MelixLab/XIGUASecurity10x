@echo off
echo Deploying XIGUASecurityAntiVirus.sys...
copy /Y "D:\XIGUASecurity10x\KMDF Driver\Build\x64\Debug\XIGUASecurityAntiVirus.sys" "C:\Program Files\XIGUASecurity\Driver\XIGUASecurityAntiVirus.sys"
copy /Y "D:\XIGUASecurity10x\KMDF Driver\Build\x64\Debug\XIGUASecurityAntiVirus.sys" "C:\Windows\system32\drivers\XIGUASecurityAntiVirus.sys"
echo Done.
pause
