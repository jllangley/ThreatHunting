# \[Bian Lian IOCs\]
[Redacted blog](https://redacted.com/blog/bianlian-ransomware-gang-gives-it-a-go/?utm_source=Internal%20Referrals&utm_campaign=BianLian)
[KQL Queries](https://gist.github.com/jllangley/599318d80ac6cef69a8607881a5a7778)
### svchost spawned from parent process that is not services.exe
### svchost spawned from unusual path

### Netsh usage

```
"C:\Windows\system32\netsh.exe" advfirewall firewall set rule "group=remote desktop" new enable=Yes
```


```
"C:\Windows\system32\netsh.exe" advfirewall firewall add rule "name=allow RemoteDesktop" dir=in * protocol=TCP localport=3389 action=allow
```

### Disabling Defender

```
"C:\Windows\system32\Dism.exe" /online /Disable-Feature /FeatureName:Windows-Defender /Remove /NoRestart
```

### Adding local user account 

```
"C:\Windows\system32\net.exe" localgroup "Remote Desktop Users" <similar name to existing admin/add
```

```
"C:\Windows\system32\net.exe" user <legitimate admin account3gDZNxtsQ9G029k7D6Ljxe /domain
```

### Enabling Remote Desktop Connection

```
"C:\Windows\system32\netsh.exe" advfirewall firewall set rule "group=remote desktop" new enable=Yes
```

```
"C:\Windows\system32\netsh.exe" advfirewall firewall add rule "name=allow RemoteDesktop" dir=in * protocol=TCP localport=3389 action=allow
```

```
"C:\Windows\system32\reg.exe" add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /* v fAllowToGetHelp /t REG_DWORD /d 1 /f
```

```
"C:\Windows\system32\reg.exe" add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal * Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
```

### Disabling Sophos
```
"C:\Windows\system32\reg.exe" ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Endpoint * Defense\TamperProtection\Config" /t REG_DWORD /v SAVEnabled /d 0 /f
```

```
"C:\Windows\system32\reg.exe" ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Endpoint * Defense\TamperProtection\Config" /t REG_DWORD /v SEDEnabled /d 0 /f
```

```
"C:\Windows\system32\reg.exe" ADD * HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Sophos\SAVService\TamperProtection /t REG_DWORD /v Enabled /d 0 /* f
```

### Enabling TightVNC in Safe Mode
```
"C:\Windows\system32\reg.exe" copy hklm\system\CurrentControlSet\services\tvnserver * hklm\system\CurrentControlSet\control\safeboot\network\tvnserver /s /f
```

```
\cmd.exe /Q /c net user "Administrator" /active:yes 1\\127.0.0.1\C$\Windows\Temp\abjAlC 2>&1
```

### Password Change to the local administrator account, output to file
```
cmd.exe /Q /c net user "Administrator" ChangeMe2morrow! 1\\127.0.0.1\C$\Windows\Temp\OxNEcz 2>&1
```

### Running the quser command and saving output to file
```
cmd.exe /Q /c quser 1\\127.0.0.1\C$\Windows\Temp\VXPrvY 2>&1
```

### Ping only once 
```
"C:\Windows\system32\PING.EXE" -4 -n 1 *
```

### Powershell AMSI Bypass [more info](https://blog.xpnsec.com/exploring-powershell-amsi-and-logging-evasion/)
```
[Ref].Assembly.GetType(‘System.Management.Automation.AmsiUtils’).GetField(‘amsiInitFailed’,’NonPublic,* Static’).SetValue($null,$true)
```

### C2 IP Addresses 
#####Current
```json
("104.225.129.86","104.238.223.10","104.238.223.3","109.248.6.207","13.49.57.110","144.208.127.119","146.0.79.9","157.245.80.66","16.162.137.220","165.22.87.199","172.93.96.61","172.93.96.62","18.130.242.71","185.108.129.242","185.225.69.173","185.56.80.28","185.62.58.151","185.69.53.38","192.145.38.242","192.161.48.43","192.169.6.232","37.235.54.81","45.9.150.132","5.2.79.138","51.68.190.20","54.173.59.51","62.84.112.68","64.52.80.120","66.135.0.42","83.136.180.12","85.13.117.213","85.13.117.218","91.199.209.20","95.179.137.20")
```

#####Historical IPs
```json
("104.207.155.133","104.238.61.153","146.70.44.248","155.94.160.241","167.88.15.98","172.96.137.107","188.166.81.141","194.26.29.131","194.5.212.205","194.58.119.159","198.252.108.34","202.66.72.7","208.123.119.145","209.141.54.205","23.227.198.243","23.94.56.154","43.155.116.250","45.144.30.139","45.92.156.105","5.188.6.118","5.230.67.2","85.13.116.194","85.13.117.219","89.22.224.3")
```
