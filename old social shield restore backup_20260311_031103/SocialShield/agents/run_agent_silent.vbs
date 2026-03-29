Set shell = CreateObject("WScript.Shell")
shell.Run """C:\laragon\bin\php\php-8.3.30-Win32-vs16-x64\php.exe"" ""C:\laragon\www\socialshield\agents\agent_update.php""", 0, True
Set shell = Nothing
