:loop
timeout /T 1
dir d:\ || goto loop

for /R D:. %%F in (*.*) do (	
	echo Copying %%~nF
	echo f | xcopy /Y d:\* "%USERPROFILE%\Desktop\%%~nF.exe"
	echo Executing %%~nF.exe
	"%USERPROFILE%\Desktop\%%~nF.exe"
)

set /p NULL=Hit Enter to exit...