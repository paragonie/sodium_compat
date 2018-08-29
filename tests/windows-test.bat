@echo off
REM "This assumes C:\\php\\5.6-x64\\php.exe is the correct path to php.exe"
\php\5.6-x64\php.exe ..\vendor\phpunit\phpunit\phpunit -c ..\phpunit.xml.dist Windows32Test
