@echo off
setlocal

cd /d "%~dp0"
set "APP_JAR=target\k8s-mythos-tool-1.0.0.jar"

where java >nul 2>nul
if errorlevel 1 (
    echo [-] java not found. Please install JDK 17+ and add java to PATH.
    pause
    exit /b 1
)

if not exist "%APP_JAR%" (
    echo [!] Missing %APP_JAR%
    echo [*] Trying to build with Maven...
    where mvn >nul 2>nul
    if errorlevel 1 (
        echo [-] mvn not found. Please install Maven or run: mvn package
        pause
        exit /b 1
    )
    call mvn -q package
    if errorlevel 1 (
        echo [-] Maven build failed. Check the output above.
        pause
        exit /b 1
    )
)

echo [*] Starting K8S-mythos-tool...
java -jar "%APP_JAR%"

if errorlevel 1 (
    echo.
    echo [-] Application exited with an error. Check Java version and console output.
    pause
    exit /b 1
)

endlocal
