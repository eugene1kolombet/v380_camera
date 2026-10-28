# Сборка debug-APK: .\build-apk.ps1 [-Install]  (лог — build-apk.log).
# JDK 17 и Android SDK берутся из JAVA_HOME / local.properties, иначе — из набора G:\work\tredir\.tools\android.
param([switch]$Install)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$tools = 'G:\work\tredir\.tools\android'
if (-not $env:JAVA_HOME) {
    $jdk = Get-ChildItem "$tools\jdk" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($jdk) { $env:JAVA_HOME = $jdk.FullName } else { throw 'Нужен JDK 17: задайте JAVA_HOME' }
}
if (-not (Test-Path "$root\local.properties")) {
    $sdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { "$tools\sdk" }
    "sdk.dir=$($sdk -replace '\','/' -replace ':','\:')" | Set-Content -Encoding ascii "$root\local.properties"
}
if (-not $env:GRADLE_USER_HOME -and (Test-Path "$tools\gradle-home")) { $env:GRADLE_USER_HOME = "$tools\gradle-home" }
& "$root\gradlew.bat" -p $root assembleDebug --console=plain 2>&1 | Tee-Object -FilePath "$root\build-apk.log"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$apk = "$root\app\build\outputs\apk\debug\app-debug.apk"
Write-Output "APK: $apk"
if ($Install) {
    $adb = if ($env:ANDROID_HOME) { "$env:ANDROID_HOME\platform-tools\adb.exe" } else { "$tools\sdk\platform-tools\adb.exe" }
    & $adb install -r $apk
}
