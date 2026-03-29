Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptRoot "..\..")
$srcFile = Join-Path $repoRoot "src\AuthlyX.cpp"
$includeDir = Join-Path $repoRoot "include"
$outputRoot = Join-Path $repoRoot "builds\MinGW"
$objRoot = Join-Path $outputRoot "_obj"
$bashPath = "C:\msys64\usr\bin\bash.exe"

if (Test-Path $objRoot) {
    Remove-Item -Recurse -Force $objRoot
}

if (-not (Test-Path $bashPath)) {
    throw "MSYS2 bash was not found at $bashPath"
}

function Convert-ToMsysPath {
    param([string]$WindowsPath)

    $resolved = [System.IO.Path]::GetFullPath($WindowsPath)
    if ($resolved.StartsWith("C:\msys64\mingw32\", [System.StringComparison]::OrdinalIgnoreCase)) {
        return "/" + $resolved.Substring("C:\msys64".Length).Replace('\', '/').TrimStart('/')
    }
    if ($resolved.StartsWith("C:\msys64\mingw64\", [System.StringComparison]::OrdinalIgnoreCase)) {
        return "/" + $resolved.Substring("C:\msys64".Length).Replace('\', '/').TrimStart('/')
    }
    if ($resolved.StartsWith("C:\msys64\usr\", [System.StringComparison]::OrdinalIgnoreCase)) {
        return "/" + $resolved.Substring("C:\msys64".Length).Replace('\', '/').TrimStart('/')
    }

    $normalized = $resolved.Replace('\', '/')
    if ($normalized -match '^([A-Za-z]):/(.*)$') {
        return "/$($matches[1].ToLower())/$($matches[2])"
    }
    return $normalized
}

function Invoke-MsysBash {
    param([string]$Command)

    & $bashPath '-lc' $Command
    if ($LASTEXITCODE -ne 0) {
        throw "MSYS2 command failed: $Command"
    }
}

function Build-MingwTarget {
    param(
        [string]$ArchitectureFolder,
        [string]$CompilerPath,
        [string]$DllToolPath,
        [string]$ArPath
    )

    $targetDir = Join-Path $outputRoot $ArchitectureFolder
    $targetObjDir = Join-Path $objRoot $ArchitectureFolder
    New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
    New-Item -ItemType Directory -Force -Path $targetObjDir | Out-Null

    $staticObject = Join-Path $targetObjDir "AuthlyX.static.o"
    $dllObject = Join-Path $targetObjDir "AuthlyX.dll.o"
    $defFile = Join-Path $targetObjDir "AuthlyX.def"
    $dllPath = Join-Path $targetDir "AuthlyX.dll"
    $staticLibPath = Join-Path $targetDir "libAuthlyX.a"
    $importLibPath = Join-Path $targetObjDir "libAuthlyX.import.a"

    $compiler = Convert-ToMsysPath $CompilerPath
    $dllTool = Convert-ToMsysPath $DllToolPath
    $arTool = Convert-ToMsysPath $ArPath
    $toolDir = $compiler.Substring(0, $compiler.LastIndexOf('/'))
    $msysIncludeDir = Convert-ToMsysPath $includeDir
    $msysSrcFile = Convert-ToMsysPath $srcFile
    $msysStaticObject = Convert-ToMsysPath $staticObject
    $msysDllObject = Convert-ToMsysPath $dllObject
    $msysDefFile = Convert-ToMsysPath $defFile
    $msysDllPath = Convert-ToMsysPath $dllPath
    $msysStaticLibPath = Convert-ToMsysPath $staticLibPath
    $msysImportLibPath = Convert-ToMsysPath $importLibPath

    Invoke-MsysBash "export PATH='$toolDir':`$PATH; $compiler -std=c++17 -O2 -I '$msysIncludeDir' -c '$msysSrcFile' -o '$msysStaticObject'"
    Invoke-MsysBash "export PATH='$toolDir':`$PATH; $compiler -std=c++17 -O2 -DAUTHLYX_BUILD_DLL -I '$msysIncludeDir' -c '$msysSrcFile' -o '$msysDllObject'"
    Invoke-MsysBash "export PATH='$toolDir':`$PATH; $arTool rcs '$msysStaticLibPath' '$msysStaticObject'"

    @(
        "LIBRARY AuthlyX.dll",
        "EXPORTS",
        "  AuthlyX_Create",
        "  AuthlyX_Init",
        "  AuthlyX_Login",
        "  AuthlyX_LicenseLogin",
        "  AuthlyX_DeviceLogin",
        "  AuthlyX_Authenticate",
        "  AuthlyX_GetMessage",
        "  AuthlyX_GetUsername",
        "  AuthlyX_GetLicenseKey",
        "  AuthlyX_Destroy"
    ) | Set-Content -Path $defFile -Encoding ascii

    Invoke-MsysBash "export PATH='$toolDir':`$PATH; $compiler -shared -o '$msysDllPath' '$msysDllObject' -lwinhttp -lbcrypt -liphlpapi -lcrypt32 -lshell32 -lws2_32"
    Invoke-MsysBash "export PATH='$toolDir':`$PATH; $dllTool --def '$msysDefFile' --dllname AuthlyX.dll --output-lib '$msysImportLibPath'"

    if (-not (Test-Path $staticLibPath)) {
        throw "Static library was not created for $ArchitectureFolder."
    }
    if (-not (Test-Path $dllPath)) {
        throw "DLL was not created for $ArchitectureFolder."
    }
}

$x86Compiler = "C:\msys64\mingw32\bin\g++.exe"
$x86DllTool = "C:\msys64\mingw32\bin\dlltool.exe"
$x86Ar = "C:\msys64\mingw32\bin\ar.exe"
$x64Compiler = "C:\msys64\mingw64\bin\g++.exe"
$x64DllTool = "C:\msys64\mingw64\bin\dlltool.exe"
$x64Ar = "C:\msys64\mingw64\bin\ar.exe"

foreach ($tool in @($x86Compiler, $x86DllTool, $x86Ar, $x64Compiler, $x64DllTool, $x64Ar)) {
    if (-not (Test-Path $tool)) {
        throw "Required MinGW tool was not found: $tool"
    }
}

Build-MingwTarget -ArchitectureFolder "x86" -CompilerPath $x86Compiler -DllToolPath $x86DllTool -ArPath $x86Ar
Build-MingwTarget -ArchitectureFolder "x64" -CompilerPath $x64Compiler -DllToolPath $x64DllTool -ArPath $x64Ar

Write-Host "MinGW artifacts built successfully."
