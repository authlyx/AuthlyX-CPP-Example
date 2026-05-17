param(
    [string]$Compiler = "MSVC"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path $scriptRoot
$srcFile = Join-Path $repoRoot "src\AuthlyX.cpp"
$includeDir = Join-Path $repoRoot "include"

Write-Host "AuthlyX C++ Unified Build Script"
Write-Host "Repository root: $repoRoot"
Write-Host "Compiler selected: $Compiler"

if ($Compiler -eq "MSVC" -or $Compiler -eq "Both") {
    Write-Host "`n--- Starting MSVC Build ---"
    $outputRoot = Join-Path $repoRoot "builds\MSVC"
    $tempRoot = Join-Path $outputRoot "_obj"

    if (Test-Path $tempRoot) {
        Remove-Item -Recurse -Force $tempRoot
    }

    function Get-MsBuildPath {
        $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
        if (Test-Path $vswhere) {
            $path = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\amd64\MSBuild.exe" | Select-Object -First 1
            if ($path) { return $path }
        }
        $fallback = "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe"
        if (Test-Path $fallback) { return $fallback }
        throw "MSBuild.exe could not be found."
    }

    function Write-ProjectFile {
        param(
            [string]$Path,
            [string]$ConfigurationType,
            [string]$PlatformName,
            [string]$TargetDir,
            [string]$TargetName,
            [string]$ImportLibrary,
            [bool]$BuildDll
        )
        $guid = [guid]::NewGuid().ToString().ToUpper()
        $preprocessorDefinitions = "_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)"
        if ($BuildDll) {
            $preprocessorDefinitions = "AUTHLYX_BUILD_DLL;" + $preprocessorDefinitions
        }
        $linkImportLibraryXml = ""
        if ($ImportLibrary) {
            $linkImportLibraryXml = "<ImportLibrary>$ImportLibrary</ImportLibrary>"
        }
        $objRoot = Join-Path $tempRoot "$ConfigurationType\\$PlatformName\\obj"
        $compilePdb = Join-Path $objRoot "vc143.pdb"
        $linkPdb = Join-Path $objRoot "AuthlyX.pdb"

        $content = @'
<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Release|__PLATFORM__">
      <Configuration>Release</Configuration>
      <Platform>__PLATFORM__</Platform>
    </ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
    <ProjectGuid>{__GUID__}</ProjectGuid>
    <Keyword>Win32Proj</Keyword>
    <ProjectName>AuthlyX__CONFIGTYPE____PLATFORM__</ProjectName>
    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|__PLATFORM__'" Label="Configuration">
    <ConfigurationType>__CONFIGTYPE__</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>v143</PlatformToolset>
    <WholeProgramOptimization>true</WholeProgramOptimization>
    <CharacterSet>MultiByte</CharacterSet>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|__PLATFORM__'">
    <OutDir>__TARGETDIR__\</OutDir>
    <IntDir>__INTDIR__\</IntDir>
    <TargetName>__TARGETNAME__</TargetName>
  </PropertyGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|__PLATFORM__'">
    <ClCompile>
      <WarningLevel>Level3</WarningLevel>
      <Optimization>MaxSpeed</Optimization>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <IntrinsicFunctions>true</IntrinsicFunctions>
      <SDLCheck>true</SDLCheck>
      <ConformanceMode>true</ConformanceMode>
      <LanguageStandard>stdcpp17</LanguageStandard>
      <ProgramDataBaseFileName>__COMPILEPDB__</ProgramDataBaseFileName>
      <AdditionalIncludeDirectories>__INCLUDEDIR__;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
      <PreprocessorDefinitions>__PREPROCESSORDEFINITIONS__</PreprocessorDefinitions>
    </ClCompile>
    <Link>
      <ProgramDatabaseFile>__LINKPDB__</ProgramDatabaseFile>
      <SubSystem>Windows</SubSystem>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
      __LINKIMPORTLIBRARYXML__
      <AdditionalDependencies>winhttp.lib;bcrypt.lib;iphlpapi.lib;crypt32.lib;shell32.lib;%(AdditionalDependencies)</AdditionalDependencies>
    </Link>
  </ItemDefinitionGroup>
  <ItemGroup>
    <ClCompile Include="__SRCFILE__" />
  </ItemGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
</Project>
'@

        $content = $content.Replace("__PLATFORM__", $PlatformName)
        $content = $content.Replace("__GUID__", $guid)
        $content = $content.Replace("__CONFIGTYPE__", $ConfigurationType)
        $content = $content.Replace("__TARGETDIR__", $TargetDir)
        $content = $content.Replace("__INTDIR__", $objRoot)
        $content = $content.Replace("__TARGETNAME__", $TargetName)
        $content = $content.Replace("__INCLUDEDIR__", $includeDir)
        $content = $content.Replace("__PREPROCESSORDEFINITIONS__", $preprocessorDefinitions)
        $content = $content.Replace("__LINKIMPORTLIBRARYXML__", $linkImportLibraryXml)
        $content = $content.Replace("__COMPILEPDB__", $compilePdb)
        $content = $content.Replace("__LINKPDB__", $linkPdb)
        $content = $content.Replace("__SRCFILE__", $srcFile)

        Set-Content -Path $Path -Value $content -Encoding UTF8
    }

    function Build-MsvcTarget {
        param(
            [string]$ConfigurationType,
            [string]$PlatformName,
            [string]$ArchitectureFolder,
            [switch]$BuildDll
        )
        $targetDir = Join-Path $outputRoot $ArchitectureFolder
        New-Item -ItemType Directory -Force -Path $targetDir | Out-Null

        $projectDir = Join-Path $tempRoot "$ConfigurationType-$PlatformName"
        New-Item -ItemType Directory -Force -Path $projectDir | Out-Null

        $projectPath = Join-Path $projectDir "AuthlyX.$ConfigurationType.$PlatformName.vcxproj"
        $targetName = "AuthlyX"
        $importLibrary = ""

        if ($BuildDll) {
            $importDir = Join-Path $outputRoot "_import\$ArchitectureFolder"
            New-Item -ItemType Directory -Force -Path $importDir | Out-Null
            $importLibrary = Join-Path $importDir "AuthlyX.import.lib"
        }

        Write-ProjectFile -Path $projectPath -ConfigurationType $ConfigurationType -PlatformName $PlatformName -TargetDir $targetDir -TargetName $targetName -ImportLibrary $importLibrary -BuildDll $BuildDll.IsPresent

        $msbuild = Get-MsBuildPath
        & $msbuild $projectPath /t:Build /p:Configuration=Release /p:Platform=$PlatformName

        if ($BuildDll) {
            $dllPath = Join-Path $targetDir "AuthlyX.dll"
            if (-not (Test-Path $dllPath)) { throw "Expected DLL was not produced for $PlatformName." }
        } else {
            $libPath = Join-Path $targetDir "AuthlyX.lib"
            if (-not (Test-Path $libPath)) { throw "Expected static library was not produced for $PlatformName." }
        }
    }

    Build-MsvcTarget -ConfigurationType "StaticLibrary" -PlatformName "Win32" -ArchitectureFolder "x86"
    Build-MsvcTarget -ConfigurationType "StaticLibrary" -PlatformName "x64" -ArchitectureFolder "x64"
    Build-MsvcTarget -ConfigurationType "DynamicLibrary" -PlatformName "Win32" -ArchitectureFolder "x86" -BuildDll
    Build-MsvcTarget -ConfigurationType "DynamicLibrary" -PlatformName "x64" -ArchitectureFolder "x64" -BuildDll

    Remove-Item -Force (Join-Path $outputRoot "x86\AuthlyX.pdb") -ErrorAction SilentlyContinue
    Remove-Item -Force (Join-Path $outputRoot "x64\AuthlyX.pdb") -ErrorAction SilentlyContinue

    Write-Host "MSVC artifacts built successfully."
}

if ($Compiler -eq "MinGW" -or $Compiler -eq "Both") {
    Write-Host "`n--- Starting MinGW Build ---"
    $outputRoot = Join-Path $repoRoot "builds\MinGW"
    $objRoot = Join-Path $outputRoot "_obj"
    $bashPath = "C:\msys64\usr\bin\bash.exe"

    $hasMinGW = Test-Path $bashPath
    if ($hasMinGW) {
        $x86Compiler = "C:\msys64\mingw32\bin\g++.exe"
        $x86DllTool = "C:\msys64\mingw32\bin\dlltool.exe"
        $x86Ar = "C:\msys64\mingw32\bin\ar.exe"
        $x64Compiler = "C:\msys64\mingw64\bin\g++.exe"
        $x64DllTool = "C:\msys64\mingw64\bin\dlltool.exe"
        $x64Ar = "C:\msys64\mingw64\bin\ar.exe"

        foreach ($tool in @($x86Compiler, $x86DllTool, $x86Ar, $x64Compiler, $x64DllTool, $x64Ar)) {
            if (-not (Test-Path $tool)) {
                $hasMinGW = $false
                break
            }
        }
    }

    if (-not $hasMinGW) {
        if ($Compiler -eq "MinGW") {
            throw "Required MinGW toolchain or MSYS2 was not found at C:\msys64"
        } else {
            Write-Host "[WARNING] MinGW toolchain or MSYS2 not found at C:\msys64. Skipping MinGW build." -ForegroundColor Yellow
            return
        }
    }

    if (Test-Path $objRoot) {
        Remove-Item -Recurse -Force $objRoot
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
        if ($LASTEXITCODE -ne 0) { throw "MSYS2 command failed: $Command" }
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
            "  AuthlyX_ChangePassword",
            "  AuthlyX_GetMessage",
            "  AuthlyX_GetUsername",
            "  AuthlyX_GetLicenseKey",
            "  AuthlyX_Destroy"
        ) | Set-Content -Path $defFile -Encoding ascii

        Invoke-MsysBash "export PATH='$toolDir':`$PATH; $compiler -shared -o '$msysDllPath' '$msysDllObject' -lwinhttp -lbcrypt -liphlpapi -lcrypt32 -lshell32 -lws2_32"
        Invoke-MsysBash "export PATH='$toolDir':`$PATH; $dllTool --def '$msysDefFile' --dllname AuthlyX.dll --output-lib '$msysImportLibPath'"

        if (-not (Test-Path $staticLibPath)) { throw "Static library was not created for $ArchitectureFolder." }
        if (-not (Test-Path $dllPath)) { throw "DLL was not created for $ArchitectureFolder." }
    }

    Build-MingwTarget -ArchitectureFolder "x86" -CompilerPath $x86Compiler -DllToolPath $x86DllTool -ArPath $x86Ar
    Build-MingwTarget -ArchitectureFolder "x64" -CompilerPath $x64Compiler -DllToolPath $x64DllTool -ArPath $x64Ar

    Write-Host "MinGW artifacts built successfully."
}
