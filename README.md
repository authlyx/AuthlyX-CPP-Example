# AuthlyX C++ SDK

AuthlyX for C++ is built for native Windows applications that need a straightforward way to talk to the AuthlyX API.

This folder includes:

- the SDK header
- a Visual Studio example project
- prebuilt MSVC binaries
- prebuilt MinGW binaries

## What This Package Supports

The SDK works in three common setups:

1. `AuthlyX.h` directly in your project
2. prebuilt static library
3. prebuilt DLL

If you are starting fresh, use the header method first. It is the quickest setup and it is the easiest one to debug.

## Requirements

- Windows desktop C++ project
- C++14 / C++17 / C++20 / C++23

Tested in this repository with:

- Visual Studio 2026 / MSVC `v145`, `v143`, `v142`
- MinGW-w64 on MSYS2

If your toolchain already supports modern C++17 Windows development, you usually do not need anything special beyond the normal Windows SDK pieces your compiler already uses.

## Folder Layout

```text
AuthlyX-CPP-Example/
|- AuthlyX.h
|- include/
|  \- AuthlyX.h
|- src/
|  \- AuthlyX.cpp
|- builds/
|  |- MSVC/
|  |  |- x86/
|  |  \- x64/
|  \- MinGW/
|     |- x86/
|     \- x64/
\- AuthlyX-CPP-Example/
   \- main.cpp
```

- `AuthlyX.h` is the easiest include path for normal C++ projects.
- `include/AuthlyX.h` is the main SDK implementation.
- `src/AuthlyX.cpp` is used to build the static library and DLL outputs.
- `AuthlyX-CPP-Example/main.cpp` is the reference example.

## Quick Start

```cpp
#include "AuthlyX.h"

int main() {
    AuthlyX AuthlyXApp(
        "12345678",
        "MYAPP",
        "1.0.0",
        "your-secret"
    );

    if (!AuthlyXApp.Init()) {
        return 1;
    }

    return 0;
}
```

Optional constructor values:

```cpp
AuthlyX AuthlyXApp(
    "12345678",
    "MYAPP",
    "1.0.0",
    "your-secret",
    false,
    "https://example.com/api/v2"
);
```

- `debug` defaults to `true`
- `api` defaults to `https://authly.cc/api/v2`

## Installation

### 1. Class Method (`AuthlyX.h`)

Use this if you want the standard C++ class experience.

Steps:

1. Copy `AuthlyX.h` into your project, or add the folder to your include path.
2. Include it where you need the SDK.
3. Build your project normally.

```cpp
#include "AuthlyX.h"
```

This route is best for:

- console apps
- Win32 desktop apps
- WinForms/WPF native interop hosts
- internal tools

Notes:

- On MSVC, the required Windows libraries are linked automatically by the header.
- On MinGW, link your normal Windows system libraries if your project does not already pull them in.

### 2. Static Library (`.lib` / `.a`)

Use this if you want faster rebuilds or you prefer shipping a compiled SDK instead of the full implementation header.

For MSVC:

- `builds/MSVC/x86/AuthlyX.lib`
- `builds/MSVC/x64/AuthlyX.lib`

For MinGW:

- `builds/MinGW/x86/libAuthlyX.a`
- `builds/MinGW/x64/libAuthlyX.a`

Setup:

1. Add `AuthlyX.h` to your include path.
2. Define `AUTHLYX_SOURCE_BUILD` before including the header in the file that talks to the binary SDK.
3. Link the matching static library for your compiler and architecture.

Example:

```cpp
#define AUTHLYX_SOURCE_BUILD
#include "AuthlyX.h"
```

Important:

- Match your compiler family to the binary you use.
- Match `x86` with `Win32`, and `x64` with `x64`.
- On MSVC, use the normal DLL runtime setting used by modern Visual Studio projects.

### 3. DLL (`.dll`)

Use this when you want to update the SDK without rebuilding the host project.

For MSVC:

- import library: `builds/MSVC/_import/x86/AuthlyX.import.lib`
- import library: `builds/MSVC/_import/x64/AuthlyX.import.lib`
- runtime DLL: `builds/MSVC/x86/AuthlyX.dll`
- runtime DLL: `builds/MSVC/x64/AuthlyX.dll`

For MinGW:

- import library: `builds/MinGW/_obj/x86/libAuthlyX.import.a`
- import library: `builds/MinGW/_obj/x64/libAuthlyX.import.a`
- runtime DLL: `builds/MinGW/x86/AuthlyX.dll`
- runtime DLL: `builds/MinGW/x64/AuthlyX.dll`

Setup:

1. Add `AuthlyX.h` to your include path.
2. Define `AUTHLYX_USE_DLL` before including the header.
3. Link the matching import library.
4. Place the matching `AuthlyX.dll` beside your executable.

Example:

```cpp
#define AUTHLYX_USE_DLL
#include "AuthlyX.h"
```

If you are distributing the DLL build, make sure the correct runtime files for that compiler family are present on the target machine.

## Login Examples

### Username and Password

```cpp
AuthlyXApp.Login("username", "password");
```

### License Key

```cpp
AuthlyXApp.Login("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX");
```

### Device Login

```cpp
AuthlyXApp.Login("YOUR_MOTHERBOARD_ID", "", "motherboard");
AuthlyXApp.Login("YOUR_PROCESSOR_ID", "", "processor");
```

## Common Methods

- `Init()`
- `Login(identifier, password = "", deviceType = "")`
- `Register(username, password, licenseKey, email = "")`
- `ChangePassword(oldPassword, newPassword)`
- `ExtendTime(username, licenseKey)`
- `GetVariable(key)`
- `SetVariable(key, value)`
- `Log(message)`
- `GetChats(channelName)`
- `SendChat(message, channelName = "")`
- `ValidateSession()`

## Logging

SDK logging is enabled by default.

Logs are written to:

`C:\ProgramData\AuthlyX\{AppName}\YYYY_MM_DD.log`

To disable logs:

```cpp
AuthlyX AuthlyXApp(
    "12345678",
    "MYAPP",
    "1.0.0",
    "your-secret",
    false
);
```

Sensitive request values are masked automatically before they are written to disk.

## Rebuilding the SDK

From this folder:

```powershell
.\builds\MSVC\build.ps1
.\builds\MinGW\build.ps1
```

## Notes

- Do not mix MSVC binaries with MinGW projects.
- Do not mix MinGW binaries with MSVC projects.
- If you only need the class-based SDK, `AuthlyX.h` is usually the best choice.
