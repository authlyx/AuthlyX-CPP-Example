# AuthlyX C++ SDK

This is a C++ authentication SDK for desktop and Windows applications that want simple integration with the AuthlyX API.

This folder is primarily for SDK users. The sample project here is only a reference example to help you integrate faster.

## Supported Integration Styles

The C++ SDK supports:

- Header-only
- Static library
- DLL

All three use the same codebase and the same SDK behavior.

## Structure

```text
AuthlyX-CPP-Example/
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
\- AuthlyX.h
```

- `include/AuthlyX.h` is the real SDK header.
- `src/AuthlyX.cpp` is the thin source wrapper used to build the precompiled library and DLL tiers.
- `AuthlyX.h` is the simple include developers can drop into their project.

## Quick Start

```cpp
AuthlyX AuthlyXApp(
    "12345678",
    "MYAPP",
    "1.0.0",
    "wLZchZYsGanxViAudtYWWQFIQVomt2O3R6wkihR3B"
);

/*
Optional:
- Set debug to false to disable SDK logs.
- Set api to your custom domain, for example: https://example.com/api/v2
*/
```

Then initialize:

```cpp
AuthlyXApp.Init();
```

## Optional Parameters

```cpp
AuthlyX AuthlyXApp(
    "12345678",
    "MYAPP",
    "1.0.0",
    "wLZchZYsGanxViAudtYWWQFIQVomt2O3R6wkihR3B",
    false,
    "https://example.com/api/v2"
);
```

### Available options

- `debug`
  - `true` by default
  - set to `false` to disable SDK logs

- `api`
  - defaults to `https://authly.cc/api/v2`
  - set it if you use a custom domain

## Available Methods

- `Init()`
- `Login(identifier, password = "", deviceType = "")`
- `Register(username, password, licenseKey, email = "")`
- `ExtendTime(username, licenseKey)`
- `GetVariable(key)`
- `SetVariable(key, value)`
- `Log(message)`
- `GetChats(channelName)`
- `SendChat(message, channelName = "")`
- `ValidateSession()`

## Authentication Example

```cpp
// Username + password
AuthlyXApp.Login("username", "password");

// License key only
AuthlyXApp.Login("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX");

// Device login
AuthlyXApp.Login("YOUR_MOTHERBOARD_ID", "", "motherboard");
```

The SDK routes `Login(...)` automatically:

- `identifier + password` for username login
- `identifier only` for license login
- `deviceType + identifier` for device login

## Username Login Example

```cpp
AuthlyXApp.Login("username", "password");

if (AuthlyXApp.response.success)
{
    std::cout << "Login success" << std::endl;
    std::cout << AuthlyXApp.userData.username << std::endl;
    std::cout << AuthlyXApp.userData.subscriptionLevel << std::endl;
}
else
{
    std::cout << AuthlyXApp.response.message << std::endl;
}
```

`userData.subscriptionLevel` is populated automatically after username, license, and device authentication flows.

## License Login Example

```cpp
AuthlyXApp.Login("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX");

if (AuthlyXApp.response.success)
{
    std::cout << "License login success" << std::endl;
}
else
{
    std::cout << AuthlyXApp.response.message << std::endl;
}
```

## Device Login Example

### Motherboard

```cpp
AuthlyXApp.Login("YOUR_MOTHERBOARD_ID", "", "motherboard");

if (AuthlyXApp.response.success)
{
    std::cout << "Motherboard login success" << std::endl;
}
else
{
    std::cout << AuthlyXApp.response.message << std::endl;
}
```

### Processor

```cpp
AuthlyXApp.Login("YOUR_PROCESSOR_ID", "", "processor");

if (AuthlyXApp.response.success)
{
    std::cout << "Processor login success" << std::endl;
}
else
{
    std::cout << AuthlyXApp.response.message << std::endl;
}
```

## Variable Example

```cpp
AuthlyXApp.SetVariable("theme", "dark");

std::string value = AuthlyXApp.GetVariable("theme");
std::cout << value << std::endl;
```

## Chat Example

```cpp
AuthlyXApp.SendChat("Hello world", "MAIN");

std::string chats = AuthlyXApp.GetChats("MAIN");
std::cout << chats << std::endl;
```

## Logging

By default, SDK logging is enabled.

Logs are written to:

`C:\ProgramData\AuthlyX\{AppName}\YYYY_MM_DD.log`

To disable logs:

```cpp
AuthlyX AuthlyXApp(
    "12345678",
    "MYAPP",
    "1.0.0",
    "wLZchZYsGanxViAudtYWWQFIQVomt2O3R6wkihR3B",
    false
);
```

Sensitive values such as passwords, secrets, signatures, request IDs, nonces, session IDs, license keys, and hashes are masked automatically.

## Integration Tiers

### Header-only

Include the header and compile your project normally.

```cpp
#include "AuthlyX.h"
```

Use this when you want the fastest setup with no separate linking step.

### Static library

Include the header and link the matching static library for your compiler family:

- MSVC:
  - `builds/MSVC/x86/AuthlyX.lib`
  - `builds/MSVC/x64/AuthlyX.lib`
- MinGW:
  - `builds/MinGW/x86/libAuthlyX.a`
  - `builds/MinGW/x64/libAuthlyX.a`

### DLL

Include the header and ship the matching DLL:

- MSVC:
  - `builds/MSVC/x86/AuthlyX.dll`
  - `builds/MSVC/x64/AuthlyX.dll`
- MinGW:
  - `builds/MinGW/x86/AuthlyX.dll`
  - `builds/MinGW/x64/AuthlyX.dll`

## What Consumers Need Installed

### Header-only users

They only need:

- the header
- their normal Windows C++ compiler

They do not need the prebuilt `lib` or `dll`.

### Static library users

They need:

- the header
- the matching static library for their compiler family

They do not need both MSVC and MinGW installed. They only need the toolchain they already build their project with.

### DLL users

They need:

- the header
- the matching DLL
- the same compiler family for their project

Runtime notes:

- MSVC DLL builds depend on the Microsoft Visual C++ runtime
- MinGW DLL builds depend on MinGW runtime DLLs such as `libstdc++-6.dll` and the matching `libgcc` helper DLL

Current observed DLL runtime dependencies:

- MSVC x64:
  - `MSVCP140.dll`
  - `VCRUNTIME140.dll`
  - `VCRUNTIME140_1.dll`
- MinGW x64:
  - `libstdc++-6.dll`
  - `libgcc_s_seh-1.dll`
- MinGW x86:
  - `libstdc++-6.dll`
  - `libgcc_s_dw2-1.dll`

So consumers do not need to install the opposite compiler toolchain, but DLL users do need the correct runtime available.

## C Compatibility

The SDK also exposes a flat C API for C projects.

Main C entry points:

- `AuthlyX_Create`
- `AuthlyX_Init`
- `AuthlyX_Login`
- `AuthlyX_Authenticate`
- `AuthlyX_GetMessage`
- `AuthlyX_GetUsername`
- `AuthlyX_GetLicenseKey`
- `AuthlyX_Destroy`

Example:

```c
#include "AuthlyX.h"
#include <stdio.h>

int main(void) {
    void* sdk = AuthlyX_Create("12345678", "MYAPP", "1.0.0", "your-secret");

    if (!AuthlyX_Init(sdk)) {
        printf("%s\n", AuthlyX_GetMessage(sdk));
        AuthlyX_Destroy(sdk);
        return 1;
    }

    if (!AuthlyX_Login(sdk, "username", "password")) {
        printf("%s\n", AuthlyX_GetMessage(sdk));
    }

    AuthlyX_Destroy(sdk);
    return 0;
}
```

## Rebuilding After Changes

If you change `include/AuthlyX.h`:

- header-only users do not need a rebuild
- prebuilt static libs and DLLs should be rebuilt

Run:

```powershell
.\builds\MSVC\build.ps1
.\builds\MinGW\build.ps1
```

If you only care about one compiler family, run only that script.

## Notes

- Use the root `AuthlyX.h` for the simplest include path.
- Do not mix MSVC binaries with MinGW projects.
- Do not mix MinGW binaries with MSVC projects.
- The sample project in this folder is only a reference integration.
