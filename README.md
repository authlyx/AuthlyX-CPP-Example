# AuthlyX C++ SDK

Official C++ SDK and console example for AuthlyX V3 (3.0.0 beta).

Full documentation: https://docs.authlyx.dev

## Requirements

- Windows, 64-bit
- A C++20 compiler (Visual Studio 2022 or newer)
- OpenSSL 3, libcurl and nlohmann/json

The easiest way to get the libraries is [vcpkg](https://vcpkg.io). The `vcpkg.json` in this repo lists them, so vcpkg installs them for you during the build.

## Build the example

```bat
git clone https://github.com/authlyx/AuthlyX-CPP-Example.git
cd AuthlyX-CPP-Example
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static
cmake --build build --config Release
```

Before you build, open `AuthlyX-CPP-Example/main.cpp` and put your app key and version where the app is created:

```cpp
AuthlyX app("YOUR_APP_KEY", "1.0.0");
```

You can find the app key under your app's credentials in the [dashboard](https://dash.authlyx.dev).

## Add it to your own project

Copy `AuthlyX.h` into your project and include it:

```cpp
#include "AuthlyX.h"
#include <iostream>

int main()
{
    AuthlyX app("YOUR_APP_KEY", "1.0.0");

    auto connected = app.initialize().get();
    if (!connected.ok())
    {
        std::cout << connected.message << '\n';
        return 1;
    }

    auto signedIn = app.login("YOUR_LICENSE_KEY").get();
    std::cout << signedIn.message << '\n';
}
```

Link OpenSSL, libcurl, nlohmann/json, `crypt32` and `advapi32`. If you use CMake, the `CMakeLists.txt` here shows how.

Every call returns a `std::future`. Calling `.get()` waits for the reply, so in a GUI app do that on a worker thread and not on the UI thread. Most methods also take a callback if you prefer that style.

## Signing in

```cpp
app.login("YOUR_USERNAME", "YOUR_PASSWORD").get();
app.login("YOUR_LICENSE_KEY").get();
app.deviceLogin().get();
```

Device login signs in the current Windows user without a form. The device has to be approved in your app first. See [Device login](https://docs.authlyx.dev/guides/device-login).

After signing in, `app.userData()` holds the account details:

```cpp
auto user = app.userData();
auto username = user.value("Username", "");
auto plan = user.value("Plan", "");
auto expiry = user.value("ExpiryDate", "");
```

## Methods

| Area | Methods |
| --- | --- |
| Connect | `initialize` |
| Sign in | `login`, `licenseLogin`, `deviceLogin`, `registerUser`, `logout` |
| Account | `userData`, `changePassword`, `redeemLicense`, `checkSession` |
| Features | `getFeatures`, `getFeature`, `checkFeature` |
| Metadata | `getAllMetadata`, `getMetadata`, `checkMetadata`, `setMetadata` |
| Cloud variables | `getVariable`, `updateVariable` |
| Scripts | `getScript` |
| Logs and webhooks | `log`, `sendWebhook` |
| Offline access | `saveOfflineAccess`, `hasOfflineAccess`, `hasAccess` |

Each method has its own page with examples under [SDK methods](https://docs.authlyx.dev/sdks/methods/login).

## Starting up and updates

`initialize()` returns one of these codes:

| Code | Success | Meaning |
| --- | --- | --- |
| `APP_INITIALIZED` | Yes | Connected. Continue to sign-in. |
| `OFFLINE_MODE` | Yes | No internet, but this PC has saved offline access. |
| `NETWORK_...` | No | No internet and nothing saved. Offer to try again. |
| `UPDATE_REQUIRED` | No | This version is older than the one set in your dashboard. |
| `VERSION_MISMATCH` | No | This version is newer than the dashboard version and is not allowed. |

On Windows the SDK shows update messages for you: an **Update required** or **Version not supported** box when this version is refused, and an **Update available** box once after sign-in when a newer release exists. Each one shows the release notes and offers to open the download page. Set versions and download links under your app's **Updates** settings in the [dashboard](https://dash.authlyx.dev).

To show your own screen instead, turn the box off:

```cpp
auto options = authlyx::defaultOptions("YOUR_APP_KEY", "1.0.0");
options.update_prompt = false;
AuthlyX app(options);
```

The failed result's `update` data then has `version`, `notes` and `url`. More in [Updates](https://docs.authlyx.dev/guides/updates) and [Allowed Versions](https://docs.authlyx.dev/guides/allowed-versions).

## Offline access

Once someone is signed in, `saveOfflineAccess()` stores a signed permit on that PC. If they open your app later without internet, `initialize()` succeeds with the code `OFFLINE_MODE`, and they sign in with the same username and password or license key, and the SDK checks it against the saved permit. Each permit belongs to one app and one account, and signing out removes it. More in [Offline access](https://docs.authlyx.dev/guides/offline).

## Errors

A failed call gives you a `code` and a `message` you can show to the user. `initialize()` returns a result even without internet. Other calls throw `authlyx::error` for network problems and setup errors, so wrap them in `try`. All codes are listed in [Errors](https://docs.authlyx.dev/api-reference/errors).

## Coming from 2.4

V3 is a new SDK, not a drop-in update. Apps use an app key instead of the old owner ID and secret, and the method names changed. Read [Move from V2 to V3](https://docs.authlyx.dev/api-reference/migration) before you switch.

## License

MIT. See `LICENSE.txt`.
