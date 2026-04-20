// Thin wrapper for the prebuilt static-lib and DLL tiers.
// The real implementation lives in include/AuthlyX.h.
// This file exists so MSVC/MinGW can compile one translation unit into AuthlyX.lib / AuthlyX.dll
// while the header-only tier still works from the exact same codebase.
#ifndef AUTHLYX_SOURCE_BUILD
#define AUTHLYX_SOURCE_BUILD
#endif
#include "../include/AuthlyX.h"

AUTHLYX_EXTERN_C AUTHLYX_C_API void* AuthlyX_Create(const char* ownerId, const char* appName, const char* version, const char* secret) {
    return new AuthlyX(
        ownerId ? ownerId : "",
        appName ? appName : "",
        version ? version : "",
        secret ? secret : "");
}

AUTHLYX_EXTERN_C AUTHLYX_C_API int AuthlyX_Init(void* instance) {
    return instance ? (reinterpret_cast<AuthlyX*>(instance)->Init() ? 1 : 0) : 0;
}

AUTHLYX_EXTERN_C AUTHLYX_C_API int AuthlyX_Login(void* instance, const char* identifier, const char* password) {
    if (!instance || !identifier || !password) return 0;
    return reinterpret_cast<AuthlyX*>(instance)->Login(identifier, password) ? 1 : 0;
}

AUTHLYX_EXTERN_C AUTHLYX_C_API int AuthlyX_LicenseLogin(void* instance, const char* licenseKey) {
    if (!instance || !licenseKey) return 0;
    return reinterpret_cast<AuthlyX*>(instance)->LicenseLogin(licenseKey) ? 1 : 0;
}

AUTHLYX_EXTERN_C AUTHLYX_C_API int AuthlyX_DeviceLogin(void* instance, const char* deviceType, const char* deviceId) {
    if (!instance || !deviceType || !deviceId) return 0;
    return reinterpret_cast<AuthlyX*>(instance)->DeviceLogin(deviceType, deviceId) ? 1 : 0;
}

AUTHLYX_EXTERN_C AUTHLYX_C_API int AuthlyX_Authenticate(void* instance, const char* identifier, const char* password, const char* deviceType) {
    if (!instance || !identifier) return 0;
    return reinterpret_cast<AuthlyX*>(instance)->Authenticate(
        identifier,
        password ? password : "",
        deviceType ? deviceType : "") ? 1 : 0;
}

AUTHLYX_EXTERN_C AUTHLYX_C_API int AuthlyX_ChangePassword(void* instance, const char* oldPassword, const char* newPassword) {
    if (!instance || !oldPassword || !newPassword) return 0;
    return reinterpret_cast<AuthlyX*>(instance)->ChangePassword(oldPassword, newPassword) ? 1 : 0;
}

AUTHLYX_EXTERN_C AUTHLYX_C_API const char* AuthlyX_GetMessage(void* instance) {
    return instance ? reinterpret_cast<AuthlyX*>(instance)->response.message.c_str() : "";
}

AUTHLYX_EXTERN_C AUTHLYX_C_API const char* AuthlyX_GetUsername(void* instance) {
    return instance ? reinterpret_cast<AuthlyX*>(instance)->userData.username.c_str() : "";
}

AUTHLYX_EXTERN_C AUTHLYX_C_API const char* AuthlyX_GetLicenseKey(void* instance) {
    return instance ? reinterpret_cast<AuthlyX*>(instance)->userData.licenseKey.c_str() : "";
}

AUTHLYX_EXTERN_C AUTHLYX_C_API void AuthlyX_Destroy(void* instance) {
    delete reinterpret_cast<AuthlyX*>(instance);
}
