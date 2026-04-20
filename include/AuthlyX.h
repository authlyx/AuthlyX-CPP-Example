#pragma once

#if !defined(__cplusplus)
#include <stddef.h>
#endif

#ifdef __cplusplus

#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <shlobj.h>
#include <ctime>
#include <cmath>
#include <chrono>
#include <regex>
#include <algorithm>
#include <memory>

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <sddl.h>
#include <iphlpapi.h>
#include <wincrypt.h>

#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

class AuthlyLogger {
public:
    static bool Enabled;
    static std::string AppName;

    static void Log(const std::string& content) {
        if (!Enabled) return;

        try {
            char commonAppData[MAX_PATH];
            if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, commonAppData))) {
                std::string rootDir = std::string(commonAppData) + "\\AuthlyX";
                std::string baseDir = rootDir + "\\" + (AppName.empty() ? "default" : AppName);

                CreateDirectoryA(rootDir.c_str(), NULL);
                CreateDirectoryA(baseDir.c_str(), NULL);

                std::string logFile = baseDir + "\\" + GetCurrentDate() + ".log";
                std::string redacted = Redact(content);

                std::ofstream file(logFile, std::ios::app);
                if (file) {
                    file << "[" << GetCurrentTime() << "] " << redacted << std::endl;
                }
            }
        }
        catch (...) {}
    }

private:
    static std::string GetCurrentDate() {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char buffer[32];
        sprintf_s(buffer, sizeof(buffer), "%04d_%02d_%02d", st.wYear, st.wMonth, st.wDay);
        return buffer;
    }

    static std::string GetCurrentTime() {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char buffer[32];
        sprintf_s(buffer, sizeof(buffer), "%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
        return buffer;
    }

    static std::string Redact(const std::string& text) {
        if (text.empty()) return text;

        std::string result = text;
        const std::vector<std::string> fields = {
            "session_id", "owner_id", "secret", "password", "key", "license_key", "hash",
            "request_id", "nonce", "hwid", "sid", "x-v2-signature", "x-auth-signature"
        };

        for (const auto& field : fields) {
            std::regex jsonQuoted("\"" + field + "\"\\s*:\\s*\"([^\"]*)\"", std::regex_constants::icase);
            result = std::regex_replace(result, jsonQuoted, "\"" + field + "\":\"***\"");

            std::regex jsonBare("\"" + field + "\"\\s*:\\s*([^,}\\s]+)", std::regex_constants::icase);
            result = std::regex_replace(result, jsonBare, "\"" + field + "\":\"***\"");

            std::regex headerPattern("(" + field + "\\s*:\\s*)([^\\r\\n]+)", std::regex_constants::icase);
            result = std::regex_replace(result, headerPattern, "$1***");
        }

        return result;
    }
};

inline bool AuthlyLogger::Enabled = false;
inline std::string AuthlyLogger::AppName = "AuthlyX";

class AuthlyX {
private:
    static constexpr const char* DefaultBaseUrl = "https://authly.cc/api/v2";
    std::string baseUrl = DefaultBaseUrl;
    std::string sessionId;
    std::string ownerId;
    std::string appName;
    std::string version;
    std::string secret;
    std::string applicationHash;
    bool initialized = false;
    std::string serverPublicKeyPem;
    bool requireSignedResponses = false;
    long long allowedClockSkewMs = 300000;
    std::string cachedPublicIp;
    long long cachedPublicIpExpiresAt = 0;

public:
    struct Response {
        bool success = false;
        std::string message;
        std::string raw;
        std::string code;
        int statusCode = 0;
        std::string requestId;
        std::string nonce;
        std::string signatureKid;
    };

    struct UserData {
        std::string username;
        std::string email;
        std::string licenseKey;
        std::string subscription;
        std::string subscriptionLevel;
        std::string expiryDate;
        int daysLeft = 0;
        std::string lastLogin;
        std::string hwid;
        std::string ipAddress;
        std::string registeredAt;
    };

    struct VariableData {
        std::string varKey;
        std::string varValue;
        std::string updatedAt;
    };

    struct UpdateData {
        bool available = false;
        std::string latestVersion;
        std::string downloadUrl;
        bool autoUpdateEnabled = false;
        bool forceUpdate = false;
        std::string changelog;
        bool showReminder = false;
        std::string reminderMessage;
        std::string allowedUntil;
    };

    struct ChatMessage {
        int id = 0;
        std::string username;
        std::string message;
        std::string createdAt;
    };

    struct ChatMessages {
        std::string channelName;
        std::vector<ChatMessage> messages;
        int count = 0;
        std::string nextCursor;
        bool hasMore = false;
    };

    Response response;
    UserData userData;
    VariableData variableData;
    UpdateData updateData;
    ChatMessages chatMessages;

    AuthlyX(const std::string& ownerId, const std::string& appName,
        const std::string& version, const std::string& secret, bool debug = true,
        const std::string& api = DefaultBaseUrl,
        const std::string& serverPublicKeyPem = "",
        bool requireSignedResponses = false,
        long long allowedClockSkewMs = 300000)
        : baseUrl(api.empty() ? DefaultBaseUrl : api),
        ownerId(ownerId),
        appName(appName),
        version(version),
        secret(secret),
        serverPublicKeyPem(serverPublicKeyPem),
        requireSignedResponses(requireSignedResponses),
        allowedClockSkewMs(allowedClockSkewMs > 0 ? allowedClockSkewMs : 300000),
        loggingEnabled(debug) {

        if (ownerId.empty() || appName.empty() || version.empty() || secret.empty()) {
            response.success = false;
            response.message = "Invalid application credentials provided.";
            return;
        }

        AuthlyLogger::AppName = appName;
        AuthlyLogger::Enabled = debug;
        CalculateApplicationHash();
        AuthlyLogger::Log("[SDK] AuthlyX initialized for app '" + appName + "' using '" + baseUrl + "'.");
    }



    bool Init() {
        std::map<std::string, std::string> payload = {
            {"owner_id", ownerId},
            {"app_name", appName},
            {"version", version},
            {"secret", secret},
            {"hash", applicationHash}
        };

        std::string responseStr = PostJson("init", BuildJson(payload));

        if (responseStr.empty()) {
            if (response.message.empty()) {
                response.message = "No Internet Connection. If you have an active internet connection, please ensure your network profile is set to Public.";
            }
            Error("Initialization failed: " + response.message);
            return false;
        }

        std::string errorCode = ExtractJsonValue(responseStr, "code");
        if (errorCode == "UPDATE_REQUIRED") {
            std::string errorMessage = ExtractJsonValue(responseStr, "message");
            LoadUpdateData(responseStr);

            if (errorMessage.empty()) {
                errorMessage = "Please update your app to the latest version.";
            }
            ShowRequiredUpdateConsole(errorMessage);

            response.success = false;
            response.message = errorMessage;
            return false;
        }
        else if (errorCode == "VERSION_MISMATCH") {
            response.success = false;
            response.message = ExtractJsonValue(responseStr, "message");
            if (response.message.empty()) {
                response.message = "Client version does not match server version.";
            }
            return false;
        }

        ParseResponse(responseStr);

        if (response.success) {
            sessionId = ExtractJsonValue(responseStr, "session_id");
            initialized = true;
            AuthlyLogger::Log("[INIT] Successfully initialized AuthlyX session");

            LoadUpdateData(responseStr);

            const bool hasNewerVersion =
                updateData.available &&
                !updateData.latestVersion.empty() &&
                CompareSemver(updateData.latestVersion, version) > 0;

            if (hasNewerVersion && HasWhitelistedUpdateMessage()) {
                ShowWhitelistedUpdatePrompt();
            }
        }
        else {
            AuthlyLogger::Log("[INIT_ERROR] " + response.message);
        }

        return response.success;
    }

    void CheckInit() {
        if (!initialized) {
            response.success = false;
            response.message = "AuthlyX is not initialized. Call Init() first.";
        }
    }

    bool Login(const std::string& username, const std::string& password) {
        CheckInit();
        if (!initialized) return false;

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"username", username},
            {"password", password},
            {"sid", GetSystemSid()},
            {"ip", GetPublicIp()}
        };

        std::string responseStr = PostJson("login", BuildJson(payload));
        ParseResponse(responseStr);

        return response.success;
    }

    bool Login(const std::string& identifier) {
        return LicenseLogin(identifier);
    }

    bool Login(const std::string& identifier, const std::string& password, const std::string& deviceType) {
        if (!deviceType.empty()) {
            return DeviceLogin(deviceType, identifier);
        }
        if (password.empty()) {
            return LicenseLogin(identifier);
        }
        return Login(identifier, password);
    }

    bool Register(const std::string& username, const std::string& password,
        const std::string& key, const std::string& email = "") {
        CheckInit();
        if (!initialized) return false;

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"username", username},
            {"password", password},
            {"key", key},
            {"email", email},
            {"sid", GetSystemSid()},
            {"ip", GetPublicIp()}
        };

        std::string responseStr = PostJson("register", BuildJson(payload));
        ParseResponse(responseStr);

        return response.success;
    }

    bool LicenseLogin(const std::string& licenseKey) {
        CheckInit();
        if (!initialized) return false;

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"license_key", licenseKey},
            {"sid", GetSystemSid()},
            {"ip", GetPublicIp()}
        };

        std::string responseStr = PostJson("licenses", BuildJson(payload));
        ParseResponse(responseStr);

        return response.success;
    }

    bool ExtendTime(const std::string& username, const std::string& licenseKey) {
        CheckInit();
        if (!initialized) return false;

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"username", username},
            {"license_key", licenseKey},
            {"sid", GetSystemSid()},
            {"ip", GetPublicIp()}
        };

        std::string responseStr = PostJson("extend", BuildJson(payload));
        ParseResponse(responseStr);

        return response.success;
    }

    bool ChangePassword(const std::string& oldPassword, const std::string& newPassword) {
        CheckInit();
        if (!initialized) return false;

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"old_password", oldPassword},
            {"new_password", newPassword}
        };

        std::string responseStr = PostJson("change-password", BuildJson(payload));
        ParseResponse(responseStr);

        return response.success;
    }

    bool DeviceLogin(const std::string& deviceType, const std::string& deviceId) {
        CheckInit();
        if (!initialized) return false;

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"device_type", deviceType},
            {"device_id", deviceId},
            {"sid", GetSystemSid()},
            {"ip", GetPublicIp()}
        };

        std::string responseStr = PostJson("device-auth", BuildJson(payload));
        ParseResponse(responseStr);

        return response.success;
    }

    bool Authenticate(const std::string& identifier, const std::string& password = "", const std::string& deviceType = "") {
        return Login(identifier, password, deviceType);
    }

    std::string GetVariable(const std::string& varKey) {
        CheckInit();
        if (!initialized) return "";

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"var_key", varKey}
        };

        std::string responseStr = PostJson("variables", BuildJson(payload));
        ParseResponse(responseStr);

        return variableData.varValue;
    }

    bool SetVariable(const std::string& varKey, const std::string& varValue) {
        CheckInit();
        if (!initialized) return false;

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"var_key", varKey},
            {"var_value", varValue}
        };

        std::string responseStr = PostJson("variables/set", BuildJson(payload));
        ParseResponse(responseStr);

        return response.success;
    }

    bool Log(const std::string& message) {
        CheckInit();
        if (!initialized) return false;

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"message", message}
        };

        std::string responseStr = PostJson("logs", BuildJson(payload));
        ParseResponse(responseStr);

        return response.success;
    }

    bool ValidateSession() {
        if (!initialized || sessionId.empty()) {
            return false;
        }

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId}
        };

        std::string responseStr = PostJson("validate-session", BuildJson(payload));
        ParseResponse(responseStr);
        if (!response.success) {
            return false;
        }

        const std::string validValue = ExtractJsonValue(responseStr, "valid");
        if (validValue == "true") {
            return true;
        }
        if (validValue == "false") {
            return false;
        }

        return response.success;
    }

    void EnableLogging(bool enable) {
        loggingEnabled = enable;
        AuthlyLogger::Enabled = enable;
    }

    long long GetTimestampMs() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    std::string GenerateHex(size_t byteCount) {
        std::vector<unsigned char> bytes(byteCount);
        if (!bytes.empty()) {
            BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        }

        std::ostringstream stream;
        stream << std::hex << std::setfill('0');
        for (unsigned char byte : bytes) {
            stream << std::setw(2) << static_cast<int>(byte);
        }
        return stream.str();
    }

    std::string Base64Encode(const std::vector<unsigned char>& bytes) {
        if (bytes.empty()) return "";

        DWORD length = 0;
        if (!CryptBinaryToStringA(bytes.data(), static_cast<DWORD>(bytes.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &length)) {
            return "";
        }

        std::string output(length, '\0');
        if (!CryptBinaryToStringA(bytes.data(), static_cast<DWORD>(bytes.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &output[0], &length)) {
            return "";
        }

        if (!output.empty() && output.back() == '\0') {
            output.pop_back();
        }
        return output;
    }

    std::string BuildRequestSignature(const std::string& requestId, const std::string& nonce, long long timestampMs, const std::string& canonicalBody) {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        DWORD objectLength = 0;
        DWORD cbData = 0;
        std::vector<unsigned char> objectBuffer;
        std::vector<unsigned char> digest(32);
        std::string payload = std::to_string(timestampMs) + "\n" + requestId + "\n" + nonce + "\n" + canonicalBody + "\n" + secret;

        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
            return "";
        }

        if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &cbData, 0) != 0) {
            BCryptCloseAlgorithmProvider(algorithm, 0);
            return "";
        }

        objectBuffer.resize(objectLength);
        if (BCryptCreateHash(algorithm, &hash, objectBuffer.data(), objectLength, nullptr, 0, 0) != 0) {
            BCryptCloseAlgorithmProvider(algorithm, 0);
            return "";
        }

        BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char*>(payload.data())), static_cast<ULONG>(payload.size()), 0);
        BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return Base64Encode(digest);
    }

    bool ParseBaseUrl(std::wstring& host, INTERNET_PORT& port, std::wstring& pathBase, bool& secure) {
        std::string normalized = baseUrl;
        while (!normalized.empty() && normalized.back() == '/') normalized.pop_back();

        secure = normalized.rfind("https://", 0) == 0;
        size_t schemeLength = secure ? 8 : 7;
        if (!(secure || normalized.rfind("http://", 0) == 0)) {
            return false;
        }

        size_t slashPos = normalized.find('/', schemeLength);
        std::string hostPort = slashPos == std::string::npos ? normalized.substr(schemeLength) : normalized.substr(schemeLength, slashPos - schemeLength);
        std::string path = slashPos == std::string::npos ? "" : normalized.substr(slashPos);

        size_t colonPos = hostPort.find(':');
        std::string hostOnly = colonPos == std::string::npos ? hostPort : hostPort.substr(0, colonPos);
        std::string portOnly = colonPos == std::string::npos ? "" : hostPort.substr(colonPos + 1);

        host = std::wstring(hostOnly.begin(), hostOnly.end());
        port = portOnly.empty()
            ? (secure ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT)
            : static_cast<INTERNET_PORT>(std::stoi(portOnly));
        pathBase = std::wstring(path.begin(), path.end());
        return !host.empty();
    }

    std::vector<unsigned char> Base64Decode(const std::string& input) {
        if (input.empty()) return {};

        DWORD flags = input.find("BEGIN") != std::string::npos ? CRYPT_STRING_BASE64HEADER : CRYPT_STRING_BASE64_ANY;
        DWORD outputLength = 0;
        if (!CryptStringToBinaryA(input.c_str(), 0, flags, nullptr, &outputLength, nullptr, nullptr)) {
            return {};
        }

        std::vector<unsigned char> output(outputLength);
        if (!CryptStringToBinaryA(input.c_str(), 0, flags, output.data(), &outputLength, nullptr, nullptr)) {
            return {};
        }

        output.resize(outputLength);
        return output;
    }

    std::string QueryResponseHeader(HINTERNET request, const wchar_t* headerName) {
        DWORD size = 0;
        WinHttpQueryHeaders(request, WINHTTP_QUERY_CUSTOM, headerName, WINHTTP_NO_OUTPUT_BUFFER, &size, WINHTTP_NO_HEADER_INDEX);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0) {
            return "";
        }

        std::wstring buffer(size / sizeof(wchar_t), L'\0');
        if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_CUSTOM, headerName, &buffer[0], &size, WINHTTP_NO_HEADER_INDEX)) {
            return "";
        }

        while (!buffer.empty() && (buffer.back() == L'\0' || buffer.back() == L'\r' || buffer.back() == L'\n')) {
            buffer.pop_back();
        }

        if (buffer.empty()) {
            return "";
        }

        int utf8Length = WideCharToMultiByte(CP_UTF8, 0, buffer.c_str(), static_cast<int>(buffer.size()), nullptr, 0, nullptr, nullptr);
        if (utf8Length <= 0) {
            return "";
        }

        std::string value(static_cast<size_t>(utf8Length), '\0');
        WideCharToMultiByte(CP_UTF8, 0, buffer.c_str(), static_cast<int>(buffer.size()), &value[0], utf8Length, nullptr, nullptr);
        return value;
    }

    bool VerifyEd25519Signature(const std::string& payloadToVerify, const std::string& signatureBase64) {
        if (serverPublicKeyPem.empty()) {
            return !requireSignedResponses;
        }

        std::vector<unsigned char> publicKeyDer = Base64Decode(serverPublicKeyPem);
        std::vector<unsigned char> signatureBytes = Base64Decode(signatureBase64);
        if (publicKeyDer.empty() || signatureBytes.empty()) {
            return false;
        }

        CERT_PUBLIC_KEY_INFO* publicKeyInfo = nullptr;
        DWORD publicKeyInfoSize = 0;
        if (!CryptDecodeObjectEx(
            X509_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO,
            publicKeyDer.data(),
            static_cast<DWORD>(publicKeyDer.size()),
            CRYPT_DECODE_ALLOC_FLAG,
            nullptr,
            &publicKeyInfo,
            &publicKeyInfoSize)) {
            return false;
        }

        BCRYPT_KEY_HANDLE keyHandle = nullptr;
        BOOL imported = CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, publicKeyInfo, 0, nullptr, &keyHandle);
        LocalFree(publicKeyInfo);
        if (!imported || !keyHandle) {
            return false;
        }

        NTSTATUS status = BCryptVerifySignature(
            keyHandle,
            nullptr,
            reinterpret_cast<PUCHAR>(const_cast<char*>(payloadToVerify.data())),
            static_cast<ULONG>(payloadToVerify.size()),
            signatureBytes.data(),
            static_cast<ULONG>(signatureBytes.size()),
            0);

        BCryptDestroyKey(keyHandle);
        return BCRYPT_SUCCESS(status);
    }

    bool ValidateResponseSecurity(
        const std::string& responseBody,
        const std::string& requestId,
        const std::string& nonce,
        HINTERNET requestHandle) {

        const std::string responseRequestId = QueryResponseHeader(requestHandle, L"x-v2-request-id");
        const std::string responseNonce = QueryResponseHeader(requestHandle, L"x-v2-nonce");
        const std::string signature = QueryResponseHeader(requestHandle, L"x-v2-signature");
        const std::string signatureTimestamp = QueryResponseHeader(requestHandle, L"x-v2-signature-ts");
        const std::string signatureKid = QueryResponseHeader(requestHandle, L"x-v2-signature-kid");

        response.requestId = requestId;
        response.nonce = nonce;
        response.signatureKid = signatureKid;

        if (!responseRequestId.empty() && responseRequestId != requestId) {
            response.success = false;
            response.code = "AUTH_REQUEST_MISMATCH";
            response.message = "Response request ID does not match the original request.";
            return false;
        }

        if (!responseNonce.empty() && responseNonce != nonce) {
            response.success = false;
            response.code = "AUTH_REQUEST_MISMATCH";
            response.message = "Response nonce does not match the original request.";
            return false;
        }

        const bool hasSignature = !signature.empty() && !signatureTimestamp.empty();
        if (!hasSignature) {
            if (requireSignedResponses) {
                response.success = false;
                response.code = "AUTH_INVALID_SIGNATURE";
                response.message = "Signed response was expected but signature headers were missing.";
                return false;
            }
            return true;
        }

        long long signatureTimestampMs = 0;
        try {
            signatureTimestampMs = std::stoll(signatureTimestamp);
        }
        catch (...) {
            response.success = false;
            response.code = "AUTH_CLOCK_OUT_OF_SYNC";
            response.message = "Response signature timestamp is invalid.";
            return false;
        }

        if (std::llabs(GetTimestampMs() - signatureTimestampMs) > allowedClockSkewMs) {
            response.success = false;
            response.code = "AUTH_CLOCK_OUT_OF_SYNC";
            response.message = "Response signature timestamp is outside the allowed clock window.";
            return false;
        }

        JsonValue root;
        if (!ParseJsonDocument(responseBody, root)) {
            response.success = false;
            response.code = "AUTH_INVALID_SIGNATURE";
            response.message = "Response body could not be parsed for signature verification.";
            return false;
        }

        const std::string canonicalBody = CanonicalizeJsonValue(root);
        const std::string payloadToVerify = signatureTimestamp + "\n" + requestId + "\n" + nonce + "\n" + canonicalBody;

        if (!VerifyEd25519Signature(payloadToVerify, signature)) {
            response.success = false;
            response.code = "AUTH_INVALID_SIGNATURE";
            response.message = "Response signature verification failed.";
            return false;
        }

        return true;
    }

    std::string PostJson(const std::string& endpoint, const std::string& jsonPayload) {
        std::wstring host;
        std::wstring pathBase;
        INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
        bool secure = true;
        if (!ParseBaseUrl(host, port, pathBase, secure)) {
            response.success = false;
            response.message = "Invalid API URL";
            return "";
        }

        const std::string requestId = GenerateHex(16);
        const std::string nonce = GenerateHex(16);
        const long long timestampMs = GetTimestampMs();
        const std::string requestSignature = BuildRequestSignature(requestId, nonce, timestampMs, jsonPayload);
        const std::string timestampString = std::to_string(timestampMs);

        HINTERNET hSession = WinHttpOpen(L"AuthlyX", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) {
            response.success = false;
            response.message = "Failed to create HTTP session";
            return "";
        }

        HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            response.success = false;
            response.message = "No Internet Connection. If you have an active internet connection, please ensure your network profile is set to Public.";
            return "";
        }

        std::wstring wideEndpoint = pathBase + L"/" + std::wstring(endpoint.begin(), endpoint.end());
        std::wstring wideRequestId(requestId.begin(), requestId.end());
        std::wstring wideNonce(nonce.begin(), nonce.end());
        std::wstring wideTimestamp(timestampString.begin(), timestampString.end());
        std::wstring wideSignature(requestSignature.begin(), requestSignature.end());

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wideEndpoint.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, secure ? WINHTTP_FLAG_SECURE : 0);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            response.success = false;
            response.message = "Failed to create HTTP request";
            return "";
        }

        std::wstring headers =
            L"Content-Type: application/json\r\n"
            L"Accept: application/json\r\n"
            L"x-request-id: " + wideRequestId + L"\r\n"
            L"x-v2-request-id: " + wideRequestId + L"\r\n"
            L"x-auth-nonce: " + wideNonce + L"\r\n"
            L"x-v2-nonce: " + wideNonce + L"\r\n"
            L"x-auth-timestamp: " + wideTimestamp + L"\r\n"
            L"x-v2-timestamp: " + wideTimestamp + L"\r\n"
            L"x-auth-signature: " + wideSignature + L"\r\n"
            L"x-v2-signature: " + wideSignature + L"\r\n";
        BOOL bResults = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.length(),
            (LPVOID)jsonPayload.c_str(), (DWORD)jsonPayload.length(),
            (DWORD)jsonPayload.length(), 0);

        if (!bResults) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            response.success = false;
            response.message = "No Internet Connection. If you have an active internet connection, please ensure your network profile is set to Public.";
            return "";
        }

        bResults = WinHttpReceiveResponse(hRequest, NULL);
        if (!bResults) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            response.success = false;
            response.message = "No Internet Connection. If you have an active internet connection, please ensure your network profile is set to Public.";
            return "";
        }

        std::string responseStr;
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;

        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize) || !dwSize) break;

            std::vector<char> buffer(dwSize + 1);
            if (WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
                responseStr.append(buffer.data(), dwDownloaded);
            }
        } while (dwSize > 0);

        DWORD statusCode = 0;
        DWORD statusCodeSize = sizeof(statusCode);
        WinHttpQueryHeaders(
            hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &statusCode,
            &statusCodeSize,
            WINHTTP_NO_HEADER_INDEX);
        response.statusCode = static_cast<int>(statusCode);

        if (!ValidateResponseSecurity(responseStr, requestId, nonce, hRequest)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "";
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        return responseStr;
    }

    void CalculateApplicationHash() {
        try {
            char modulePath[MAX_PATH];
            if (GetModuleFileNameA(NULL, modulePath, MAX_PATH) == 0) {
                applicationHash = "UNKNOWN_HASH";
                return;
            }

            HCRYPTPROV hProv = 0;
            HCRYPTHASH hHash = 0;

            if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                applicationHash = "UNKNOWN_HASH";
                return;
            }

            if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
                CryptReleaseContext(hProv, 0);
                applicationHash = "UNKNOWN_HASH";
                return;
            }

            std::ifstream file(modulePath, std::ios::binary);
            if (!file) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                applicationHash = "UNKNOWN_HASH";
                return;
            }

            const size_t bufferSize = 8192;
            char buffer[bufferSize];

            while (file.read(buffer, bufferSize) || file.gcount() > 0) {
                if (!CryptHashData(hHash, (BYTE*)buffer, (DWORD)file.gcount(), 0)) {
                    CryptDestroyHash(hHash);
                    CryptReleaseContext(hProv, 0);
                    applicationHash = "UNKNOWN_HASH";
                    return;
                }
            }

            DWORD hashSize = 0;
            DWORD dwCount = sizeof(DWORD);
            if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashSize, &dwCount, 0)) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                applicationHash = "UNKNOWN_HASH";
                return;
            }

            std::vector<BYTE> hashBytes(hashSize);
            if (!CryptGetHashParam(hHash, HP_HASHVAL, hashBytes.data(), &hashSize, 0)) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                applicationHash = "UNKNOWN_HASH";
                return;
            }

            std::stringstream ss;
            for (DWORD i = 0; i < hashSize; i++) {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)hashBytes[i];
            }
            applicationHash = ss.str();

            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);

            AuthlyLogger::Log("[HASH] Calculated application hash: " + applicationHash.substr(0, 16) + "...");
        }
        catch (...) {
            applicationHash = "UNKNOWN_HASH";
            AuthlyLogger::Log("[HASH_ERROR] Failed to calculate hash");
        }
    }

    std::string GetSystemSid() {
        HANDLE hToken = NULL;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            return "UNKNOWN_SID";
        }

        DWORD dwSize = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
        if (dwSize == 0) {
            CloseHandle(hToken);
            return "UNKNOWN_SID";
        }

        PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);
        if (!pTokenUser) {
            CloseHandle(hToken);
            return "UNKNOWN_SID";
        }

        std::string sid = "UNKNOWN_SID";
        if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
            LPSTR sidStr = NULL;
            if (ConvertSidToStringSidA(pTokenUser->User.Sid, &sidStr)) {
                sid = sidStr;
                LocalFree(sidStr);
            }
        }

        free(pTokenUser);
        CloseHandle(hToken);
        return sid;
    }

    std::string GetPublicIp() {
        long long nowMs = GetTimestampMs();
        if (!cachedPublicIp.empty() && nowMs < cachedPublicIpExpiresAt) {
            return cachedPublicIp;
        }

        HINTERNET hSession = WinHttpOpen(L"AuthlyX/IPCheck", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) {
            return "UNKNOWN_IP";
        }

        HINTERNET hConnect = WinHttpConnect(hSession, L"api.ipify.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return "UNKNOWN_IP";
        }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "UNKNOWN_IP";
        }

        BOOL bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        if (!bResults) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "UNKNOWN_IP";
        }

        bResults = WinHttpReceiveResponse(hRequest, NULL);
        if (!bResults) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "UNKNOWN_IP";
        }

        std::string publicIp;
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;

        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize) || !dwSize) break;

            std::vector<char> buffer(dwSize + 1);
            if (WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
                publicIp.append(buffer.data(), dwDownloaded);
            }
        } while (dwSize > 0);

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        publicIp.erase(std::remove(publicIp.begin(), publicIp.end(), '\r'), publicIp.end());
        publicIp.erase(std::remove(publicIp.begin(), publicIp.end(), '\n'), publicIp.end());
        publicIp.erase(std::remove(publicIp.begin(), publicIp.end(), ' '), publicIp.end());

        if (publicIp.empty() || (publicIp.find('.') == std::string::npos && publicIp.find(':') == std::string::npos)) {
            return "UNKNOWN_IP";
        }

        cachedPublicIp = publicIp;
        cachedPublicIpExpiresAt = nowMs + 600000;
        return publicIp;
    }

    struct JsonValue {
        enum class Type { Null, Bool, Number, String, Object, Array };

        Type type = Type::Null;
        bool boolValue = false;
        std::string stringValue;
        std::map<std::string, JsonValue> objectValue;
        std::vector<JsonValue> arrayValue;
    };

    void SkipJsonWhitespace(const std::string& text, size_t& pos) {
        while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) {
            ++pos;
        }
    }

    bool ParseJsonString(const std::string& text, size_t& pos, std::string& out) {
        if (pos >= text.size() || text[pos] != '"') return false;
        ++pos;
        std::ostringstream stream;

        while (pos < text.size()) {
            char current = text[pos++];
            if (current == '"') {
                out = stream.str();
                return true;
            }
            if (current != '\\') {
                stream << current;
                continue;
            }
            if (pos >= text.size()) return false;
            char escaped = text[pos++];
            switch (escaped) {
            case '"': stream << '"'; break;
            case '\\': stream << '\\'; break;
            case '/': stream << '/'; break;
            case 'b': stream << '\b'; break;
            case 'f': stream << '\f'; break;
            case 'n': stream << '\n'; break;
            case 'r': stream << '\r'; break;
            case 't': stream << '\t'; break;
            case 'u':
                if (pos + 4 <= text.size()) {
                    stream << '?';
                    pos += 4;
                }
                else {
                    return false;
                }
                break;
            default:
                stream << escaped;
                break;
            }
        }

        return false;
    }

    bool ParseJsonValueInternal(const std::string& text, size_t& pos, JsonValue& out) {
        SkipJsonWhitespace(text, pos);
        if (pos >= text.size()) return false;

        if (text[pos] == '"') {
            out.type = JsonValue::Type::String;
            return ParseJsonString(text, pos, out.stringValue);
        }

        if (text[pos] == '{') {
            out.type = JsonValue::Type::Object;
            ++pos;
            SkipJsonWhitespace(text, pos);
            if (pos < text.size() && text[pos] == '}') {
                ++pos;
                return true;
            }

            while (pos < text.size()) {
                std::string key;
                if (!ParseJsonString(text, pos, key)) return false;
                SkipJsonWhitespace(text, pos);
                if (pos >= text.size() || text[pos] != ':') return false;
                ++pos;

                JsonValue child;
                if (!ParseJsonValueInternal(text, pos, child)) return false;
                out.objectValue[key] = child;

                SkipJsonWhitespace(text, pos);
                if (pos < text.size() && text[pos] == '}') {
                    ++pos;
                    return true;
                }
                if (pos >= text.size() || text[pos] != ',') return false;
                ++pos;
                SkipJsonWhitespace(text, pos);
            }
            return false;
        }

        if (text[pos] == '[') {
            out.type = JsonValue::Type::Array;
            ++pos;
            SkipJsonWhitespace(text, pos);
            if (pos < text.size() && text[pos] == ']') {
                ++pos;
                return true;
            }

            while (pos < text.size()) {
                JsonValue child;
                if (!ParseJsonValueInternal(text, pos, child)) return false;
                out.arrayValue.push_back(child);

                SkipJsonWhitespace(text, pos);
                if (pos < text.size() && text[pos] == ']') {
                    ++pos;
                    return true;
                }
                if (pos >= text.size() || text[pos] != ',') return false;
                ++pos;
                SkipJsonWhitespace(text, pos);
            }
            return false;
        }

        if (text.compare(pos, 4, "true") == 0) {
            out.type = JsonValue::Type::Bool;
            out.boolValue = true;
            pos += 4;
            return true;
        }

        if (text.compare(pos, 5, "false") == 0) {
            out.type = JsonValue::Type::Bool;
            out.boolValue = false;
            pos += 5;
            return true;
        }

        if (text.compare(pos, 4, "null") == 0) {
            out.type = JsonValue::Type::Null;
            pos += 4;
            return true;
        }

        size_t start = pos;
        while (pos < text.size() && std::string(",]} \t\r\n").find(text[pos]) == std::string::npos) {
            ++pos;
        }

        out.type = JsonValue::Type::Number;
        out.stringValue = text.substr(start, pos - start);
        return !out.stringValue.empty();
    }

    bool ParseJsonDocument(const std::string& text, JsonValue& out) {
        size_t pos = 0;
        if (!ParseJsonValueInternal(text, pos, out)) return false;
        SkipJsonWhitespace(text, pos);
        return pos == text.size();
    }

    const JsonValue* FindJsonValueRecursive(const JsonValue& node, const std::string& key) const {
        if (node.type == JsonValue::Type::Object) {
            auto it = node.objectValue.find(key);
            if (it != node.objectValue.end()) {
                return &it->second;
            }

            for (const auto& entry : node.objectValue) {
                const JsonValue* nested = FindJsonValueRecursive(entry.second, key);
                if (nested) return nested;
            }
        }

        if (node.type == JsonValue::Type::Array) {
            for (const auto& child : node.arrayValue) {
                const JsonValue* nested = FindJsonValueRecursive(child, key);
                if (nested) return nested;
            }
        }

        return nullptr;
    }

    std::string JsonValueToString(const JsonValue& value) const {
        switch (value.type) {
        case JsonValue::Type::String:
        case JsonValue::Type::Number:
            return value.stringValue;
        case JsonValue::Type::Bool:
            return value.boolValue ? "true" : "false";
        case JsonValue::Type::Null:
            return "null";
        default:
            return "";
        }
    }

    std::string GetNestedJsonValue(const JsonValue& node, const std::string& key) const {
        const JsonValue* value = FindJsonValueRecursive(node, key);
        return value ? JsonValueToString(*value) : "";
    }

    std::string CanonicalizeJsonValue(const JsonValue& value) const {
        switch (value.type) {
        case JsonValue::Type::Null:
            return "null";
        case JsonValue::Type::Bool:
            return value.boolValue ? "true" : "false";
        case JsonValue::Type::Number:
            return value.stringValue;
        case JsonValue::Type::String:
            return std::string("\"") + EscapeJsonString(value.stringValue) + "\"";
        case JsonValue::Type::Array: {
            std::ostringstream stream;
            stream << "[";
            for (size_t i = 0; i < value.arrayValue.size(); ++i) {
                if (i > 0) stream << ",";
                stream << CanonicalizeJsonValue(value.arrayValue[i]);
            }
            stream << "]";
            return stream.str();
        }
        case JsonValue::Type::Object: {
            std::ostringstream stream;
            stream << "{";
            bool first = true;
            for (const auto& entry : value.objectValue) {
                if (!first) stream << ",";
                first = false;
                stream << "\"" << EscapeJsonString(entry.first) << "\":" << CanonicalizeJsonValue(entry.second);
            }
            stream << "}";
            return stream.str();
        }
        }
        return "null";
    }

    std::string ExtractJsonValue(const std::string& json, const std::string& key) {
        JsonValue root;
        if (!ParseJsonDocument(json, root)) return "";

        const JsonValue* value = FindJsonValueRecursive(root, key);
        return value ? JsonValueToString(*value) : "";
    }

    void ParseResponse(const std::string& jsonResponse) {
        response.raw = jsonResponse;

        if (jsonResponse.empty()) {
            response.success = false;
            if (response.message.empty()) {
                response.message = "Empty response from server";
            }
            return;
        }

        if (jsonResponse.find("<!DOCTYPE html>") != std::string::npos ||
            jsonResponse.find("<html>") != std::string::npos) {
            response.success = false;
            response.message = "Server error - please try again later";
            return;
        }

        JsonValue root;
        if (ParseJsonDocument(jsonResponse, root)) {
            response.success = ExtractJsonValue(jsonResponse, "success") == "true";
            response.message = ExtractJsonValue(jsonResponse, "message");
            response.code = ExtractJsonValue(jsonResponse, "code");
        }

        if (response.message.empty()) {
            response.message = response.success ? "Success" : "Unknown error";
        }

        LoadUserData(jsonResponse);
        LoadVariableData(jsonResponse);
        LoadUpdateData(jsonResponse);
        LoadChatData(jsonResponse);
    }

    void LoadUserData(const std::string& jsonResponse) {
        JsonValue root;
        const bool parsed = ParseJsonDocument(jsonResponse, root);

        auto setIfPresent = [](std::string& target, const std::string& value) {
            if (!value.empty()) {
                target = value;
            }
            };

        auto getObjectValue = [&](const std::string& objectName, const std::string& key) -> std::string {
            if (!parsed || root.type != JsonValue::Type::Object) {
                return "";
            }

            auto objectIt = root.objectValue.find(objectName);
            if (objectIt == root.objectValue.end() || objectIt->second.type != JsonValue::Type::Object) {
                return "";
            }

            auto valueIt = objectIt->second.objectValue.find(key);
            if (valueIt == objectIt->second.objectValue.end()) {
                return "";
            }

            return JsonValueToString(valueIt->second);
            };

        setIfPresent(userData.username, ExtractJsonValue(jsonResponse, "username"));
        setIfPresent(userData.email, ExtractJsonValue(jsonResponse, "email"));
        setIfPresent(userData.licenseKey, ExtractJsonValue(jsonResponse, "license_key"));
        setIfPresent(userData.subscription, ExtractJsonValue(jsonResponse, "subscription"));
        setIfPresent(userData.subscriptionLevel, ExtractJsonValue(jsonResponse, "subscription_level"));
        setIfPresent(userData.lastLogin, ExtractJsonValue(jsonResponse, "last_login"));
        setIfPresent(userData.registeredAt, ExtractJsonValue(jsonResponse, "registered_at"));
        if (userData.registeredAt.empty()) {
            setIfPresent(userData.registeredAt, ExtractJsonValue(jsonResponse, "created_at"));
        }

        setIfPresent(userData.username, getObjectValue("user", "username"));
        setIfPresent(userData.email, getObjectValue("user", "email"));
        setIfPresent(userData.subscription, getObjectValue("user", "subscription"));
        setIfPresent(userData.subscriptionLevel, getObjectValue("user", "subscription_level"));
        setIfPresent(userData.licenseKey, getObjectValue("user", "linked_license_key"));
        setIfPresent(userData.lastLogin, getObjectValue("user", "last_login"));
        setIfPresent(userData.registeredAt, getObjectValue("user", "registered_at"));

        setIfPresent(userData.licenseKey, getObjectValue("license", "license_key"));
        setIfPresent(userData.email, getObjectValue("license", "email"));
        setIfPresent(userData.subscription, getObjectValue("license", "subscription"));
        setIfPresent(userData.subscriptionLevel, getObjectValue("license", "subscription_level"));
        setIfPresent(userData.lastLogin, getObjectValue("license", "last_login"));
        setIfPresent(userData.registeredAt, getObjectValue("license", "registered_at"));

        setIfPresent(userData.email, getObjectValue("device", "email"));
        setIfPresent(userData.subscription, getObjectValue("device", "subscription"));
        if (userData.subscription.empty()) {
            setIfPresent(userData.subscription, getObjectValue("device", "subscription_name"));
        }
        setIfPresent(userData.subscriptionLevel, getObjectValue("device", "subscription_level"));
        setIfPresent(userData.lastLogin, getObjectValue("device", "last_login"));
        setIfPresent(userData.registeredAt, getObjectValue("device", "registered_at"));
        if (userData.registeredAt.empty()) {
            setIfPresent(userData.registeredAt, getObjectValue("device", "date_created"));
        }

        std::string rawDate = ExtractJsonValue(jsonResponse, "expiry_date");
        if (rawDate.empty()) {
            rawDate = getObjectValue("user", "expiry_date");
        }
        if (rawDate.empty()) {
            rawDate = getObjectValue("license", "expiry_date");
        }
        if (rawDate.empty()) {
            rawDate = getObjectValue("device", "expiry_date");
        }

        if (!rawDate.empty()) {
            std::tm tm = {};
            std::istringstream ss(rawDate.substr(0, 19));
            ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");

            if (!ss.fail()) {
                char buffer[64];
                std::strftime(buffer, sizeof(buffer), "%d/%m/%Y", &tm);
                userData.expiryDate = std::string(buffer);
            }
            else {
                userData.expiryDate = rawDate;
            }
        }
        else {
            userData.expiryDate.clear();
        }

        userData.daysLeft = ComputeDaysLeft(rawDate);
        userData.hwid = ExtractJsonValue(jsonResponse, "sid");
        if (userData.hwid.empty()) {
            userData.hwid = ExtractJsonValue(jsonResponse, "hwid");
        }
        if (userData.hwid.empty()) {
            userData.hwid = getObjectValue("user", "sid");
        }
        if (userData.hwid.empty()) {
            userData.hwid = getObjectValue("user", "hwid");
        }
        if (userData.hwid.empty()) {
            userData.hwid = getObjectValue("license", "sid");
        }
        if (userData.hwid.empty()) {
            userData.hwid = getObjectValue("license", "hwid");
        }
        if (userData.hwid.empty()) {
            userData.hwid = getObjectValue("device", "sid");
        }
        if (userData.hwid.empty()) {
            userData.hwid = getObjectValue("device", "hwid");
        }
        if (userData.hwid.empty()) {
            userData.hwid = GetSystemSid();
        }

        userData.ipAddress = ExtractJsonValue(jsonResponse, "ip_address");
        if (userData.ipAddress.empty()) {
            userData.ipAddress = ExtractJsonValue(jsonResponse, "ip");
        }
        if (userData.ipAddress.empty()) {
            userData.ipAddress = getObjectValue("user", "ip_address");
        }
        if (userData.ipAddress.empty()) {
            userData.ipAddress = getObjectValue("license", "ip_address");
        }
        if (userData.ipAddress.empty()) {
            userData.ipAddress = getObjectValue("device", "ip_address");
        }
        if (userData.ipAddress.empty()) {
            userData.ipAddress = GetPublicIp();
        }

        if (userData.subscriptionLevel.empty()) {
            userData.subscriptionLevel = userData.subscription;
        }
    }

    void LoadVariableData(const std::string& jsonResponse) {
        variableData.varKey = ExtractJsonValue(jsonResponse, "var_key");
        variableData.varValue = ExtractJsonValue(jsonResponse, "var_value");
        variableData.updatedAt = ExtractJsonValue(jsonResponse, "updated_at");
    }

    void LoadUpdateData(const std::string& jsonResponse) {
        try {
            JsonValue root;
            if (!ParseJsonDocument(jsonResponse, root)) {
                updateData.available = false;
                updateData.latestVersion = "";
                updateData.downloadUrl = "";
                updateData.autoUpdateEnabled = false;
                updateData.forceUpdate = false;
                updateData.changelog = "";
                updateData.showReminder = false;
                updateData.reminderMessage = "";
                updateData.allowedUntil = "";
                return;
            }

            const JsonValue* updateNode = FindJsonValueRecursive(root, "update");
            if (!updateNode || updateNode->type != JsonValue::Type::Object) {
                updateData.available = GetNestedJsonValue(root, "auto_update_enabled") == "true" || !GetNestedJsonValue(root, "auto_update_download_url").empty();
                updateData.latestVersion = GetNestedJsonValue(root, "server_version");
                if (updateData.latestVersion.empty()) {
                    updateData.latestVersion = GetNestedJsonValue(root, "version");
                }
                updateData.downloadUrl = GetNestedJsonValue(root, "auto_update_download_url");
                updateData.autoUpdateEnabled = GetNestedJsonValue(root, "auto_update_enabled") == "true";
                updateData.forceUpdate = GetNestedJsonValue(root, "force_update") == "true";
                updateData.changelog.clear();
                updateData.showReminder = false;
                updateData.reminderMessage.clear();
                updateData.allowedUntil.clear();
                return;
            }

            updateData.available = GetNestedJsonValue(*updateNode, "available") == "true";
            updateData.latestVersion = GetNestedJsonValue(*updateNode, "latest_version");
            updateData.downloadUrl = GetNestedJsonValue(*updateNode, "download_url");
            updateData.autoUpdateEnabled = GetNestedJsonValue(*updateNode, "auto_update_enabled") == "true";
            updateData.forceUpdate = GetNestedJsonValue(*updateNode, "force_update") == "true";
            updateData.changelog = GetNestedJsonValue(*updateNode, "changelog");
            updateData.showReminder = GetNestedJsonValue(*updateNode, "show_reminder") == "true";
            updateData.reminderMessage = GetNestedJsonValue(*updateNode, "reminder_message");
            updateData.allowedUntil = GetNestedJsonValue(*updateNode, "allowed_until");

            if (updateData.available) {
                AuthlyLogger::Log("[UPDATE] Update available: " + updateData.latestVersion + ", Force: " + (updateData.forceUpdate ? "true" : "false"));
            }
        }
        catch (...) {
            AuthlyLogger::Log("[UPDATE_ERROR] Failed to load update data");
        }
    }

    void LoadChatData(const std::string& jsonResponse) {
        try {
            JsonValue root;
            if (!ParseJsonDocument(jsonResponse, root)) {
                chatMessages.channelName = "";
                chatMessages.messages.clear();
                chatMessages.count = 0;
                chatMessages.nextCursor.clear();
                chatMessages.hasMore = false;
                return;
            }

            const JsonValue* dataNode = FindJsonValueRecursive(root, "data");
            if (!dataNode || dataNode->type != JsonValue::Type::Object) {
                chatMessages.messages.clear();
                chatMessages.count = 0;
                chatMessages.nextCursor.clear();
                chatMessages.hasMore = false;
                return;
            }

            chatMessages.channelName = GetNestedJsonValue(*dataNode, "channel_name");
            chatMessages.nextCursor = GetNestedJsonValue(*dataNode, "next_cursor");
            chatMessages.hasMore = GetNestedJsonValue(*dataNode, "has_more") == "true";
            chatMessages.messages.clear();
            const JsonValue* messagesNode = FindJsonValueRecursive(*dataNode, "messages");
            if (messagesNode && messagesNode->type == JsonValue::Type::Array) {
                for (const auto& item : messagesNode->arrayValue) {
                    if (item.type != JsonValue::Type::Object) continue;
                    ChatMessage msg;
                    std::string id = GetNestedJsonValue(item, "id");
                    msg.id = id.empty() ? 0 : std::atoi(id.c_str());
                    msg.username = GetNestedJsonValue(item, "username");
                    msg.message = GetNestedJsonValue(item, "message");
                    msg.createdAt = GetNestedJsonValue(item, "created_at");
                    chatMessages.messages.push_back(msg);
                }
            }

            chatMessages.count = static_cast<int>(chatMessages.messages.size());
        }
        catch (...) {
            AuthlyLogger::Log("[CHAT_DATA_ERROR] Failed to load chat data");
            chatMessages.messages.clear();
            chatMessages.count = 0;
        }
    }

    static std::vector<int> ParseSemverParts(const std::string& versionString) {
        std::vector<int> parts;
        std::string token;
        token.reserve(16);

        auto flush = [&]() {
            if (token.empty()) return;
            try {
                parts.push_back(std::stoi(token));
            }
            catch (...) {
                parts.push_back(0);
            }
            token.clear();
        };

        for (char c : versionString) {
            if (c >= '0' && c <= '9') {
                token.push_back(c);
                continue;
            }
            if (c == '.') {
                flush();
                continue;
            }
            // stop parsing on first non-numeric separator (e.g. "-beta")
            break;
        }
        flush();

        while (parts.size() < 3) parts.push_back(0);
        return parts;
    }

    static int CompareSemver(const std::string& a, const std::string& b) {
        const std::vector<int> ap = ParseSemverParts(a);
        const std::vector<int> bp = ParseSemverParts(b);
        const size_t n = std::max(ap.size(), bp.size());
        for (size_t i = 0; i < n; i++) {
            const int av = i < ap.size() ? ap[i] : 0;
            const int bv = i < bp.size() ? bp[i] : 0;
            if (av < bv) return -1;
            if (av > bv) return 1;
        }
        return 0;
    }

    bool HasWhitelistedUpdateMessage() const {
        return updateData.showReminder || !updateData.allowedUntil.empty();
    }

    bool IsAutoUpdateEnabled() const {
        return updateData.autoUpdateEnabled;
    }

    static std::string FormatDisplayDate(const std::string& rawDate) {
        if (rawDate.empty()) return rawDate;
        std::string ts = rawDate;
        if (!ts.empty() && ts.back() == 'Z') {
            ts.pop_back();
        }
        if (ts.size() >= 19) {
            ts = ts.substr(0, 19);
        }

        std::tm tm = {};
        std::istringstream ss(ts);
        ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
        if (ss.fail()) return rawDate;

        char buffer[64];
        if (std::strftime(buffer, sizeof(buffer), "%B %d, %Y", &tm) == 0) {
            return rawDate;
        }

        std::string formatted = buffer;
        size_t zeroPos = formatted.find(" 0");
        if (zeroPos != std::string::npos) {
            formatted.erase(zeroPos + 1, 1);
        }
        return formatted;
    }

    std::string BuildWhitelistedUpdateMessage() const {
        std::string base;
        if (!updateData.allowedUntil.empty()) {
            base = "A new version is ready, and you can keep using this build until " + FormatDisplayDate(updateData.allowedUntil) + ".";
        }
        else {
            base = "A new version is ready, and you can still use this build for now.";
        }

        if (!IsAutoUpdateEnabled()) {
            return base;
        }

        return base + "\n\nWould you like to download the latest version now?";
    }

    static void EnsureConsole() {
        if (GetConsoleWindow() == NULL) {
            AllocConsole();
        }

        FILE* outputFile = nullptr;
        FILE* inputFile = nullptr;
        freopen_s(&outputFile, "CONOUT$", "w", stdout);
        freopen_s(&inputFile, "CONIN$", "r", stdin);
    }

    static void OpenUrl(const std::string& url) {
        if (url.empty()) return;
        std::wstring wideUrl(url.begin(), url.end());
        ShellExecuteW(NULL, L"open", wideUrl.c_str(), NULL, NULL, SW_SHOWNORMAL);
    }

    void OpenDownloadUrl() {
        if (!updateData.downloadUrl.empty()) {
            OpenUrl(updateData.downloadUrl);
        }
    }

    void ShowRequiredUpdateConsole(const std::string& message) {
        EnsureConsole();
        std::cout << message << std::endl;
        if (!updateData.latestVersion.empty()) {
            std::cout << "Latest version: " << updateData.latestVersion << std::endl;
        }

        if (!IsAutoUpdateEnabled() || updateData.downloadUrl.empty()) {
            return;
        }

        std::cout << "1. Download Latest" << std::endl;
        std::cout << "2. Exit" << std::endl;
        std::cout << "Select an option (1 or 2): ";

        std::string choice;
        std::getline(std::cin, choice);
        if (choice == "1") {
            OpenDownloadUrl();
        }
    }

    void ShowWhitelistedUpdatePrompt() {
        const std::string msg = BuildWhitelistedUpdateMessage();

        if (IsAutoUpdateEnabled() && !updateData.downloadUrl.empty()) {
            int r = MessageBoxA(NULL, msg.c_str(), "AuthlyX Update", MB_YESNO | MB_ICONINFORMATION | MB_TOPMOST);
            if (r == IDYES) {
                OpenDownloadUrl();
            }
            return;
        }

        MessageBoxA(NULL, msg.c_str(), "AuthlyX Update", MB_OK | MB_ICONINFORMATION | MB_TOPMOST);
    }

    void Error(const std::string& message) {
        AuthlyLogger::Log("[ERROR] " + message);

        std::string cmd = "cmd.exe /c start cmd /C \"color 4 && title AuthlyX Error && echo " +
            message + " && timeout /t 5\"";

        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

        if (pi.hProcess) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }

    int ComputeDaysLeft(const std::string& expiryDate) {
        if (expiryDate.empty()) return 0;
        std::string ts = expiryDate;
        if (ts.size() >= 19) {
            ts = ts.substr(0, 19);
        }
        std::tm tm = {};
        std::istringstream ss(ts);
        ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
        if (ss.fail()) return 0;
        time_t expiry = _mkgmtime(&tm);
        if (expiry <= 0) return 0;
        time_t now = time(nullptr);
        double diff = difftime(expiry, now);
        int days = static_cast<int>(std::ceil(diff / 86400.0));
        return days < 0 ? 0 : days;
    }

    std::string GetSessionId() const { return sessionId; }
    std::string GetCurrentApplicationHash() const { return applicationHash; }
    bool IsInitialized() const { return initialized; }
    std::string GetAppName() const { return appName; }

    bool IsUpdateAvailable() const { return updateData.available; }
    UpdateData GetUpdateInfo() const { return updateData; }

    std::string GetChats(const std::string& channelName) {
        return GetChats(channelName, 100, "");
    }

    std::string GetChats(const std::string& channelName, int limit, const std::string& cursor) {
        CheckInit();
        if (!initialized) return "";
        if (channelName.empty()) return "Channel cannot be empty";

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"channel_name", channelName},
            {"limit", std::to_string(limit > 0 ? limit : 100)}
        };

        if (!cursor.empty()) {
            payload["cursor"] = cursor;
        }

        std::string responseStr = PostJson("chats/get", BuildJson(payload));
        ParseResponse(responseStr);
        return responseStr;
    }

    void SendChat(const std::string& message) {
        SendChat(message, "global");
    }

    void SendChat(const std::string& message, const std::string& channelName) {
        if (message.empty() || channelName.empty()) return;

        std::map<std::string, std::string> payload = {
            {"session_id", sessionId},
            {"channel_name", channelName},
            {"message", message}
        };
        std::string responseStr = PostJson("chats/send", BuildJson(payload));
        ParseResponse(responseStr);
    }

private:
    std::string BuildJson(const std::map<std::string, std::string>& data) const {
        std::string json = "{";
        for (auto it = data.begin(); it != data.end(); ++it) {
            if (it != data.begin()) json += ",";
            json += "\"" + it->first + "\":\"" + EscapeJsonString(it->second) + "\"";
        }
        json += "}";
        return json;
    }

    std::string EscapeJsonString(const std::string& input) const {
        std::string output;
        for (char c : input) {
            switch (c) {
            case '"': output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b"; break;
            case '\f': output += "\\f"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default: output += c; break;
            }
        }
        return output;
    }

    bool loggingEnabled = false;
};

#endif // __cplusplus

#ifndef AUTHLYX_C_API_DECL
#define AUTHLYX_C_API_DECL

#ifdef __cplusplus
#define AUTHLYX_EXTERN_C extern "C"
#else
#define AUTHLYX_EXTERN_C
#endif

#if defined(_WIN32) && defined(AUTHLYX_BUILD_DLL)
#define AUTHLYX_C_API __declspec(dllexport)
#elif defined(_WIN32) && defined(AUTHLYX_USE_DLL)
#define AUTHLYX_C_API __declspec(dllimport)
#else
#define AUTHLYX_C_API
#endif

#if defined(__cplusplus) && !defined(AUTHLYX_SOURCE_BUILD) && !defined(AUTHLYX_USE_DLL)
static inline void* AuthlyX_Create(const char* ownerId, const char* appName, const char* version, const char* secret) {
    return new AuthlyX(
        ownerId ? ownerId : "",
        appName ? appName : "",
        version ? version : "",
        secret ? secret : "");
}

static inline int AuthlyX_Init(void* instance) {
    return instance ? (reinterpret_cast<AuthlyX*>(instance)->Init() ? 1 : 0) : 0;
}

static inline int AuthlyX_Login(void* instance, const char* identifier, const char* password) {
    if (!instance || !identifier || !password) return 0;
    return reinterpret_cast<AuthlyX*>(instance)->Login(identifier, password) ? 1 : 0;
}

static inline int AuthlyX_LicenseLogin(void* instance, const char* licenseKey) {
    if (!instance || !licenseKey) return 0;
    return reinterpret_cast<AuthlyX*>(instance)->LicenseLogin(licenseKey) ? 1 : 0;
}

static inline int AuthlyX_DeviceLogin(void* instance, const char* deviceType, const char* deviceId) {
    if (!instance || !deviceType || !deviceId) return 0;
    return reinterpret_cast<AuthlyX*>(instance)->DeviceLogin(deviceType, deviceId) ? 1 : 0;
}

static inline int AuthlyX_Authenticate(void* instance, const char* identifier, const char* password, const char* deviceType) {
    if (!instance || !identifier) return 0;
    return reinterpret_cast<AuthlyX*>(instance)->Authenticate(
        identifier,
        password ? password : "",
        deviceType ? deviceType : "") ? 1 : 0;
}

static inline int AuthlyX_ChangePassword(void* instance, const char* oldPassword, const char* newPassword) {
    if (!instance || !oldPassword || !newPassword) return 0;
    return reinterpret_cast<AuthlyX*>(instance)->ChangePassword(oldPassword, newPassword) ? 1 : 0;
}

static inline const char* AuthlyX_GetMessage(void* instance) {
    return instance ? reinterpret_cast<AuthlyX*>(instance)->response.message.c_str() : "";
}

static inline const char* AuthlyX_GetUsername(void* instance) {
    return instance ? reinterpret_cast<AuthlyX*>(instance)->userData.username.c_str() : "";
}

static inline const char* AuthlyX_GetLicenseKey(void* instance) {
    return instance ? reinterpret_cast<AuthlyX*>(instance)->userData.licenseKey.c_str() : "";
}

static inline void AuthlyX_Destroy(void* instance) {
    delete reinterpret_cast<AuthlyX*>(instance);
}
#else
typedef void* AuthlyXHandle;

AUTHLYX_EXTERN_C AUTHLYX_C_API void* AuthlyX_Create(const char* ownerId, const char* appName, const char* version, const char* secret);
AUTHLYX_EXTERN_C AUTHLYX_C_API int AuthlyX_Init(void* instance);
AUTHLYX_EXTERN_C AUTHLYX_C_API int AuthlyX_Login(void* instance, const char* identifier, const char* password);
AUTHLYX_EXTERN_C AUTHLYX_C_API int AuthlyX_LicenseLogin(void* instance, const char* licenseKey);
AUTHLYX_EXTERN_C AUTHLYX_C_API int AuthlyX_DeviceLogin(void* instance, const char* deviceType, const char* deviceId);
AUTHLYX_EXTERN_C AUTHLYX_C_API int AuthlyX_Authenticate(void* instance, const char* identifier, const char* password, const char* deviceType);
AUTHLYX_EXTERN_C AUTHLYX_C_API int AuthlyX_ChangePassword(void* instance, const char* oldPassword, const char* newPassword);
AUTHLYX_EXTERN_C AUTHLYX_C_API const char* AuthlyX_GetMessage(void* instance);
AUTHLYX_EXTERN_C AUTHLYX_C_API const char* AuthlyX_GetUsername(void* instance);
AUTHLYX_EXTERN_C AUTHLYX_C_API const char* AuthlyX_GetLicenseKey(void* instance);
AUTHLYX_EXTERN_C AUTHLYX_C_API void AuthlyX_Destroy(void* instance);
#endif

#endif
