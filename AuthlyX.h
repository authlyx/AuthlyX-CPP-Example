// AuthlyX C++ SDK Version 3.0 BETA
#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <array>
#include <vector>


namespace authlyx
{
    using json = nlohmann::ordered_json;
    class error : public std::runtime_error
    {
      public:
        std::string code, kind, request_id;
        int status;
        json data;
        error(std::string code, std::string message, std::string kind, int status = 0,
              std::string request_id = "");
    };
    struct result
    {
        bool success;
        bool ok() const
        {
            return success;
        }
        bool failed() const
        {
            return !success;
        }
        std::string code, message, request_id;
        json data;
        template <class T> T decode() const
        {
            return data.template get<T>();
        }
    };
    class protected_store
    {
      public:
        virtual ~protected_store() = default;
        virtual std::optional<std::string> load(const std::string &) = 0;
        virtual void save(const std::string &, const std::string &) = 0;
        virtual void remove(const std::string &) = 0;
    };
    class memory_store final : public protected_store
    {
        std::mutex mutex_;
        std::map<std::string, std::string> values_;

      public:
        std::optional<std::string> load(const std::string &) override;
        void save(const std::string &, const std::string &) override;
        void remove(const std::string &) override;
    };
    class windows_protected_store final : public protected_store
    {
        std::filesystem::path directory_;
        std::filesystem::path file(const std::string &) const;

      public:
        explicit windows_protected_store(std::filesystem::path);
        std::optional<std::string> load(const std::string &) override;
        void save(const std::string &, const std::string &) override;
        void remove(const std::string &) override;
    };
    struct options
    {
        std::string app_key, version, systemId, endpoint, build_hash;
        std::map<std::string, std::string> response_keys, offline_keys, script_keys;
        std::shared_ptr<protected_store> storage;
        std::chrono::milliseconds request_budget{8000};
        bool manual_heartbeat = false, allow_local_http = false, update_prompt = true;
        std::string heartbeat;
        std::function<void(const std::string &)> on_connection;
        std::function<void(const error &)> on_invalidated;
    };
    options defaultOptions(std::string app_key, std::string version);
    class AuthlyX final
    {
        struct impl;
        std::shared_ptr<impl> impl_;
        std::future<result> execute(std::function<result(impl &, std::stop_token)>,
                                    std::stop_token);

      public:
        explicit AuthlyX(options);
        AuthlyX(std::string app_key, std::string version);
        static std::string systemId();
        ~AuthlyX();
        AuthlyX(const AuthlyX &) = delete;
        AuthlyX &operator=(const AuthlyX &) = delete;
        json userData() const;
        std::future<result> registerUser(std::string, std::string, std::string,
                                         std::stop_token = {});
        std::future<result> changePassword(std::string, std::string, std::stop_token = {});
        std::future<result> redeemLicense(std::string, std::stop_token = {});
        std::future<result> log(std::string, std::stop_token = {});
        std::future<result> initialize(std::stop_token cancel = {})
        {
            return init(cancel);
        }
        std::future<void> initialize(std::function<void(result)> callback,
                                     std::stop_token cancel = {})
        {
            return init(std::move(callback), cancel);
        }
        std::future<result> init(std::stop_token = {});
        std::future<void> init(std::function<void(result)>, std::stop_token = {});
        std::future<void> login(std::string, std::function<void(result)>, std::stop_token = {});
        std::future<void> login(std::string, std::string, std::function<void(result)>,
                                std::stop_token = {});
        std::future<void> getVariable(std::string, std::function<void(result)>,
                                      std::stop_token = {});
        std::future<void> getScript(std::string, std::function<void(result)>, std::stop_token = {});
        std::future<result> login(std::string username, std::string password, std::stop_token = {});
        std::future<result> login(std::string license, std::stop_token = {});
        std::future<result> licenseLogin(std::string, std::stop_token = {});
        std::future<result> deviceLogin(std::stop_token = {});
        std::future<result> checkSession(std::stop_token = {});
        std::future<result> onResume(std::stop_token = {});
        std::future<result> getMetadata(std::stop_token = {});
        std::future<result> updateVariable(std::string name, std::string value,
                                           std::stop_token = {});
        std::future<result> getFeatures(std::stop_token = {});
        std::future<result> getFeature(std::string name, std::stop_token = {});
        std::future<result> getAllMetadata(std::stop_token = {});
        std::future<result> getMetadata(std::string key, std::stop_token = {});
        std::future<result> checkMetadata(std::string key, std::stop_token = {});
        std::future<result> sendWebhook(std::string event_name, json data, std::stop_token = {});
        std::future<result> setMetadata(std::string, json, std::stop_token = {});
        std::future<result> checkFeature(std::string, std::stop_token = {});
        std::future<result> getVariable(std::string, std::stop_token = {});
        std::future<result> getScript(std::string, std::optional<int> = {}, std::stop_token = {});
        std::future<result> saveOfflineAccess(std::stop_token = {});
        bool hasAccess();
        bool hasOfflineAccess();
        std::future<result> logout(std::stop_token = {});
        void close();
    };
}
#if !defined(AUTHLYX_SEPARATE_IMPLEMENTATION) || defined(AUTHLYX_IMPLEMENTATION)
#ifdef AUTHLYX_IMPLEMENTATION
#define AUTHLYX_INLINE
#else
#define AUTHLYX_INLINE inline
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <thread>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <sddl.h>
#include <wincrypt.h>
#include <windows.h>
#include <shellapi.h>
#ifdef _MSC_VER
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#endif
#endif
namespace authlyx
{
    using namespace std::chrono;
    AUTHLYX_INLINE error::error(std::string c, std::string m, std::string k, int s, std::string id)
        : std::runtime_error(std::move(m)), code(std::move(c)), kind(std::move(k)),
          request_id(std::move(id)), status(s)
    {
    }
    namespace detail
    {
        AUTHLYX_INLINE long long wall()
        {
            return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
        }
        AUTHLYX_INLINE std::string hex(const unsigned char *bytes, std::size_t size)
        {
            std::ostringstream out;
            out << std::hex << std::setfill('0');
            for (std::size_t i = 0; i < size; ++i)
                out << std::setw(2) << static_cast<unsigned>(bytes[i]);
            return out.str();
        }
        AUTHLYX_INLINE std::string hash(const std::string &value)
        {
            unsigned char output[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char *>(value.data()), value.size(), output);
            return hex(output, sizeof output);
        }
        AUTHLYX_INLINE std::string random(std::size_t n)
        {
            std::string bytes(n, '\0');
            if (RAND_bytes(reinterpret_cast<unsigned char *>(bytes.data()), static_cast<int>(n)) !=
                1)
                throw error("RANDOM_UNAVAILABLE", "The OS random source is unavailable.",
                            "security");
            return bytes;
        }
        AUTHLYX_INLINE std::string b64(const std::string &v)
        {
            std::string out(4 * ((v.size() + 2) / 3), '\0');
            EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()),
                            reinterpret_cast<const unsigned char *>(v.data()),
                            static_cast<int>(v.size()));
            return out;
        }
        AUTHLYX_INLINE std::string unb64(const std::string &v)
        {
            if (v.empty() || v.size() % 4)
                throw error("DATA_INVALID", "Invalid base64 data.", "security");
            std::string out(v.size() / 4 * 3, '\0');
            int length = EVP_DecodeBlock(reinterpret_cast<unsigned char *>(out.data()),
                                         reinterpret_cast<const unsigned char *>(v.data()),
                                         static_cast<int>(v.size()));
            if (length < 0)
                throw error("DATA_INVALID", "Invalid base64 data.", "security");
            if (v.back() == '=')
                --length;
            if (v.size() > 1 && v[v.size() - 2] == '=')
                --length;
            out.resize(length);
            return out;
        }
        using pkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
        AUTHLYX_INLINE pkey public_key(const std::string &pem)
        {
            BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
            if (!bio)
                return {nullptr, EVP_PKEY_free};
            auto *key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
            if (key && EVP_PKEY_id(key) != EVP_PKEY_ED25519)
            {
                EVP_PKEY_free(key);
                key = nullptr;
            }
            return {key, EVP_PKEY_free};
        }
        AUTHLYX_INLINE std::string der(EVP_PKEY *key)
        {
            int size = i2d_PUBKEY(key, nullptr);
            if (size <= 0)
                throw error("KEY_INVALID", "Invalid verification key.", "security");
            std::string out(size, '\0');
            auto *ptr = reinterpret_cast<unsigned char *>(out.data());
            i2d_PUBKEY(key, &ptr);
            return out;
        }
        AUTHLYX_INLINE std::string key_id(const std::string &pem)
        {
            auto key = public_key(pem);
            return key ? hash(der(key.get())) : "";
        }
        AUTHLYX_INLINE bool verify(const std::string &pem, const std::string &payload,
                           const std::string &signature)
        {
            try
            {
                auto key = public_key(pem);
                if (!key)
                    return false;
                auto sig = unb64(signature);
                std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),
                                                                            EVP_MD_CTX_free);
                return ctx &&
                       EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) == 1 &&
                       EVP_DigestVerify(
                           ctx.get(), reinterpret_cast<const unsigned char *>(sig.data()),
                           sig.size(), reinterpret_cast<const unsigned char *>(payload.data()),
                           payload.size()) == 1;
            }
            catch (...)
            {
                return false;
            }
        }
        AUTHLYX_INLINE std::string str(const json &v, const char *k)
        {
            return v.contains(k) && v[k].is_string() ? v[k].get<std::string>() : "";
        }
        AUTHLYX_INLINE std::string find_key(const std::map<std::string, std::string> &keys,
                                    const std::string &id)
        {
            auto it = keys.find(id);
            return it == keys.end() ? "" : it->second;
        }
        AUTHLYX_INLINE bool equivalent(const json &a, const json &b)
        {
            return nlohmann::json::parse(a.dump()) == nlohmann::json::parse(b.dump());
        }
        AUTHLYX_INLINE long long timestamp(const std::string &v)
        {
            std::tm time{};
            std::istringstream in(v.substr(0, 19));
            in >> std::get_time(&time, "%Y-%m-%dT%H:%M:%S");
            if (in.fail() || v.size() < 20 || v.back() != 'Z')
                throw error("RESPONSE_INVALID", "Invalid server timestamp.", "security");
#ifdef _WIN32
            auto seconds = _mkgmtime(&time);
#else
            auto seconds = timegm(&time);
#endif
            long long fraction = 0;
            if (v[19] == '.')
            {
                auto end = v.find('Z', 20);
                std::string digits = v.substr(20, end - 20);
                while (digits.size() < 3)
                    digits += '0';
                fraction = std::stoll(digits.substr(0, 3));
            }
            return seconds * 1000LL + fraction;
        }
        AUTHLYX_INLINE std::string protect(const std::string &name, const std::string &value, bool encrypt)
        {
#ifdef _WIN32
            DATA_BLOB input{static_cast<DWORD>(value.size()),
                            reinterpret_cast<BYTE *>(const_cast<char *>(value.data()))},
                entropy{static_cast<DWORD>(name.size()),
                        reinterpret_cast<BYTE *>(const_cast<char *>(name.data()))},
                output{};
            BOOL ok = encrypt ? CryptProtectData(&input, nullptr, &entropy, nullptr, nullptr,
                                                 CRYPTPROTECT_UI_FORBIDDEN, &output)
                              : CryptUnprotectData(&input, nullptr, &entropy, nullptr, nullptr,
                                                   CRYPTPROTECT_UI_FORBIDDEN, &output);
            if (!ok)
                throw error("STORAGE_INVALID", "Protected state could not be read or saved.",
                            "storage");
            std::string bytes(reinterpret_cast<char *>(output.pbData), output.cbData);
            LocalFree(output.pbData);
            return bytes;
#else
            throw error("STORAGE_UNAVAILABLE", "Supply a platform-protected store.", "storage");
#endif
        }
        AUTHLYX_INLINE std::string device_text(const std::string &value)
        {
            std::string out;
            for (unsigned char c : value)
                if (c >= 0x20 && c <= 0x7E && c != 34 && c != 92 && c != 60 && c != 62 && c != 38)
                    out.push_back(static_cast<char>(c));
            auto first = out.find_first_not_of(' ');
            if (first == std::string::npos)
                return "";
            out = out.substr(first, out.find_last_not_of(' ') - first + 1);
            return out.substr(0, 100);
        }
        AUTHLYX_INLINE std::string chassis_type(int chassis)
        {
            switch (chassis)
            {
            case 8: case 9: case 10: case 14: case 31: case 32:
                return "Windows laptop";
            case 30:
                return "Windows tablet";
            case 17: case 23: case 28: case 29:
                return "Windows server";
            case 3: case 4: case 5: case 6: case 7: case 13: case 15: case 16: case 24: case 35: case 36:
                return "Windows desktop";
            default:
                return "Windows";
            }
        }
        AUTHLYX_INLINE json device_details()
        {
            std::string name, type = "Windows", baseboard, uuid;
#ifdef _WIN32
            wchar_t host[MAX_COMPUTERNAME_LENGTH + 1];
            DWORD host_size = MAX_COMPUTERNAME_LENGTH + 1;
            if (GetComputerNameW(host, &host_size))
                for (DWORD i = 0; i < host_size; ++i)
                    name.push_back(host[i] < 0x80 ? static_cast<char>(host[i]) : '?');
            UINT size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
            std::vector<unsigned char> raw(size);
            if (size > 8 && GetSystemFirmwareTable('RSMB', 0, raw.data(), size) == size)
            {
                std::size_t length = raw[4] | raw[5] << 8 | raw[6] << 16 | static_cast<std::size_t>(raw[7]) << 24;
                const unsigned char *p = raw.data() + 8, *end = p + (std::min)(length, raw.size() - 8);
                while (p + 4 <= end)
                {
                    unsigned char kind = p[0], header = p[1];
                    if (header < 4 || p + header > end)
                        break;
                    const unsigned char *strings = p + header;
                    auto text_at = [&](unsigned char index)
                    {
                        std::string value;
                        const unsigned char *q = strings;
                        for (unsigned char i = 1; index && i < index && q < end; ++i)
                        {
                            while (q < end && *q)
                                ++q;
                            ++q;
                        }
                        while (index && q < end && *q)
                            value.push_back(static_cast<char>(*q++));
                        return value;
                    };
                    if (kind == 1 && header >= 0x18)
                    {
                        const unsigned char *u = p + 8;
                        char buffer[37];
                        std::snprintf(buffer, sizeof buffer,
                                      "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                                      u[3], u[2], u[1], u[0], u[5], u[4], u[7], u[6], u[8], u[9], u[10],
                                      u[11], u[12], u[13], u[14], u[15]);
                        uuid = buffer;
                    }
                    else if (kind == 2 && header >= 8 && baseboard.empty())
                        baseboard = text_at(p[7]);
                    else if (kind == 3 && header >= 6 && type == "Windows")
                        type = chassis_type(p[5] & 0x7F);
                    const unsigned char *q = strings;
                    while (q + 1 < end && !(q[0] == 0 && q[1] == 0))
                        ++q;
                    p = q + 2;
                    if (kind == 127)
                        break;
                }
            }
#endif
            return json{{"name", device_text(name)},
                        {"type", type},
                        {"baseboard", device_text(baseboard)},
                        {"uuid", device_text(uuid)}};
        }
    }
    using namespace detail;
    AUTHLYX_INLINE std::optional<std::string> memory_store::load(const std::string &name)
    {
        std::lock_guard lock(mutex_);
        auto it = values_.find(name);
        if (it == values_.end())
            return {};
        return it->second;
    }
    AUTHLYX_INLINE void memory_store::save(const std::string &name, const std::string &v)
    {
        std::lock_guard lock(mutex_);
        values_[name] = v;
    }
    AUTHLYX_INLINE void memory_store::remove(const std::string &name)
    {
        std::lock_guard lock(mutex_);
        values_.erase(name);
    }
    AUTHLYX_INLINE windows_protected_store::windows_protected_store(std::filesystem::path path)
        : directory_(std::filesystem::absolute(path))
    {
#ifndef _WIN32
        throw error("STORAGE_UNAVAILABLE", "Supply a platform-protected store.", "storage");
#endif
        std::filesystem::create_directories(directory_);
    }
    AUTHLYX_INLINE std::filesystem::path windows_protected_store::file(const std::string &name) const
    {
        return directory_ / (hash(name) + ".dat");
    }
    AUTHLYX_INLINE std::optional<std::string> windows_protected_store::load(const std::string &name)
    {
        auto path = file(name);
        if (!std::filesystem::exists(path))
            return {};
        if (std::filesystem::file_size(path) > 1048576)
            throw error("STORAGE_INVALID", "Protected state is too large.", "storage");
        std::ifstream stream(path, std::ios::binary);
        std::string bytes((std::istreambuf_iterator<char>(stream)), {});
        return protect(name, bytes, false);
    }
    AUTHLYX_INLINE void windows_protected_store::save(const std::string &name, const std::string &value)
    {
        auto path = file(name), temp = path;
        auto bytes = random(8);
        temp += hex(reinterpret_cast<const unsigned char *>(bytes.data()), bytes.size()) + ".tmp";
        try
        {
            std::ofstream stream(temp, std::ios::binary | std::ios::trunc);
            std::string encrypted = protect(name, value, true);
            stream.write(encrypted.data(), encrypted.size());
            stream.flush();
            if (!stream)
                throw error("STORAGE_INVALID", "Could not save protected state.", "storage");
            stream.close();
#ifdef _WIN32
            if (!MoveFileExW(temp.c_str(), path.c_str(),
                             MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
                throw error("STORAGE_INVALID", "Could not replace protected state.", "storage");
#else
            std::filesystem::rename(temp, path);
#endif
        }
        catch (...)
        {
            std::filesystem::remove(temp);
            throw;
        }
    }
    AUTHLYX_INLINE void windows_protected_store::remove(const std::string &name)
    {
        std::filesystem::remove(file(name));
    }

    struct AuthlyX::impl : std::enable_shared_from_this<AuthlyX::impl>
    {
        options o;
        pkey key{nullptr, EVP_PKEY_free};
        json userData = json::object();
        std::string public_pem, key_hash, prefix, token, session_id, app_id, identity_id, slot;
        json offline, credential;
        bool offline_session = false;
        std::mutex gate, event_gate, schedule_gate;
        std::string prompt_title, prompt_text, prompt_url;
        bool update_offered = false;
        std::condition_variable condition;
        std::vector<std::function<void()>> events;
        std::thread worker;
        std::atomic<bool> disposed{false}, active{false}, logging_out{false};
        long long server = 0, anchor_wall = 0, deadline = 0;
        steady_clock::time_point anchor;
        std::atomic<double> heartbeat_seconds{600}, jitter_seconds{15};
        std::array<std::mutex, CURL_LOCK_DATA_LAST> share_locks;
        std::unique_ptr<CURLSH, decltype(&curl_share_cleanup)> share{nullptr, curl_share_cleanup};
        static void share_lock(CURL *, curl_lock_data data, curl_lock_access, void *self)
        {
            static_cast<impl *>(self)->share_locks[data].lock();
        }
        static void share_unlock(CURL *, curl_lock_data data, void *self)
        {
            static_cast<impl *>(self)->share_locks[data].unlock();
        }
        explicit impl(options options) : o(std::move(options))
        {
            if (!o.heartbeat.empty())
            {
                if (o.heartbeat != "server" && o.heartbeat != "manual")
                    throw std::invalid_argument("Use server or manual heartbeat mode.");
                o.manual_heartbeat = o.heartbeat == "manual";
            }
            static const int initialized = []() { return curl_global_init(CURL_GLOBAL_DEFAULT); }();
            if (initialized != CURLE_OK)
                throw error("CONFIG_INVALID", "Could not initialize HTTPS.", "network");
            share.reset(curl_share_init());
            if (share)
            {
                curl_share_setopt(share.get(), CURLSHOPT_LOCKFUNC, &impl::share_lock);
                curl_share_setopt(share.get(), CURLSHOPT_UNLOCKFUNC, &impl::share_unlock);
                curl_share_setopt(share.get(), CURLSHOPT_USERDATA, this);
                curl_share_setopt(share.get(), CURLSHOPT_SHARE, CURL_LOCK_DATA_CONNECT);
                curl_share_setopt(share.get(), CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
                curl_share_setopt(share.get(), CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
            }
            CURLU *url = curl_url();
            if (!url || curl_url_set(url, CURLUPART_URL, o.endpoint.c_str(), 0) != CURLUE_OK)
            {
                if (url)
                    curl_url_cleanup(url);
                throw error("CONFIG_INVALID", "Invalid API origin.", "storage");
            }
            auto part = [&](CURLUPart name)
            {
                char *raw = nullptr;
                auto result = curl_url_get(url, name, &raw, 0);
                std::string value = result == CURLUE_OK ? raw : "";
                curl_free(raw);
                return value;
            };
            auto scheme = part(CURLUPART_SCHEME), host = part(CURLUPART_HOST),
                 path = part(CURLUPART_PATH);
            bool local =
                host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1";
            bool valid = (scheme == "https" || (o.allow_local_http && scheme == "http" && local)) &&
                         (path.empty() || path == "/") && part(CURLUPART_USER).empty() &&
                         part(CURLUPART_PASSWORD).empty() && part(CURLUPART_QUERY).empty() &&
                         part(CURLUPART_FRAGMENT).empty();
            curl_url_cleanup(url);
            if (!valid || o.app_key.empty() || o.version.empty() || o.systemId.empty() ||
                o.response_keys.empty() || !o.storage || o.request_budget < milliseconds(100) ||
                o.request_budget > seconds(60))
                throw error("CONFIG_INVALID",
                            "Provide an HTTPS API origin, app identity, protected "
                            "storage, trusted keys and a bounded request budget.",
                            "storage");
            while (!o.endpoint.empty() && o.endpoint.back() == '/')
                o.endpoint.pop_back();
            prefix = "authlyx.v3." + hash(o.endpoint + "/\n" + o.app_key + "\n" + o.systemId);
            auto identity_name = "authlyx.v3.installation." + hash(o.endpoint + "/\n" + o.systemId);
            auto saved = o.storage->load(identity_name);
            std::string seed = saved ? unb64(*saved) : random(32);
            if (seed.size() != 32)
                throw error("STORAGE_INVALID", "Invalid protected installation key.", "storage");
            if (!saved)
                o.storage->save(identity_name, b64(seed));
            key.reset(EVP_PKEY_new_raw_private_key(
                EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char *>(seed.data()),
                seed.size()));
            OPENSSL_cleanse(seed.data(), seed.size());
            if (!key)
                throw error("KEY_INVALID", "Could not load installation key.", "security");
            key_hash = hash(der(key.get()));
            BIO *bio = BIO_new(BIO_s_mem());
            PEM_write_bio_PUBKEY(bio, key.get());
            char *raw = nullptr;
            auto count = BIO_get_mem_data(bio, &raw);
            public_pem.assign(raw, count);
            BIO_free(bio);
        }
        long long now() const
        {
            return server
                       ? server + duration_cast<milliseconds>(steady_clock::now() - anchor).count()
                       : wall();
        }
        void set_anchor(long long value)
        {
            server = value;
            anchor = steady_clock::now();
            anchor_wall = wall();
        }
        std::string sign(const std::string &value)
        {
            std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),
                                                                        EVP_MD_CTX_free);
            std::string signature(64, '\0');
            std::size_t size = signature.size();
            if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1 ||
                EVP_DigestSign(ctx.get(), reinterpret_cast<unsigned char *>(signature.data()),
                               &size, reinterpret_cast<const unsigned char *>(value.data()),
                               value.size()) != 1)
                throw error("SIGNING_FAILED", "Could not sign the SDK request.", "security");
            signature.resize(size);
            return b64(signature);
        }
        void queue(std::function<void()> fn)
        {
            std::lock_guard lock(event_gate);
            events.push_back(std::move(fn));
        }
        void offer_update(const json &data, const std::string &code, const std::string &message)
        {
            if (!o.update_prompt || !data.is_object() || !data.contains("update") ||
                !data["update"].is_object())
                return;
            const json &update = data["update"];
            auto text = [&](const char *key)
            {
                return update.contains(key) && update[key].is_string() ? update[key].get<std::string>()
                                                                       : std::string();
            };
            std::string url = text("url"), latest = text("version"), notes = text("notes");
            if (url.rfind("https://", 0) != 0 && url.rfind("http://", 0) != 0)
                url.clear();
            bool required = code == "UPDATE_REQUIRED" || code == "VERSION_MISMATCH";
            if (!required)
            {
                bool available = data.contains("updateAvailable") && data["updateAvailable"].is_boolean() &&
                                 data["updateAvailable"].get<bool>();
                if (update_offered || !available || url.empty())
                    return;
                update_offered = true;
            }
            std::string body = required ? message : "Version " + latest + " is available.";
            body += "\n\nYour version: " + o.version;
            if (!latest.empty())
                body += "\nLatest version: " + latest;
            if (!notes.empty())
                body += "\n\n" + notes;
            if (!url.empty())
                body += "\n\nOpen the download page?";
            prompt_title = code == "UPDATE_REQUIRED"    ? "Update required"
                           : code == "VERSION_MISMATCH" ? "Version not supported"
                                                        : "Update available";
            prompt_text = body;
            prompt_url = url;
        }
        void show_prompt()
        {
            std::string title, text, url;
            {
                std::lock_guard lock(gate);
                title.swap(prompt_title);
                text.swap(prompt_text);
                url.swap(prompt_url);
            }
            if (title.empty())
                return;
#ifdef _WIN32
            auto wide = [](const std::string &value)
            {
                int size = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
                std::wstring out(size > 0 ? size : 1, L'\0');
                if (size > 0)
                    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, out.data(), size);
                out.resize(wcslen(out.c_str()));
                return out;
            };
            UINT flags = (url.empty() ? MB_OK : MB_YESNO) | MB_ICONINFORMATION | MB_TOPMOST |
                         MB_SETFOREGROUND;
            if (MessageBoxW(nullptr, wide(text).c_str(), wide(title).c_str(), flags) == IDYES &&
                !url.empty())
                ShellExecuteW(nullptr, L"open", wide(url).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
#endif
        }
        bool offline_available()
        {
            if (offline_session)
                return valid_offline() && persist_offline();
            for (auto &item : slots())
                if (item.is_string() && valid_record(load_record(item.get<std::string>())))
                    return true;
            return false;
        }
        void flush()
        {
            std::vector<std::function<void()>> pending;
            {
                std::lock_guard lock(event_gate);
                pending.swap(events);
            }
            for (auto &fn : pending)
                try
                {
                    fn();
                }
                catch (...)
                {
                }
        }
        void connection(const std::string &value)
        {
            if (o.on_connection)
            {
                auto fn = o.on_connection;
                queue([fn, value] { fn(value); });
            }
        }
        static std::string slot_of(const std::string &type, const std::string &username,
                                   const std::string &license)
        {
            auto trim = [](const std::string &v)
            {
                auto start = v.find_first_not_of(" \t\r\n");
                auto end = v.find_last_not_of(" \t\r\n");
                return start == std::string::npos ? std::string() : v.substr(start, end - start + 1);
            };
            std::string id = type == "user" ? trim(username) : type == "license" ? trim(license) : "";
            if (type == "user")
                std::transform(id.begin(), id.end(), id.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return hash(type + "\n" + id);
        }
        static std::string verifier(const std::string &secret, const std::string &salt)
        {
            unsigned char out[32];
            if (PKCS5_PBKDF2_HMAC(secret.data(), static_cast<int>(secret.size()),
                                  reinterpret_cast<const unsigned char *>(salt.data()),
                                  static_cast<int>(salt.size()), 120000, EVP_sha256(), sizeof out,
                                  out) != 1)
                throw error("SIGNING_FAILED", "Could not protect offline access.", "security");
            return b64(std::string(reinterpret_cast<char *>(out), sizeof out));
        }
        std::string record_name(const std::string &value) const
        {
            return prefix + ".offline." + value;
        }
        json slots()
        {
            try
            {
                auto saved = o.storage->load(prefix + ".offline");
                if (saved)
                {
                    auto list = json::parse(*saved);
                    if (list.is_object() && list.contains("slots") && list["slots"].is_array())
                        return list["slots"];
                }
            }
            catch (...)
            {
            }
            return json::array();
        }
        void save_slots(const json &list)
        {
            if (list.empty())
                o.storage->remove(prefix + ".offline");
            else
                o.storage->save(prefix + ".offline", json{{"slots", list}}.dump());
        }
        json load_record(const std::string &value)
        {
            try
            {
                auto saved = o.storage->load(record_name(value));
                if (saved)
                    return json::parse(*saved);
            }
            catch (...)
            {
            }
            return nullptr;
        }
        void forget(const std::string &value)
        {
            if (value.empty())
                return;
            o.storage->remove(record_name(value));
            json kept = json::array();
            for (auto &item : slots())
                if (item != value)
                    kept.push_back(item);
            save_slots(kept);
        }
        void clear_offline()
        {
            offline = nullptr;
            offline_session = false;
            forget(slot);
        }
        void invalidate(const error &e)
        {
            token.clear();
            userData = json::object();
            deadline = 0;
            active = false;
            condition.notify_all();
            try
            {
                clear_offline();
            }
            catch (...)
            {
                offline = nullptr;
                offline_session = false;
            }
            if (o.on_invalidated)
            {
                auto fn = o.on_invalidated;
                queue([fn, e] { fn(e); });
            }
        }
        result verified(const json &outer, int status, const std::string &path,
                        const std::string &body, const std::string &nonce)
        {
            try
            {
                const auto &proof = outer.at("verification");
                auto id = str(proof, "keyId"), pem = find_key(o.response_keys, id),
                     payload = str(proof, "signedPayload");
                if (payload.size() > 2000000 || pem.empty() || key_id(pem) != id ||
                    !verify(pem, payload, str(proof, "signature")))
                    throw std::runtime_error("invalid");
                auto signed_value = json::parse(payload), envelope = outer;
                envelope.erase("verification");
                auto request = json{{"method", "POST"},
                                    {"path", path},
                                    {"nonce", nonce},
                                    {"bodySha256", hash(body)}};
                if (signed_value["type"] != "authlyx.response.v3" || signed_value["keyId"] != id ||
                    signed_value["httpStatus"] != status ||
                    !equivalent(signed_value["request"], request) ||
                    !equivalent(signed_value["response"], envelope) ||
                    !envelope["message"].is_string() || !envelope["success"].is_boolean() ||
                    !envelope["code"].is_string() || !envelope["requestId"].is_string())
                    throw std::runtime_error("invalid");
                set_anchor(timestamp(str(signed_value, "serverTime")));
                return {envelope["success"].get<bool>(), str(envelope, "code"),
                        str(envelope, "message"), str(envelope, "requestId"), envelope["data"]};
            }
            catch (...)
            {
                throw error("RESPONSE_INVALID", "The server response could not be verified.",
                            "security");
            }
        }
        struct transfer
        {
            impl *owner;
            std::stop_token cancel;
            std::string body, retry_after;
            bool oversized = false;
        };
        static std::size_t receive(char *ptr, std::size_t size, std::size_t count, void *context)
        {
            auto &t = *static_cast<transfer *>(context);
            auto n = size * count;
            if (t.body.size() + n > 2000000)
            {
                t.oversized = true;
                return 0;
            }
            t.body.append(ptr, n);
            return n;
        }
        static std::size_t header(char *ptr, std::size_t size, std::size_t count, void *context)
        {
            auto &t = *static_cast<transfer *>(context);
            std::string value(ptr, size * count), lower = value;
            for (auto &c : lower)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (lower.starts_with("retry-after:"))
            {
                t.retry_after = value.substr(12);
                while (!t.retry_after.empty() &&
                       std::isspace(static_cast<unsigned char>(t.retry_after.back())))
                    t.retry_after.pop_back();
                while (!t.retry_after.empty() &&
                       std::isspace(static_cast<unsigned char>(t.retry_after.front())))
                    t.retry_after.erase(t.retry_after.begin());
            }
            return size * count;
        }
        static int progress(void *context, curl_off_t, curl_off_t, curl_off_t, curl_off_t)
        {
            auto &t = *static_cast<transfer *>(context);
            return t.owner->disposed || t.cancel.stop_requested() ? 1 : 0;
        }
        result request(const std::string &path, const json &data, bool auth, bool retry,
                       std::stop_token cancel)
        {
            if (disposed || cancel.stop_requested())
                throw error("REQUEST_CANCELLED", "The request was cancelled.", "cancelled");
            if (auth && token.empty())
                throw error("NOT_SIGNED_IN", "Sign in before using this feature.", "server");
            const auto body = data.dump();
            auto until = steady_clock::now() + o.request_budget;
            for (int attempt = 0;; ++attempt)
            {
                try
                {
                    if (disposed || cancel.stop_requested())
                        throw error("REQUEST_CANCELLED", "The request was cancelled.", "cancelled");
                    auto nonce_bytes = random(24),
                         nonce = hex(reinterpret_cast<const unsigned char *>(nonce_bytes.data()),
                                     nonce_bytes.size()),
                         stamp = std::to_string(now());
                    transfer t{this, cancel};
                    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(),
                                                                             curl_easy_cleanup);
                    if (!curl)
                        throw error("NETWORK_ERROR", "Could not initialize HTTPS.", "network");
                    curl_slist *headers = nullptr;
                    headers = curl_slist_append(headers, "Content-Type: application/json");
                    headers = curl_slist_append(headers, ("X-AuthlyX-Nonce: " + nonce).c_str());
                    if (auth)
                    {
                        headers =
                            curl_slist_append(headers, ("Authorization: Bearer " + token).c_str());
                        headers =
                            curl_slist_append(headers, ("X-AuthlyX-Timestamp: " + stamp).c_str());
                        auto proof = json{{"type", "authlyx.request.v3"},
                                          {"method", "POST"},
                                          {"path", path},
                                          {"bodySha256", hash(body)},
                                          {"nonce", nonce},
                                          {"timestamp", stamp},
                                          {"tokenHash", hash(token)}};
                        headers = curl_slist_append(
                            headers, ("X-AuthlyX-Signature: " + sign(proof.dump())).c_str());
                    }
                    std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> list(
                        headers, curl_slist_free_all);
                    auto url = o.endpoint + path;
                    curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
                    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers);
                    curl_easy_setopt(curl.get(), CURLOPT_POST, 1L);
                    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, body.data());
                    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE_LARGE,
                                     static_cast<curl_off_t>(body.size()));
                    curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 0L);
                    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
                    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);
                    curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);
                    if (share)
                        curl_easy_setopt(curl.get(), CURLOPT_SHARE, share.get());
                    curl_easy_setopt(curl.get(), CURLOPT_TCP_KEEPALIVE, 1L);
                    auto remaining =
                        duration_cast<milliseconds>(until - steady_clock::now()).count();
                    if (remaining <= 0)
                        throw error("NETWORK_TIMEOUT", "The request timed out.", "network");
                    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT_MS, static_cast<long>(remaining));
                    curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT_MS,
                                     static_cast<long>(remaining));
                    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, &receive);
                    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &t);
                    curl_easy_setopt(curl.get(), CURLOPT_HEADERFUNCTION, &header);
                    curl_easy_setopt(curl.get(), CURLOPT_HEADERDATA, &t);
                    curl_easy_setopt(curl.get(), CURLOPT_NOPROGRESS, 0L);
                    curl_easy_setopt(curl.get(), CURLOPT_XFERINFOFUNCTION, &progress);
                    curl_easy_setopt(curl.get(), CURLOPT_XFERINFODATA, &t);
                    auto code = curl_easy_perform(curl.get());
                    if (disposed || cancel.stop_requested())
                        throw error("REQUEST_CANCELLED", "The request was cancelled.", "cancelled");
                    if (t.oversized)
                        throw error("RESPONSE_INVALID", "The server response is too large.",
                                    "security");
                    if (code != CURLE_OK)
                        throw error(code == CURLE_OPERATION_TIMEDOUT ? "NETWORK_TIMEOUT"
                                                                     : "NETWORK_ERROR",
                                    code == CURLE_OPERATION_TIMEDOUT
                                        ? "The request timed out. Try again when connected."
                                        : "Could not connect to AuthlyX.",
                                    "network");
                    long status = 0;
                    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status);
                    json outer;
                    try
                    {
                        outer = json::parse(t.body);
                    }
                    catch (...)
                    {
                        throw error(status >= 500 ? "SERVICE_UNAVAILABLE" : "RESPONSE_INVALID",
                                    status >= 500 ? "The service is temporarily unavailable."
                                                  : "The server response is not valid JSON.",
                                    status >= 500 ? "network" : "security");
                    }
                    if (!outer.contains("verification") && status >= 500)
                        throw error("SERVICE_UNAVAILABLE",
                                    "The service is temporarily unavailable.", "network");
                    auto result = verified(outer, static_cast<int>(status), path, body, nonce);
                    connection("online");
                    if (!result.success || status >= 400)
                    {
                        std::string kind = (status == 429 || status >= 500) ? "network" : "server";
                        if (retry && attempt < 2 &&
                            (kind == "network" || result.code == "REQUEST_TIME_INVALID"))
                        {
                            long long delay = 150;
                            try
                            {
                                if (!t.retry_after.empty())
                                {
                                    std::size_t consumed;
                                    delay = std::stoll(t.retry_after, &consumed) * 1000;
                                    if (consumed != t.retry_after.size())
                                    {
                                        auto seconds = curl_getdate(t.retry_after.c_str(), nullptr);
                                        delay = seconds < 0 ? o.request_budget.count()
                                                            : seconds * 1000LL - wall();
                                    }
                                }
                            }
                            catch (...)
                            {
                                auto seconds = curl_getdate(t.retry_after.c_str(), nullptr);
                                delay = seconds < 0 ? o.request_budget.count()
                                                    : seconds * 1000LL - wall();
                            }
                            if (delay >= 0 &&
                                steady_clock::now() + milliseconds(delay + 50) < until)
                            {
                                for (long long elapsed = 0; elapsed < delay; elapsed += 10)
                                {
                                    if (disposed || cancel.stop_requested())
                                        throw error("REQUEST_CANCELLED",
                                                    "The request was cancelled.", "cancelled");
                                    std::this_thread::sleep_for(
                                        milliseconds(std::min(10LL, delay - elapsed)));
                                }
                                continue;
                            }
                        }
                        error failure(result.code, result.message, kind, static_cast<int>(status),
                                      result.request_id);
                        failure.data = result.data;
                        throw failure;
                    }
                    return result;
                }
                catch (const error &e)
                {
                    if (e.kind == "security")
                    {
                        connection("untrusted");
                        invalidate(e);
                    }
                    else if (e.kind == "network")
                    {
                        connection("disconnected");
                        if (retry && attempt < 2 && e.status == 0 &&
                            steady_clock::now() + milliseconds(200) < until)
                        {
                            std::this_thread::sleep_for(milliseconds(150));
                            continue;
                        }
                    }
                    else if (auth &&
                             (e.code == "SESSION_EXPIRED" || e.code == "ACCESS_REVOKED" ||
                              e.code == "APP_PAUSED" || e.code == "ACCESS_EXPIRED" ||
                              e.code == "ACCESS_DENIED" || e.code == "IP_BLACKLISTED" ||
                              e.code == "IP_NOT_WHITELISTED" || e.code == "SID_BLACKLISTED" ||
                              e.code == "SID_NOT_WHITELISTED" || e.code == "VERSION_NOT_ALLOWED" ||
                              e.code == "HASH_NOT_ALLOWED" || e.code == "COUNTRY_BLOCKED" ||
                              e.code == "VPN_NOT_ALLOWED" || e.code == "DEVICE_NOT_ALLOWED" ||
                              e.code == "APP_DISABLED" ||
                              e.code == "IP_BLOCKED" ||
                              e.code == "SID_BLOCKED" ||
                              e.code == "UPDATE_REQUIRED" ||
                              e.code == "VERSION_MISMATCH" ||
                              e.code == "INVALID_HASH" ||
                              e.code == "VPN_BLOCKED" ||
                              e.code == "USER_BANNED" ||
                              e.code == "USER_SUSPENDED" ||
                              e.code == "USER_EXPIRED" ||
                              e.code == "LICENSE_BANNED" ||
                              e.code == "LICENSE_PAUSED" ||
                              e.code == "LICENSE_EXPIRED" ||
                              e.code == "MOTHERBOARD_BANNED" ||
                              e.code == "MOTHERBOARD_PAUSED" ||
                              e.code == "MOTHERBOARD_EXPIRED" ||
                              e.code == "PROCESSOR_BANNED" ||
                              e.code == "PROCESSOR_PAUSED" ||
                              e.code == "PROCESSOR_EXPIRED"))
                        invalidate(e);
                    throw;
                }
            }
        }
        void lease(const json &data)
        {
            auto value = timestamp(str(data, "accessDeadline"));
            if (value <= 0 || value > now() + 7200100)
            {
                auto e = error("LEASE_INVALID", "The session deadline is invalid.", "security");
                invalidate(e);
                throw e;
            }
            deadline = value;
            for (const auto &field : {"features", "featureValues", "metadata"})
            {
                if (data.contains(field))
                    userData[field] = data[field];
            }
            heartbeat_seconds = std::clamp(data.value("heartbeatSeconds", 600.0), 1.0, 3600.0);
            jitter_seconds = std::clamp(data.value("jitterSeconds", 15.0), 0.0, 15.0);
        }
        result check(std::stop_token cancel)
        {
            auto r = request("/v3/session/check", json::object(), true, true, cancel);
            lease(r.data);
            return r;
        }
        result protected_call(const std::string &path, const json &data, bool retry,
                              std::stop_token cancel)
        {
            if (!token.empty() && deadline <= now())
                check(cancel);
            return request(path, data, true, retry, cancel);
        }
        result login(const std::string &type, const std::string &username,
                     const std::string &password, const std::string &license,
                     std::stop_token cancel)
        {
            if (!token.empty() || offline_session)
                throw error("ALREADY_SIGNED_IN", "Sign out before starting another session.",
                            "server");
            logging_out = false;
            json challenge;
            try
            {
                challenge =
                    request("/v3/challenge",
                            json{{"appKey", o.app_key}, {"installationPublicKey", public_pem}},
                            false, false, cancel)
                        .data;
            }
            catch (const error &e)
            {
                if (e.kind != "network" || type == "register")
                    throw;
                return offline_login(type, username, password, license);
            }
            json operation = {{"type", type},         {"appKey", o.app_key},
                              {"version", o.version}, {"sid", o.systemId},
                              {"hash", o.build_hash}, {"username", username},
                              {"password", password}, {"licenseKey", license},
                              {"device", device_details()}};
            auto signature =
                sign(json{{"challenge", challenge["payload"]}, {"operation", operation}}.dump());
            operation["challengeId"] = challenge["challengeId"];
            operation["signature"] = signature;
            auto r = request("/v3/login", operation, false, false, cancel);
            app_id = str(json::parse(str(challenge, "payload")), "appId");
            token = str(r.data, "token");
            session_id = str(r.data, "sessionId");
            userData = r.data["identity"];
            for (auto pair : {std::pair{"SID", "systemId"},
                              {"Email", "email"},
                              {"Plan", "plan"},
                              {"ExpiryDate", "expiry"},
                              {"Country", "country"},
                              {"IpAddress", "ipAddress"},
                              {"DeviceLimit", "deviceLimit"},
                              {"LicenseKey", "licenseKey"}})
                userData[pair.first] = userData[pair.second];
            userData["Username"] = userData["type"] == "user" ? userData["name"] : json("");
            identity_id = str(r.data, "identityId");
            auto kind = type == "register" ? std::string("user") : type;
            slot = slot_of(kind, username, license);
            auto salt = random(16);
            credential = json{{"kind", kind},
                              {"salt", b64(salt)},
                              {"verifier", kind == "device"
                                               ? std::string()
                                               : verifier(kind == "user" ? password : license, salt)}};
            lease(r.data);
            r.data.erase("token");
            active = true;
            condition.notify_all();
            offer_update(r.data, r.code, r.message);
            return r;
        }
        long long record_now(const json &record) const
        {
            if (server)
                return now();
            return record.at("trustedTime").get<long long>() + wall() -
                   record.at("localTime").get<long long>();
        }
        result offline_login(const std::string &type, const std::string &username,
                             const std::string &password, const std::string &license)
        {
            auto name = slot_of(type, username, license);
            auto record = load_record(name);
            if (record.is_null() || !valid_record(record))
            {
                if (!record.is_null())
                    forget(name);
                throw error("OFFLINE_UNAVAILABLE",
                            "Could not connect to AuthlyX, and this PC has no saved offline access "
                            "for that account. Check your internet connection and try again.",
                            "network");
            }
            if (type != "device")
            {
                auto expected = str(record, "verifier");
                auto actual = verifier(type == "user" ? password : license,
                                       unb64(str(record, "salt")));
                if (expected.size() != actual.size() ||
                    CRYPTO_memcmp(expected.data(), actual.data(), actual.size()) != 0)
                    throw type == "user"
                        ? error("INVALID_CREDENTIALS", "Username or password is incorrect.", "server")
                        : error("LICENSE_NOT_FOUND", "License not found.", "server");
            }
            if (!server)
                set_anchor(record_now(record));
            app_id = str(record, "appId");
            identity_id = str(record, "identityId");
            slot = name;
            offline = record;
            offline_session = true;
            userData = record.contains("userData") && record["userData"].is_object()
                           ? record["userData"]
                           : json::object();
            persist_offline();
            return result{true, "OFFLINE_ACCESS",
                          "Signed in with saved offline access. Online features are unavailable "
                          "until you reconnect.",
                          "", json{{"offline", true}, {"identity", userData}}};
        }
        bool valid_offline()
        {
            return offline_session && valid_record(offline);
        }
        bool valid_record(const json &record)
        {
            try
            {
                if (record.is_null() || logging_out || disposed || wall() < anchor_wall ||
                    wall() < record.at("localTime").get<long long>())
                    return false;
                auto permit = record.at("permit");
                auto payload = str(permit, "signedPayload");
                if (payload.size() > 4096)
                    return false;
                auto claims = json::parse(payload);
                auto id = str(claims, "keyId"), pem = find_key(o.offline_keys, id);
                auto issued = claims.at("issuedAt").get<long long>(),
                     expires = claims.at("expiresAt").get<long long>(),
                     current = record_now(record);
                return !pem.empty() && key_id(pem) == id &&
                       verify(pem, payload, str(permit, "signature")) &&
                       claims["type"] == "authlyx.offline.v1" &&
                       claims["appId"] == record["appId"] &&
                       claims["subjectId"] == record["identityId"] &&
                       claims["installationKeyHash"] == key_hash && issued <= current &&
                       current < expires && expires > issued && expires - issued <= 2592000000LL &&
                       current >= record.at("trustedTime").get<long long>();
            }
            catch (...)
            {
                return false;
            }
        }
        bool persist_offline()
        {
            try
            {
                offline["trustedTime"] = record_now(offline);
                offline["localTime"] = wall();
                o.storage->save(record_name(slot), offline.dump());
                return true;
            }
            catch (...)
            {
                offline = nullptr;
                offline_session = false;
                return false;
            }
        }
        void start()
        {
            if (o.manual_heartbeat)
                return;
            auto shared = shared_from_this();
            worker = std::thread(
                [this, shared]
                {
                    while (!disposed)
                    {
                        std::unique_lock lock(schedule_gate);
                        condition.wait(lock, [this] { return disposed || active; });
                        if (disposed)
                            return;
                        auto bytes = random(4);
                        unsigned number = 0;
                        std::memcpy(&number, bytes.data(), 4);
                        auto delay = milliseconds(static_cast<long long>(
                            std::max(1.0, heartbeat_seconds.load() +
                                              (static_cast<double>(number) / 0xffffffff * 2 - 1) *
                                                  jitter_seconds.load()) *
                            1000));
                        if (condition.wait_for(lock, delay, [this] { return disposed || !active; }))
                            continue;
                        lock.unlock();
                        try
                        {
                            {
                                std::lock_guard call(gate);
                                if (!disposed && active)
                                    check({});
                            }
                            flush();
                        }
                        catch (...)
                        {
                            flush();
                        }
                    }
                });
        }
        void close()
        {
            if (disposed.exchange(true))
                return;
            active = false;
            condition.notify_all();
            if (worker.joinable())
            {
                if (worker.get_id() == std::this_thread::get_id())
                    worker.detach();
                else
                    worker.join();
            }
            std::lock_guard lock(gate);
            token.clear();
            userData = json::object();
            deadline = 0;
        }
    };
    AUTHLYX_INLINE AuthlyX::AuthlyX(options o) : impl_(std::make_shared<impl>(std::move(o)))
    {
        impl_->start();
    }
    AUTHLYX_INLINE AuthlyX::~AuthlyX()
    {
        close();
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::execute(std::function<result(impl &, std::stop_token)> fn,
                                                std::stop_token cancel)
    {
        auto shared = impl_;
        return std::async(std::launch::async,
                          [shared, fn = std::move(fn), cancel]
                          {
                              try
                              {
                                  result r;
                                  {
                                      std::lock_guard lock(shared->gate);
                                      if (shared->disposed || cancel.stop_requested())
                                          throw error("REQUEST_CANCELLED",
                                                      "The request was cancelled.", "cancelled");
                                      r = fn(*shared, cancel);
                                  }
                                  shared->flush();
                                  shared->show_prompt();
                                  return r;
                              }
                              catch (...)
                              {
                                  shared->flush();
                                  throw;
                              }
                          });
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::init(std::stop_token c)
    {
        return execute(
            [](impl &p, std::stop_token c)
            {
                try
                {
                    return p.request("/v3/initialize",
                                     json{{"appKey", p.o.app_key}, {"version", p.o.version}}, false,
                                     true, c);
                }
                catch (const error &e)
                {
                    if (e.kind == "network")
                    {
                        if (p.offline_available())
                            return result{true, "OFFLINE_MODE",
                                          "You are offline. Sign in with the account you saved "
                                          "offline access for.",
                                          e.request_id, json::object()};
                        return result{false, e.code,
                                      "Could not connect to AuthlyX. Check your internet connection.",
                                      e.request_id, nullptr};
                    }
                    if (e.kind != "server")
                        throw;
                    p.offer_update(e.data, e.code, e.what());
                    return result{false, e.code, e.what(), e.request_id, e.data};
                }
            },
            c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::login(std::string u, std::string p, std::stop_token c)
    {
        return execute([u = std::move(u), p = std::move(p)](impl &s, std::stop_token c)
                       { return s.login("user", u, p, "", c); }, c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::login(std::string key, std::stop_token c)
    {
        return licenseLogin(std::move(key), c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::licenseLogin(std::string key, std::stop_token c)
    {
        return execute([key = std::move(key)](impl &s, std::stop_token c)
                       { return s.login("license", "", "", key, c); }, c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::deviceLogin(std::stop_token c)
    {
        return execute([](impl &s, std::stop_token c) { return s.login("device", "", "", "", c); },
                       c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::checkSession(std::stop_token c)
    {
        return execute([](impl &s, std::stop_token c) { return s.check(c); }, c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::onResume(std::stop_token c)
    {
        return checkSession(c);
    }
    AUTHLYX_INLINE json AuthlyX::userData() const
    {
        std::lock_guard lock(impl_->gate);
        return impl_->userData;
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::registerUser(std::string u, std::string p, std::string k,
                                                     std::stop_token c)
    {
        return execute(
            [u = std::move(u), p = std::move(p), k = std::move(k)](impl &s, std::stop_token c)
            { return s.login("register", u, p, k, c); }, c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::changePassword(std::string p, std::string n,
                                                       std::stop_token c)
    {
        return execute(
            [p = std::move(p), n = std::move(n)](impl &s, std::stop_token c)
            {
                return s.protected_call("/v3/account/password",
                                        json{{"currentPassword", p}, {"newPassword", n}}, false, c);
            },
            c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::redeemLicense(std::string k, std::stop_token c)
    {
        return execute(
            [k = std::move(k)](impl &s, std::stop_token c)
            { return s.protected_call("/v3/licenses/redeem", json{{"licenseKey", k}}, false, c); },
            c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::log(std::string m, std::stop_token c)
    {
        return execute([m = std::move(m)](impl &s, std::stop_token c)
                       { return s.protected_call("/v3/logs/add", json{{"message", m}}, false, c); },
                       c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::getMetadata(std::stop_token c)
    {
        return execute([](impl &s, std::stop_token c)
                       { return s.protected_call("/v3/metadata/get", json::object(), true, c); },
                       c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::updateVariable(std::string name, std::string value,
                                                       std::stop_token c)
    {
        return execute(
            [name = std::move(name), value = std::move(value)](impl &s, std::stop_token cancel)
            {
                return s.protected_call("/v3/data/set", json{{"name", name}, {"value", value}},
                                        false, cancel);
            },
            c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::getFeatures(std::stop_token c)
    {
        return execute(
            [](impl &s, std::stop_token cancel)
            { return s.protected_call("/v3/features/list", json::object(), true, cancel); }, c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::getFeature(std::string name, std::stop_token c)
    {
        return execute(
            [name = std::move(name)](impl &s, std::stop_token cancel)
            { return s.protected_call("/v3/features/get", json{{"name", name}}, true, cancel); },
            c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::getAllMetadata(std::stop_token c)
    {
        return execute(
            [](impl &s, std::stop_token cancel)
            { return s.protected_call("/v3/metadata/list", json::object(), true, cancel); }, c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::getMetadata(std::string key, std::stop_token c)
    {
        return execute(
            [key = std::move(key)](impl &s, std::stop_token cancel)
            { return s.protected_call("/v3/metadata/get", json{{"key", key}}, true, cancel); }, c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::checkMetadata(std::string key, std::stop_token c)
    {
        return execute(
            [key = std::move(key)](impl &s, std::stop_token cancel)
            { return s.protected_call("/v3/metadata/check", json{{"key", key}}, true, cancel); },
            c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::sendWebhook(std::string event_name, json data,
                                                    std::stop_token c)
    {
        return execute(
            [event_name = std::move(event_name), data = std::move(data)](impl &s,
                                                                         std::stop_token cancel)
            {
                return s.protected_call("/v3/webhooks/send",
                                        json{{"event", event_name}, {"data", data}}, false, cancel);
            },
            c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::setMetadata(std::string key, json value, std::stop_token c)
    {
        return execute(
            [key = std::move(key), value = std::move(value)](impl &s, std::stop_token c)
            {
                return s.protected_call("/v3/metadata/set", json{{"key", key}, {"value", value}},
                                        false, c);
            },
            c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::checkFeature(std::string name, std::stop_token c)
    {
        return execute(
            [name = std::move(name)](impl &s, std::stop_token c)
            { return s.protected_call("/v3/features/check", json{{"name", name}}, true, c); }, c);
    }
    AUTHLYX_INLINE std::future<void> complete(std::future<result> operation,
                                      std::function<void(result)> callback)
    {
        if (!callback)
            throw std::invalid_argument("A completion callback is required.");
        std::packaged_task<void()> task(
            [operation = std::move(operation), callback = std::move(callback)]() mutable
            {
                result value;
                try
                {
                    value = operation.get();
                }
                catch (const error &failure)
                {
                    value =
                        result{false, failure.code, failure.what(), failure.request_id, nullptr};
                }
                catch (const std::exception &failure)
                {
                    value = result{false, "CLIENT_ERROR", failure.what(), "", nullptr};
                }
                callback(std::move(value));
            });
        auto finished = task.get_future();
        std::thread(std::move(task)).detach();
        return finished;
    }
    AUTHLYX_INLINE std::future<void> AuthlyX::init(std::function<void(result)> callback,
                                           std::stop_token cancel)
    {
        return complete(init(cancel), std::move(callback));
    }
    AUTHLYX_INLINE std::future<void> AuthlyX::login(std::string key, std::function<void(result)> callback,
                                            std::stop_token cancel)
    {
        return complete(login(std::move(key), cancel), std::move(callback));
    }
    AUTHLYX_INLINE std::future<void> AuthlyX::login(std::string username, std::string password,
                                            std::function<void(result)> callback,
                                            std::stop_token cancel)
    {
        return complete(login(std::move(username), std::move(password), cancel),
                        std::move(callback));
    }
    AUTHLYX_INLINE std::future<void> AuthlyX::getVariable(std::string name,
                                                  std::function<void(result)> callback,
                                                  std::stop_token cancel)
    {
        return complete(getVariable(std::move(name), cancel), std::move(callback));
    }
    AUTHLYX_INLINE std::future<void> AuthlyX::getScript(std::string name,
                                                std::function<void(result)> callback,
                                                std::stop_token cancel)
    {
        return complete(getScript(std::move(name), std::nullopt, cancel), std::move(callback));
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::getVariable(std::string name, std::stop_token c)
    {
        return execute([name = std::move(name)](impl &s, std::stop_token c)
                       { return s.protected_call("/v3/data/get", json{{"name", name}}, true, c); },
                       c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::getScript(std::string name, std::optional<int> revision,
                                                  std::stop_token c)
    {
        return execute(
            [name = std::move(name), revision](impl &s, std::stop_token c)
            {
                json data = {{"name", name}};
                if (revision)
                    data["revision"] = *revision;
                auto r = s.protected_call("/v3/scripts/get", data, true, c);
                auto payload = str(r.data, "signedPayload"), content = str(r.data, "content");
                auto manifest = json::parse(payload);
                if (manifest.contains("issuedAt") || manifest.contains("expiresAt"))
                {
                    if (!manifest["issuedAt"].is_number_integer() ||
                        !manifest["expiresAt"].is_number_integer() ||
                        manifest["issuedAt"].get<int64_t>() > s.now() + 30000 ||
                        manifest["expiresAt"].get<int64_t>() <= s.now() ||
                        manifest["expiresAt"].get<int64_t>() <= manifest["issuedAt"].get<int64_t>())
                        throw error("SCRIPT_INVALID", "The script could not be verified.",
                                    "security");
                }
                if (manifest.contains("minimumRevision") &&
                    (!manifest["minimumRevision"].is_number_integer() ||
                     manifest["revision"] < manifest["minimumRevision"]))
                    throw error("SCRIPT_INVALID", "The script could not be verified.", "security");
                auto pem = find_key(s.o.script_keys, str(manifest, "keyId"));
                if (pem.empty() || !verify(pem, payload, str(r.data, "signature")) ||
                    !equivalent(manifest, r.data["manifest"]) || manifest["appId"] != s.app_id ||
                    manifest["name"] != name || (revision && manifest["revision"] != *revision) ||
                    manifest["sha256"] != hash(content) || manifest["bytes"] != content.size())
                    throw error("SCRIPT_INVALID", "The script could not be verified.", "security");
                return r;
            },
            c);
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::saveOfflineAccess(std::stop_token c)
    {
        return execute(
            [](impl &s, std::stop_token c)
            {
                if (s.token.empty() || s.credential.is_null())
                    throw error("NOT_SIGNED_IN",
                                "Sign in online before saving offline access.", "server");
                auto challenge =
                    s.request("/v3/offline/challenge", json::object(), true, false, c).data;
                auto proof = s.sign(json{
                    {"challenge", challenge["payload"]},
                    {"operation", json{{"action", "offlinePermit"}, {"sessionId", s.session_id}}}}
                                        .dump());
                auto r =
                    s.request("/v3/offline/permit",
                              json{{"challengeId", challenge["challengeId"]}, {"signature", proof}},
                              true, false, c);
                json record{{"appId", s.app_id},
                            {"identityId", s.identity_id},
                            {"kind", s.credential["kind"]},
                            {"salt", s.credential["salt"]},
                            {"verifier", s.credential["verifier"]},
                            {"permit", r.data},
                            {"trustedTime", s.now()},
                            {"localTime", wall()},
                            {"userData", s.userData}};
                if (!s.valid_record(record))
                    throw error("OFFLINE_INVALID", "The offline permit could not be verified.",
                                "security");
                try
                {
                    s.o.storage->save(s.record_name(s.slot), record.dump());
                    auto list = s.slots();
                    if (std::find(list.begin(), list.end(), json(s.slot)) == list.end())
                        list.push_back(s.slot);
                    s.save_slots(list);
                }
                catch (...)
                {
                    throw error("STORAGE_INVALID", "Could not save protected offline state.",
                                "storage");
                }
                return r;
            },
            c);
    }
    AUTHLYX_INLINE bool AuthlyX::hasAccess()
    {
        std::lock_guard lock(impl_->gate);
        if (impl_->disposed || impl_->logging_out)
            return false;
        return (!impl_->token.empty() && impl_->deadline > impl_->now()) ||
               (impl_->valid_offline() && impl_->persist_offline());
    }
    AUTHLYX_INLINE bool AuthlyX::hasOfflineAccess()
    {
        std::lock_guard lock(impl_->gate);
        return impl_->offline_available();
    }
    AUTHLYX_INLINE std::future<result> AuthlyX::logout(std::stop_token c)
    {
        impl_->logging_out = true;
        impl_->active = false;
        impl_->condition.notify_all();
        return execute(
            [c](impl &s, std::stop_token)
            {
                s.logging_out = true;
                try
                {
                    result r{true, "SESSION_ENDED", "You have signed out.", "", nullptr};
                    if (!s.token.empty())
                        r = s.request("/v3/session/logout", json::object(), true, false, c);
                    s.token.clear();
                    s.userData = json::object();
                    s.deadline = 0;
                    s.clear_offline();
                    s.credential = nullptr;
                    s.slot.clear();
                    return r;
                }
                catch (...)
                {
                    s.token.clear();
                    s.userData = json::object();
                    s.deadline = 0;
                    s.clear_offline();
                    throw;
                }
            },
            {});
    }
    AUTHLYX_INLINE void AuthlyX::close()
    {
        if (impl_)
            impl_->close();
    }
}

namespace authlyx
{
    AUTHLYX_INLINE std::string AuthlyX::systemId()
    {
#ifdef _WIN32
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
            throw error("SYSTEM_ID_UNAVAILABLE", "Could not read the Windows user SID.", "storage");
        DWORD size = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &size);
        std::vector<unsigned char> buffer(size);
        if (!GetTokenInformation(token, TokenUser, buffer.data(), size, &size))
        {
            CloseHandle(token);
            throw error("SYSTEM_ID_UNAVAILABLE", "Could not read the Windows user SID.", "storage");
        }
        LPSTR value = nullptr;
        const bool valid =
            ConvertSidToStringSidA(reinterpret_cast<TOKEN_USER *>(buffer.data())->User.Sid, &value);
        CloseHandle(token);
        if (!valid)
            throw error("SYSTEM_ID_UNAVAILABLE", "Could not read the Windows user SID.", "storage");
        std::string sid(value);
        LocalFree(value);
        return sid;
#else
        throw error("SYSTEM_ID_UNAVAILABLE", "Supply a platform system ID through options.",
                    "storage");
#endif
    }
    AUTHLYX_INLINE options defaultOptions(std::string app_key, std::string version)
    {
        options o;
        o.app_key = std::move(app_key);
        o.version = std::move(version);
        o.systemId = AuthlyX::systemId();
        o.endpoint = "https://api.authlyx.dev";
        o.allow_local_http = true;
#ifdef _WIN32
        std::wstring local(32768, L'\0');
        DWORD size = GetEnvironmentVariableW(L"LOCALAPPDATA", local.data(),
                                             static_cast<DWORD>(local.size()));
        if (!size || size >= local.size())
            throw error("STORAGE_UNAVAILABLE", "LOCALAPPDATA is unavailable.", "storage");
        local.resize(size);
        o.storage = std::make_shared<windows_protected_store>(std::filesystem::path(local) /
                                                              "AuthlyX" / "v3");
#else
        throw error("STORAGE_UNAVAILABLE", "Supply a platform-protected store through options.",
                    "storage");
#endif
        o.response_keys = {{"2318305346828e7b61e0447bfc4b3daac50dcda1b425814120ee3d6947609052",
                            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAaXXIKXRn0uPJ16wc4SX1GLArAGTAPeVhreGxp4f9/6Q=\n-----END PUBLIC KEY-----\n"}};
        o.offline_keys = {{"d3ea94e9f098eece181306689713c9f4d984c0321948fbd0007ef471bcf5b7d2",
                           "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA7d2GrJ8SIUFor6bZuXo0NCX2k9SkHVz5PxOZDut3ydk=\n-----END PUBLIC KEY-----\n"}};
        o.script_keys = {{"5aec455eb0b10697",
                          "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA0zpUhvFdbX95R1Q0+105MZsJr0IJ/yFTNxSiUwqfFH0=\n-----END PUBLIC KEY-----\n"}};
        return o;
    }
    AUTHLYX_INLINE AuthlyX::AuthlyX(std::string app_key, std::string version)
        : AuthlyX(defaultOptions(std::move(app_key), std::move(version)))
    {
    }
}
#endif
namespace authlyx
{
    using client = AuthlyX;
}
using AuthlyX = authlyx::AuthlyX;
