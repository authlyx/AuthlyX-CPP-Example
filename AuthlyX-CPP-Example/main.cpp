#include "AuthlyX.h"
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>
#ifdef _WIN32
#include <conio.h>
#include <io.h>
#define isatty _isatty
#define fileno _fileno
#else
#include <unistd.h>
#endif

using authlyx::json;

static const bool interactive = isatty(fileno(stdin)) && isatty(fileno(stdout));

static void clear()
{
        if (!interactive)
            return;
    #ifdef _WIN32
        std::system("cls");
    #else
        std::cout << "\x1b[2J\x1b[H" << std::flush;
    #endif
}

static std::string ask(const std::string &label)
{
    std::cout << label << ": " << std::flush;
    std::string value;
    if (!std::getline(std::cin, value))
        std::exit(0);
    auto end = value.find_last_not_of(" \t\r");
    return end == std::string::npos ? "" : value.substr(value.find_first_not_of(" \t"), end + 1 - value.find_first_not_of(" \t"));
}

static std::string askPassword()
{
    #ifdef _WIN32
        if (interactive)
        {
            std::cout << "Password: " << std::flush;
            std::string value;
            for (int c; (c = _getch()) != '\r';)
            {
                if (c == '\b')
                {
                    if (!value.empty())
                    {
                        value.pop_back();
                        std::cout << "\b \b" << std::flush;
                    }
                }
                else if (c == 0 || c == 224)
                    _getch();
                else if (c >= 32)
                {
                    value.push_back(static_cast<char>(c));
                    std::cout << '*' << std::flush;
                }
            }
            std::cout << '\n';
            return value;
        }
    #endif
    return ask("Password");
}

static void pause()
{
    std::cout << "\nPress Enter to go back." << std::flush;
    std::string ignored;
    if (!std::getline(std::cin, ignored))
        std::exit(0);
}

static void title(const std::string &text)
{
    clear();
    std::cout << "AuthlyX  |  C++ example\n\n" << text << "\n\n";
}

static std::string text(const json &value)
{
    if (value.is_null())
        return "-";
    if (value.is_string())
        return value.get<std::string>().empty() ? "-" : value.get<std::string>();
    if (value.is_boolean())
        return value.get<bool>() ? "Yes" : "No";
    return value.dump();
}

static std::string date(const json &value, bool withTime)
{
    if (!value.is_string() || value.get<std::string>().empty())
        return "-";
    auto s = value.get<std::string>();
    if (!withTime || s.size() < 16)
        return s.substr(0, 10);
    return s.substr(0, 10) + " " + s.substr(11, 5) + " UTC";
}

static void row(const std::string &label, const std::string &value)
{
    std::cout << "  " << std::left << std::setw(16) << label << value << '\n';
}

static std::string displayName(const json &user)
{
    return text(user.value("name", json()));
}

static std::string expiry(const json &user)
{
    auto value = user.value("expiry", json());
    return value.is_null() ? "Never" : date(value, false);
}

static void showAccount(const json &user)
{
    title("Account details");
    auto type = user.value("type", std::string());
    row(type == "license" ? "License key" : type == "device" ? "Device" : "Username",
        displayName(user));
    if (type != "license" && user.contains("licenseKey") && !user["licenseKey"].is_null())
        row("License key", text(user["licenseKey"]));
    row("Email", text(user.value("email", json())));
    row("Plan", text(user.value("plan", json())));
    row("Expires", expiry(user));
    auto limit = user.value("deviceLimit", json());
    row("Device limit", limit.is_number() && limit.get<int>() == 0 ? "Unlimited" : text(limit));
    row("Registered", date(user.value("registeredAt", json()), true));
    row("Last sign-in", date(user.value("lastLogin", json()), true));
    row("System ID", text(user.value("systemId", json())));
    row("IP address", text(user.value("ipAddress", json())));
    row("Country", text(user.value("country", json())));
}

static void showList(const std::string &heading, const json &values, const char *empty)
{
    std::cout << heading << '\n';
    if (!values.is_object() || values.empty())
        std::cout << "  " << empty << '\n';
    else
        for (auto &[key, value] : values.items())
            row(key, text(value));
}

int main()
{
    try
    {
        AuthlyX app("", "");
        std::string notice;
        for (;;)
        {
            title("Connecting...");
            authlyx::result initialized;
            try
            {
                initialized = app.initialize().get();
            }
            catch (const authlyx::error &error)
            {
                initialized = {false, error.code, error.what(), error.request_id, nullptr};
            }
            if (initialized.ok())
                break;
            bool network = initialized.code.rfind("NETWORK", 0) == 0;
            if (network && app.hasOfflineAccess())
            {
                notice = "You are offline. Sign in with the account you saved offline access for.";
                break;
            }
            title("Could not connect");
            std::cout << initialized.message << '\n';
            if (network)
                std::cout << "Check your internet connection.\n";
            std::cout << "\n  1  Try again\n  0  Exit\n\n";
            if (ask("Choose") != "1")
                return 0;
        }
        for (;;)
        {
            if (!app.hasAccess())
            {
                title("Sign in");
                if (!notice.empty())
                    std::cout << notice << "\n\n";
                notice.clear();
                std::cout << "  1  Username and password\n"
                             "  2  License key\n"
                             "  3  This device\n"
                             "  0  Exit\n\n";
                auto choice = ask("Choose");
                authlyx::result result;
                try
                {
                    if (choice == "1")
                    {
                        auto username = ask("Username");
                        result = app.login(username, askPassword()).get();
                    }
                    else if (choice == "2")
                        result = app.login(ask("License key")).get();
                    else if (choice == "3")
                        result = app.deviceLogin().get();
                    else if (choice == "0" || choice.empty())
                        break;
                    else
                    {
                        notice = "Choose 1, 2, 3 or 0.";
                        continue;
                    }
                    if (!result.ok())
                        notice = result.message;
                }
                catch (const authlyx::error &error)
                {
                    notice = error.what();
                }
                continue;
            }

            auto user = app.userData();
            title("Signed in as " + displayName(user) + "  |  " + text(user.value("plan", json())) +
                  " plan  |  Expires " + expiry(user));
            if (!notice.empty())
                std::cout << notice << "\n\n";
            notice.clear();
            std::cout << "  1  Account details          6  Check session\n"
                         "  2  Read a variable          7  Send a log\n"
                         "  3  Update a variable        8  Save offline access\n"
                         "  4  Features and metadata    9  Sign out\n"
                         "  5  Fetch a script           0  Exit\n\n";
            auto choice = ask("Choose");
            if (choice == "0" || choice.empty())
                break;
            try
            {
                if (choice == "1")
                    showAccount(user);
                else if (choice == "2")
                {
                    auto name = ask("Variable name");
                    auto result = app.getVariable(name).get();
                    title("Variable");
                    if (result.ok())
                    {
                        row("Name", name);
                        row("Value", text(result.data.value("value", json())));
                    }
                    else
                        std::cout << result.message << '\n';
                }
                else if (choice == "3")
                {
                    auto name = ask("Variable name");
                    auto value = ask("New value");
                    auto result = app.updateVariable(name, value).get();
                    title("Update a variable");
                    std::cout << result.message << '\n';
                }
                else if (choice == "4")
                {
                    auto features = app.getFeatures().get();
                    auto metadata = app.getAllMetadata().get();
                    title("Features and metadata");
                    showList("Features", features.data.value("features", json::object()),
                             "No features on this plan.");
                    std::cout << '\n';
                    showList("Metadata", metadata.data.value("metadata", json::object()),
                             "No metadata.");
                }
                else if (choice == "5")
                {
                    auto name = ask("Script name");
                    auto result = app.getScript(name).get();
                    title("Script: " + name);
                    std::cout << (result.ok() ? text(result.data.value("content", json()))
                                              : result.message)
                              << '\n';
                }
                else if (choice == "6")
                {
                    auto result = app.checkSession().get();
                    title("Session");
                    std::cout << result.message << '\n';
                }
                else if (choice == "7")
                {
                    auto message = ask("Log message");
                    auto result = app.log(message).get();
                    title("Send a log");
                    std::cout << result.message << '\n';
                }
                else if (choice == "8")
                {
                    auto result = app.saveOfflineAccess().get();
                    title("Offline access");
                    std::cout << result.message << '\n';
                }
                else if (choice == "9")
                {
                    app.logout().get();
                    notice = "You are signed out.";
                    continue;
                }
                else
                {
                    notice = "Choose one of the listed options.";
                    continue;
                }
            }
            catch (const authlyx::error &error)
            {
                title("Something went wrong");
                std::cout << error.what() << '\n';
            }
            pause();
        }
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
