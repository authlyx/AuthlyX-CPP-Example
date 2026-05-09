#include <iostream>
#include <string>
#include <conio.h> 
#include <windows.h> 
#include "AuthlyX.h"

void SetConsoleColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

void ResetConsoleColor() {
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

std::string ReadPassword() {
    std::string password;
    char ch;

    while ((ch = _getch()) != '\r') {
        if (ch == '\b') {
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";
            }
        }
        else {
            password.push_back(ch);
            std::cout << '*';
        }
    }
    std::cout << std::endl;
    return password;
}

void DisplayResult(const std::string& operation, const AuthlyX::Response& response) {
    std::cout << "\n" << std::string(30, '-') << std::endl;
    if (response.success) {
        SetConsoleColor(FOREGROUND_GREEN);
        std::cout << "[OK] " << operation << " SUCCESS" << std::endl;
        ResetConsoleColor();
        std::cout << "Message: " << response.message << std::endl;
    }
    else {
        SetConsoleColor(FOREGROUND_RED);
        std::cout << "[X] " << operation << " FAILED" << std::endl;
        ResetConsoleColor();
        std::cout << "Message: " << response.message << std::endl;
    }
    std::cout << std::string(30, '-') << std::endl;
}

void DisplayUserInfo(const AuthlyX::UserData& user) {
    std::cout << "\n" << std::string(50, '=') << std::endl;
    SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_GREEN);
    std::cout << "USER PROFILE" << std::endl;
    ResetConsoleColor();
    std::cout << std::string(50, '=') << std::endl;

    std::cout << "Username: " << (user.username.empty() ? "N/A" : user.username) << std::endl;
    std::cout << "Email: " << (user.email.empty() ? "N/A" : user.email) << std::endl;
    std::cout << "License Key: " << (user.licenseKey.empty() ? "N/A" : user.licenseKey) << std::endl;
    std::cout << "Subscription: " << (user.subscription.empty() ? "N/A" : user.subscription) << std::endl;
    std::cout << "Subscription Level: " << (user.subscriptionLevel.empty() ? "N/A" : user.subscriptionLevel) << std::endl;
    std::cout << "Expiry Date: " << (user.expiryDate.empty() ? "N/A" : user.expiryDate) << std::endl;
    std::cout << "Days Left: " << user.daysLeft << std::endl;
    std::cout << "Last Login: " << (user.lastLogin.empty() ? "N/A" : user.lastLogin) << std::endl;
    std::cout << "Registered At: " << (user.registeredAt.empty() ? "N/A" : user.registeredAt) << std::endl;
    std::cout << "HWID/SID: " << (user.hwid.empty() ? "N/A" : user.hwid) << std::endl;
    std::cout << "IP Address: " << (user.ipAddress.empty() ? "N/A" : user.ipAddress) << std::endl;
    std::cout << std::string(50, '=') << std::endl;
}

void ShowLoginMenu() {
    std::cout << "\n" << std::string(50, '=') << std::endl;
    SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_GREEN);
    std::cout << "LOGIN MENU - Choose an option:" << std::endl;
    ResetConsoleColor();
    std::cout << "1. Login (Username + Password)" << std::endl;
    std::cout << "2. Register New Account" << std::endl;
    std::cout << "3. License Login (License Key Only)" << std::endl;
    std::cout << "4. Device Login (Motherboard/Processor ID)" << std::endl;
    std::cout << "0. Exit" << std::endl;
    std::cout << std::string(50, '=') << std::endl;
    std::cout << "Your choice: ";
}

void ShowMainMenu() {
    std::cout << "\n" << std::string(50, '=') << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN);
    std::cout << "MAIN MENU - Choose an option:" << std::endl;
    ResetConsoleColor();
    std::cout << "1. Variable Operations" << std::endl;
    std::cout << "2. View User Information" << std::endl;
    std::cout << "3. Send Log Message" << std::endl;
    std::cout << "4. Test All Features" << std::endl;
    std::cout << "5. Show Application Info" << std::endl;
    std::cout << "6. Chat System" << std::endl;
    std::cout << "9. Logout" << std::endl;
    std::cout << "0. Exit" << std::endl;
    std::cout << std::string(50, '=') << std::endl;
    std::cout << "Your choice: ";
}

bool TestLogin(AuthlyX& authly) {
    std::cout << "\n" << std::string(40, '-') << std::endl;
    SetConsoleColor(FOREGROUND_BLUE);
    std::cout << "LOGIN" << std::endl;
    ResetConsoleColor();

    std::cout << "Enter Username: ";
    std::string username;
    std::getline(std::cin, username);

    std::cout << "Enter Password: ";
    std::string password = ReadPassword();

    std::cout << "\nAuthenticating..." << std::endl;

    authly.Log("Login attempt for user: " + username);

    if (authly.Login(username, password)) {
        DisplayResult("Login", authly.response);

        if (authly.response.success) {
            authly.Log("User logged in successfully: " + username);
            return true;
        }
    }
    else {
        DisplayResult("Login", authly.response);
        authly.Log("Login failed for user: " + username + " - Reason: " + authly.response.message);
    }
    return false;
}

bool TestRegister(AuthlyX& authly) {
    std::cout << "\n" << std::string(40, '-') << std::endl;
    SetConsoleColor(FOREGROUND_BLUE);
    std::cout << "REGISTRATION" << std::endl;
    ResetConsoleColor();

    std::cout << "Enter Username: ";
    std::string username;
    std::getline(std::cin, username);

    std::cout << "Enter Password: ";
    std::string password = ReadPassword();

    std::cout << "Enter License Key: ";
    std::string licenseKey;
    std::getline(std::cin, licenseKey);

    std::cout << "Enter Email (optional): ";
    std::string email;
    std::getline(std::cin, email);

    if (email.empty()) {
        email = "";
    }

    std::cout << "\nRegistering account..." << std::endl;

    authly.Log("Registration attempt for user: " + username);

    if (authly.Register(username, password, licenseKey, email)) {
        DisplayResult("Registration", authly.response);

        if (authly.response.success) {
            authly.Log("User registered successfully: " + username);
            return true;
        }
    }
    else {
        DisplayResult("Registration", authly.response);
        authly.Log("Registration failed for user: " + username + " - Reason: " + authly.response.message);
    }
    return false;
}

bool TestLicenseLogin(AuthlyX& authly) {
    std::cout << "\n" << std::string(40, '-') << std::endl;
    SetConsoleColor(FOREGROUND_BLUE);
    std::cout << "LICENSE LOGIN" << std::endl;
    ResetConsoleColor();

    std::cout << "Enter License Key: ";
    std::string licenseKey;
    std::getline(std::cin, licenseKey);

    std::cout << "\nAuthenticating with license..." << std::endl;

    authly.Log("License login attempt with key: " + licenseKey.substr(0, 8) + "...");

    if (authly.Authenticate(licenseKey)) {
        DisplayResult("License Login", authly.response);

        if (authly.response.success) {
            authly.Log("License login successful for key: " + licenseKey.substr(0, 8) + "...");
            return true;
        }
    }
    else {
        DisplayResult("License Login", authly.response);
        authly.Log("License login failed for key: " + licenseKey.substr(0, 8) + "... - Reason: " + authly.response.message);
    }
    return false;
}

void TestVariables(AuthlyX& authly) {
    std::cout << "\n" << std::string(40, '-') << std::endl;
    SetConsoleColor(FOREGROUND_BLUE);
    std::cout << "VARIABLE OPERATIONS" << std::endl;
    ResetConsoleColor();

    std::cout << "1. Get Variable" << std::endl;
    std::cout << "2. Set Variable" << std::endl;
    std::cout << "Choose operation: ";

    std::string choice;
    std::getline(std::cin, choice);

    if (choice == "1") {
        std::cout << "Enter Variable Key: ";
        std::string varKey;
        std::getline(std::cin, varKey);

        std::cout << "\nFetching variable..." << std::endl;

        authly.Log("Getting variable: " + varKey);

        std::string value = authly.GetVariable(varKey);

        if (authly.response.success) {
            SetConsoleColor(FOREGROUND_GREEN);
            std::cout << "Variable '" << varKey << "': " << value << std::endl;
            ResetConsoleColor();

            authly.Log("Successfully retrieved variable: " + varKey + " = " + value);
        }
        else {
            DisplayResult("Get Variable", authly.response);
            authly.Log("Failed to get variable: " + varKey + " - Reason: " + authly.response.message);
        }
    }
    else if (choice == "2") {
        std::cout << "Enter Variable Key: ";
        std::string varKey;
        std::getline(std::cin, varKey);

        std::cout << "Enter Variable Value: ";
        std::string varValue;
        std::getline(std::cin, varValue);

        std::cout << "\nSetting variable..." << std::endl;

        authly.Log("Setting variable: " + varKey + " = " + varValue);

        if (authly.SetVariable(varKey, varValue)) {
            DisplayResult("Set Variable", authly.response);

            if (authly.response.success) {
                authly.Log("Successfully set variable: " + varKey + " = " + varValue);
            }
        }
        else {
            DisplayResult("Set Variable", authly.response);
            authly.Log("Failed to set variable: " + varKey + " - Reason: " + authly.response.message);
        }
    }
    else {
        SetConsoleColor(FOREGROUND_RED);
        std::cout << "Invalid choice for variable operation." << std::endl;
        ResetConsoleColor();
    }
}

void TestLogMessage(AuthlyX& authly) {
    std::cout << "\n" << std::string(40, '-') << std::endl;
    SetConsoleColor(FOREGROUND_BLUE);
    std::cout << "SEND LOG MESSAGE" << std::endl;
    ResetConsoleColor();

    std::cout << "Enter log message: ";
    std::string message;
    std::getline(std::cin, message);

    std::cout << "\nSending log message..." << std::endl;

    if (authly.Log(message)) {
        DisplayResult("Send Log", authly.response);
    }
    else {
        DisplayResult("Send Log", authly.response);
    }
}

void ShowApplicationInfo(AuthlyX& authly) {
    std::cout << "\n" << std::string(50, '=') << std::endl;
    SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_GREEN);
    std::cout << "APPLICATION INFORMATION" << std::endl;
    ResetConsoleColor();
    std::cout << std::string(50, '=') << std::endl;

    std::cout << "App Name: " << authly.GetAppName() << std::endl;
    std::cout << "Session ID: " << authly.GetSessionId() << std::endl;
    std::cout << "Application Hash: " << authly.GetCurrentApplicationHash() << std::endl;
    std::cout << "Initialized: " << (authly.IsInitialized() ? "Yes" : "No") << std::endl;
    std::cout << std::string(50, '=') << std::endl;
}

void TestAllFeatures(AuthlyX& authly) {
    std::cout << "\n" << std::string(40, '-') << std::endl;
    SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_RED);
    std::cout << "COMPREHENSIVE FEATURE TEST" << std::endl;
    ResetConsoleColor();

    authly.Log("Starting comprehensive feature test");

    std::cout << "\n1. Testing Variable Operations..." << std::endl;
    std::string testKey = "test_variable";

    SYSTEMTIME st;
    GetLocalTime(&st);
    std::string testValue = "test_value_" +
        std::to_string(st.wHour) +
        std::to_string(st.wMinute) +
        std::to_string(st.wSecond);

    authly.Log("Comprehensive test - Setting variable: " + testKey);

    if (authly.SetVariable(testKey, testValue)) {
        DisplayResult("Set Variable", authly.response);

        if (authly.response.success) {
            authly.Log("Comprehensive test - Variable set successfully: " + testKey);

            authly.Log("Comprehensive test - Getting variable: " + testKey);

            std::string retrievedValue = authly.GetVariable(testKey);
            DisplayResult("Get Variable", authly.response);

            if (authly.response.success) {
                std::cout << "Retrieved value: " << retrievedValue << std::endl;
                authly.Log("Comprehensive test - Variable retrieved: " + testKey + " = " + retrievedValue);
            }
        }
    }

    std::cout << "\n2. Testing Logging..." << std::endl;
    std::string testLog = "Comprehensive test completed at " +
        std::to_string(st.wHour) + ":" +
        std::to_string(st.wMinute) + ":" +
        std::to_string(st.wSecond);

    if (authly.Log(testLog)) {
        DisplayResult("Send Log", authly.response);
    }

    std::cout << "\n3. Final User Information:" << std::endl;
    DisplayUserInfo(authly.userData);

    authly.Log("Comprehensive feature test completed successfully");
}

void TestChatSystem(AuthlyX& authly) {
    std::cout << "\n" << std::string(40, '-') << std::endl;
    SetConsoleColor(FOREGROUND_BLUE);
    std::cout << "CHAT SYSTEM" << std::endl;
    ResetConsoleColor();

    std::cout << "1. Get Chats (View Messages)" << std::endl;
    std::cout << "2. Send Chat Message" << std::endl;
    std::cout << "Choose operation: ";

    std::string choice;
    std::getline(std::cin, choice);

    if (choice == "1") {
        std::cout << "Enter Channel Name (leave empty for default): ";
        std::string channelName;
        std::getline(std::cin, channelName);

        if (channelName.empty()) {
            channelName = authly.GetAppName();
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN);
            std::cout << "Using default channel: " << channelName << std::endl;
            ResetConsoleColor();
        }

        std::cout << "\nFetching messages..." << std::endl;
        std::string result = authly.GetChats(channelName);

        if (authly.response.success) {
            if (authly.chatMessages.count > 0) {
                SetConsoleColor(FOREGROUND_GREEN);
                std::cout << "\nRetrieved " << authly.chatMessages.count << " message(s) from channel '" << channelName << "':" << std::endl;
                ResetConsoleColor();
                std::cout << std::string(50, '=') << std::endl;

                for (const auto& msg : authly.chatMessages.messages) {
                    std::string timeStr = msg.createdAt.empty() ? "N/A" : msg.createdAt.substr(0, 19);
                    std::cout << "[" << timeStr << "] " << msg.username << ": " << msg.message << std::endl;
                }
                std::cout << std::string(50, '=') << std::endl;
            }
            else {
                SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN);
                std::cout << "No messages found in channel '" << channelName << "'" << std::endl;
                ResetConsoleColor();
            }
        }
        else {
            DisplayResult("Get Chats", authly.response);
        }
    }
    else if (choice == "2") {
        std::cout << "Enter Channel Name (leave empty for default): ";
        std::string channelName;
        std::getline(std::cin, channelName);

        std::cout << "Enter Message: ";
        std::string message;
        std::getline(std::cin, message);

        if (message.empty()) {
            SetConsoleColor(FOREGROUND_RED);
            std::cout << "Message cannot be empty." << std::endl;
            ResetConsoleColor();
            return;
        }

        if (channelName.empty()) {
            channelName = authly.GetAppName();
            SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN);
            std::cout << "Using default channel: " << channelName << std::endl;
            ResetConsoleColor();
        }

        std::cout << "\nSending message..." << std::endl;
        authly.SendChat(message, channelName);

        DisplayResult("Send Chat", authly.response);
    }
    else {
        SetConsoleColor(FOREGROUND_RED);
        std::cout << "Invalid choice for chat operation." << std::endl;
        ResetConsoleColor();
    }
}

void ClearUserData(AuthlyX& authly) {
    authly.userData = AuthlyX::UserData();
}

bool TestDeviceLogin(AuthlyX& authly) {
    std::cout << "\n" << std::string(40, '-') << std::endl;
    SetConsoleColor(FOREGROUND_BLUE);
    std::cout << "DEVICE LOGIN" << std::endl;
    ResetConsoleColor();

    std::cout << "1. Motherboard ID" << std::endl;
    std::cout << "2. Processor ID" << std::endl;
    std::cout << "Choose device type: ";
    std::string typeChoice;
    std::getline(std::cin, typeChoice);

    std::string deviceType = (typeChoice == "2") ? "processor" : "motherboard";

    std::cout << "Enter Device ID: ";
    std::string deviceId;
    std::getline(std::cin, deviceId);

    if (deviceId.empty()) {
        SetConsoleColor(FOREGROUND_RED);
        std::cout << "Device ID cannot be empty." << std::endl;
        ResetConsoleColor();
        return false;
    }

    std::cout << "\nAuthenticating with device..." << std::endl;
    bool success = authly.Authenticate(deviceId, "", deviceType);
    DisplayResult("Device Login", authly.response);
    return success;
}

int main() {
    SetConsoleTitleA("AuthlyX");

    SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_GREEN);
    std::cout << "==============================================" << std::endl;
    std::cout << "              AUTHLYX C++ EXAMPLE             " << std::endl;
    std::cout << "==============================================" << std::endl;
    ResetConsoleColor();

    std::cout << "\nInitializing AuthlyX connection..." << std::endl;

    AuthlyX AuthlyXApp(
        "",
        "",
        "",
        ""
    );

    /*
    Optional:
    - Set debug to false to disable SDK logs.
    - Set api to your custom domain, for example: https://example.com/api/v2
    */

    if (!AuthlyXApp.Init()) {
        SetConsoleColor(FOREGROUND_RED);
        std::cout << "Connection Failed: " << AuthlyXApp.response.message << std::endl;
        ResetConsoleColor();
        std::cout << "Press any key to exit...";
        std::cin.get();
        return 1;
    }
    
    SetConsoleColor(FOREGROUND_GREEN);
    std::cout << "[OK] Connected Successfully!" << std::endl;
    ResetConsoleColor();

    AuthlyXApp.Log("C++ Application started successfully");

    bool running = true;
    bool loggedIn = false;

    while (running) {
        if (!loggedIn) {
            ShowLoginMenu();
            std::string choice;
            std::getline(std::cin, choice);

            if (choice == "1") {
                loggedIn = TestLogin(AuthlyXApp);
            }
            else if (choice == "2") {
                loggedIn = TestRegister(AuthlyXApp);
            }
            else if (choice == "3") {
                loggedIn = TestLicenseLogin(AuthlyXApp);
            }
            else if (choice == "4") {
                loggedIn = TestDeviceLogin(AuthlyXApp);
            }
            else if (choice == "0") {
                running = false;
                AuthlyXApp.Log("C++ Application exiting");
                std::cout << "Thank you for using AuthlyX!" << std::endl;
            }
            else {
                SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN);
                std::cout << "Invalid choice. Please try again." << std::endl;
                ResetConsoleColor();
            }
        }
        else {
            ShowMainMenu();
            std::string choice;
            std::getline(std::cin, choice);

            if (choice == "1") {
                TestVariables(AuthlyXApp);
            }
            else if (choice == "2") {
                std::cout << "\n" << std::string(40, '-') << std::endl;
                SetConsoleColor(FOREGROUND_BLUE);
                std::cout << "USER INFORMATION" << std::endl;
                ResetConsoleColor();
                DisplayUserInfo(AuthlyXApp.userData);
            }
            else if (choice == "3") {
                TestLogMessage(AuthlyXApp);
            }
            else if (choice == "4") {
                TestAllFeatures(AuthlyXApp);
            }
            else if (choice == "5") {
                ShowApplicationInfo(AuthlyXApp);
            }
            else if (choice == "6") {
                TestChatSystem(AuthlyXApp);
            }
            else if (choice == "9") {
                loggedIn = false;
                ClearUserData(AuthlyXApp);
                AuthlyXApp.Log("User logged out");
                SetConsoleColor(FOREGROUND_RED);
                std::cout << "Logged out successfully. Returning to login menu." << std::endl;
                ResetConsoleColor();
            }
            else if (choice == "0") {
                running = false;
                AuthlyXApp.Log("C++ Application exiting");
                std::cout << "Thank you for using AuthlyX!" << std::endl;
            }
            else {
                SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN);
                std::cout << "Invalid choice. Please try again." << std::endl;
                ResetConsoleColor();
            }
        }

        if (running) {
            std::cout << "\nPress any key to continue...";
            std::cin.get();
            system("cls");

            SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_GREEN);
            if (loggedIn) {
                const std::string displayName = AuthlyXApp.userData.username.empty()
                    ? AuthlyXApp.userData.licenseKey.substr(0, 8) + "..."
                    : AuthlyXApp.userData.username;
                const size_t paddingWidth = displayName.length() >= 25 ? 0 : 25 - displayName.length();

                std::cout << "==============================================" << std::endl;
                std::cout << "             AUTHLYX - MAIN MENU              " << std::endl;
                std::cout << "           Welcome, " << displayName;
                for (size_t i = 0; i < paddingWidth; ++i) std::cout << " ";
                std::cout << std::endl;
                std::cout << "==============================================" << std::endl;
            }
            else {
                std::cout << "==============================================" << std::endl;
                std::cout << "             AUTHLYX C++ EXAMPLE              " << std::endl;
                std::cout << "==============================================" << std::endl;
            }
            ResetConsoleColor();
        }
    }

    return 0;
}


