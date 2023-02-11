#include <iostream>
#include <string>
#include "api.h"

authSpire::api api(
    "authspire",
    "ixwupMLC",
    "iZ2WBMvGWZNtZHm3Hntpy2pXNJ7ael3e",
    "1.0",
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx0nVH3883VloO37EECLIBGIwGrldR02lTddB5XQFWuIcV+fvjE2+pycaC/RtlY5YUK/PoO/GjwrYrJNuWb2OGPWHFmulfzLvHtGo3YjnAnLZa/Hk2JYJ0JPmyzwsSVO7uXG8gswre9QFQlFD+sUzTgYuLRn394PaoLr6Hmg8MSSgP7Pk7yNg2B8AkPdJuLiRpiGA1MJ4Y9mY9TQUAw1tsyYfZ257mCFjvek5R1dpFCMctjF22LGErzDWsbnHATSn+S/crMcDgMPOcBxkP4VT17SS8doVM46pt89GlQHnLL34v9kORPxMVcX12ox6XP74erl8FUYO8Uaju7HGT+FzFQIDAQAB"
);

void Logo()
{
    std::string logo = R"(
Yb  dP                        db              
 YbdP  .d8b. 8   8 8d8b      dPYb   88b. 88b. 
  YP   8' .8 8b d8 8P       dPwwYb  8  8 8  8 
  88   `Y8P' `Y8P8 8       dP    Yb 88P' 88P' 
                                    8    8    
)";

    std::cout << logo << std::endl;
}

int main() {
    api.Init();

    Logo();

    std::cout << "[1] Register" << std::endl;
    std::cout << "[2] Login" << std::endl;
    std::cout << "[3] License only" << std::endl;
    std::cout << "[4] Add Log" << std::endl;

    std::cout << ">> ";
    std::string option;
    std::cin >> option;
    std::cout << std::endl;

    if (option == "1")
    {
        std::cout << "Username: ";
        std::string username;
        std::cin >> username;
        std::cout << "Password: ";
        std::string password;
        std::cin >> password;
        std::cout << "License: ";
        std::string license;
        std::cin >> license;
        std::cout << "Email: ";
        std::string email;
        std::cin >> email;

        bool registered = api.Register(username, password, license, email);
        if (registered)
        {
            std::cout << "Thanks for registering!" << std::endl;
        }
    }
    else if (option == "2")
    {
        std::cout << "Username: ";
        std::string username;
        std::cin >> username;
        std::cout << "Password: ";
        std::string password;
        std::cin >> password;

        bool loggedIn = api.Login(username, password);
        if (loggedIn)
        {
            std::cout << "Welcome back " << api.user.username << std::endl;
            std::cout << std::endl;
            std::cout << api.user.email << std::endl;
            std::cout << api.user.ip << std::endl;
            std::cout << api.user.expires << std::endl;
            std::cout << api.user.hwid << std::endl;
            std::cout << api.user.last_login << std::endl;
            std::cout << api.user.created_at << std::endl;
            std::cout << api.user.variable << std::endl;
            std::cout << api.user.level << std::endl;
        }
    }
    else if (option == "3")
    {
        std::cout << "License: ";
        std::string license;
        std::cin >> license;

        if (api.License(license))
        {
            std::cout << "Welcome back " << api.user.username << std::endl;
            std::cout << std::endl;
            std::cout << api.user.email << std::endl;
            std::cout << api.user.ip << std::endl;
            std::cout << api.user.expires << std::endl;
            std::cout << api.user.hwid << std::endl;
            std::cout << api.user.last_login << std::endl;
            std::cout << api.user.created_at << std::endl;
            std::cout << api.user.variable << std::endl;
            std::cout << api.user.level << std::endl;
        }
    }
    else if (option == "4") 
    {
        std::cout << "Username: ";
        std::string username;
        std::cin >> username;
        std::cout << "Action: ";
        std::string action;
        std::cin >> action;

        api.AddLog(username, action);
        std::cout << "Log added!" << std::endl;
    }
    return 0;
}