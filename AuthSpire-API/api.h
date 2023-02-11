#ifndef API_H
#define API_H

#include <string>
#include <iostream>
#include "rsa.h"
#include "base64.h"
#include <nlohmann/json.hpp>


namespace authSpire {
    class api
    {
        public:
            const std::string ServerOffline = "Server is currently not responding, try again later!";
            const std::string RegisterInvalidLicense = "The license you entered is invalid or already taken!";
            const std::string RegisterInvalidDetails = "You entered an invalid username or email!";
            const std::string RegisterUsernameTaken = "This username is already taken!";
            const std::string RegisterEmailTaken = "This email is already taken!";
            const std::string UserExists = "A user with this username already exists!";
            const std::string UserLicenseTaken = "This license is already binded to another machine!";
            const std::string UserLicenseExpired = "Your license has expired!";
            const std::string UserBanned = "You have been banned for violating the TOS!";
            const std::string UserBlacklisted = "Your IP/HWID has been blacklisted!";
            const std::string VPNBlocked = "You cannot use a vpn with our service! Please disable it.";
            const std::string InvalidUser = "User doesn't exist!";
            const std::string InvalidUserCredentials = "Username or password doesn't match!";
            const std::string InvalidLoginInfo = "Invalid login information!";
            const std::string InvalidLogInfo = "Invalid log information!";
            const std::string LogLimitReached = "You can only add a maximum of 50 logs as a free user, upgrade to premium to enjoy no log limits!";
            const std::string UserLimitReached = "You can only add a maximum of 30 users as a free user, upgrade to premium to enjoy no user limits!";
            const std::string FailedToAddLog = "Failed to add log, contact the provider!";
            const std::string InvalidApplication = "Application could not be initialized, please check your public key, userid, app name & secret.";
            const std::string ApplicationPaused = "This application is currently under construction, please try again later!";
            const std::string NotInitialized = "Please initialize your application first!";
            const std::string NotLoggedIn = "Please log into your application first!";
            const std::string ApplicationDisabled = "Application has been disabled by the provider.";
            const std::string ApplicationManipulated = "File corrupted! This program has been manipulated or cracked. This file won't work anymore.";

            struct Application {
                std::string application_status;
                std::string application_name;
                std::string user_count;
                std::string application_version;
                std::string update_url;
                std::string application_hash;
            };

            struct User {
                std::string username;
                std::string email;
                std::string ip;
                std::string expires;
                std::string hwid;
                std::string last_login;
                std::string created_at;
                std::string variable;
                std::string level;
            };

            std::map<std::string, std::string> Variables;
            Application application;
            User user;
            std::string name, userid, secret, currentVersion, publicKey;
            bool initialized;


            api(std::string name, std::string userid, std::string secret, std::string currentVersion, std::string publicKey) : name(name), userid(userid), secret(secret), currentVersion(currentVersion), publicKey(publicKey) {
                if (userid.empty() || secret.empty() || currentVersion.empty() || publicKey.empty()) {
                    std::cerr << "Invalid settings!" << std::endl;
                    exit(-1);
                }
            }

            void Init();
            bool Login(std::string username, std::string password);
            bool Register(std::string username, std::string password, std::string license, std::string email);
            bool License(std::string license);
            bool AddLog(std::string username, std::string action);
            std::string GetVariable(std::string secret);
            void UpdateApplication(const std::string& updateURL, const std::string& version);
    };
}
#endif