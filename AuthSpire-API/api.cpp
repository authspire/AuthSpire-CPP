#include "api.h"
#include <iostream>
#include <curl/curl.h> // INSTALLATION REQUIRED
#include <string>
#include <map>
#include <random>
#include <vector>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>
#include "cryptlib.h"
#include "hex.h"
#include "filters.h"
#include "modes.h"
#include "aes.h"
#include "base64.h"
#include "sha.h"
#include "rsa.h"
#include "osrng.h"
#include <nlohmann/json.hpp>

#include <windows.h>


using namespace CryptoPP;


namespace authSpire {
    
    RSA::PublicKey pubkey;
    std::string key;
    std::string iv;
    std::string endpoint = "https://api.authspire.com/v1"; 

    std::string randomKey(int length) {
        static const std::string alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        std::random_device rd;
        std::mt19937 engine(rd());
        std::uniform_int_distribution<> dist(0, alphabet.length() - 1);
        std::string key = "";
        for (int i = 0; i < length; i++) {
            int randomCharacterPosition = dist(engine);
            key += alphabet[randomCharacterPosition];
        }
        return key;
    }

    bool StringEmpty(std::string check)
    {
        return check.empty();
    }

    void Error(const std::string& message) {
        MessageBoxA(NULL, message.c_str(), "", MB_OK | MB_ICONWARNING);
    }

    constexpr char kBase64Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::vector<unsigned char> getBytes(const std::string& str) {
        std::vector<unsigned char> result(str.size());
        std::copy(str.begin(), str.end(), result.begin());
        return result;
    }

    std::string base64_encode(const std::string& str) {
        std::vector<unsigned char> bytes = getBytes(str);
        std::string result;
        result.reserve(((bytes.size() + 2) / 3) * 4);

        for (size_t i = 0; i < bytes.size(); i += 3) {
            unsigned char b1 = bytes[i];
            unsigned char b2 = (i + 1 < bytes.size()) ? bytes[i + 1] : 0;
            unsigned char b3 = (i + 2 < bytes.size()) ? bytes[i + 2] : 0;

            result.push_back(kBase64Chars[b1 >> 2]);
            result.push_back(kBase64Chars[((b1 & 0x03) << 4) | (b2 >> 4)]);
            result.push_back((i + 1 < bytes.size()) ? kBase64Chars[((b2 & 0x0f) << 2) | (b3 >> 6)] : '=');
            result.push_back((i + 2 < bytes.size()) ? kBase64Chars[b3 & 0x3f] : '=');
        }

        return result;
    }

    size_t write_data(char* ptr, size_t size, size_t nmemb, void* userdata)
    {
        std::stringstream* ss = (std::stringstream*)userdata;
        size_t count = size * nmemb;
        ss->write(ptr, count);
        return count;
    }

    std::string post(const std::string& url, const std::map<std::string, std::string>& params)
    {
        CURL* curl = curl_easy_init();
        if (!curl)
            return "";

        std::stringstream response_stream;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_stream);
        curl_easy_setopt(curl, CURLOPT_POST, 1);

        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        std::string post_data;
        for (const auto& p : params)
        {
            post_data += curl_easy_escape(curl, p.first.c_str(), p.first.length());
            post_data += '=';
            post_data += curl_easy_escape(curl, p.second.c_str(), p.second.length());
            post_data += '&';
        }
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, post_data.length());

        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK)
            return "";

        return response_stream.str();
    }

    std::vector<byte> PKCS7Padding(const std::vector<byte>& input, const size_t blockSize) {
        std::vector<byte> result(input);
        const size_t paddingLength = blockSize - (input.size() % blockSize);
        result.insert(result.end(), paddingLength, paddingLength);
        return result;
    }

    std::vector<byte> PKCS7UnPadding(const  std::vector<byte>& input) {
        std::vector<byte> result(input);
        const size_t paddingLength = result.back();
        if (paddingLength <= result.size()) {
            result.erase(result.end() - paddingLength, result.end());
        }
        return result;
    }

    std::string aes_encrypt(std::string plaintext, std::string key, std::string iv) {
        std::vector<byte> bKey(key.begin(), key.end());
        std::vector<byte> bIV(iv.begin(), iv.end());
        std::vector<byte> bPlainText(plaintext.begin(), plaintext.end());

        AES::Encryption aesEncryption(bKey.data(), bKey.size());
        CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, bIV.data());

        bPlainText = PKCS7Padding(bPlainText, aesEncryption.BlockSize());
        std::vector<byte> cipherText(bPlainText.size());

        cbcEncryption.ProcessData(cipherText.data(), bPlainText.data(), bPlainText.size());

        std::string encoded;
        StringSource(cipherText.data(), cipherText.size(), true, new Base64Encoder(new StringSink(encoded)));

        return encoded;
    }

    std::string aes_decrypt(std::string encrypted, std::string key, std::string iv) {
        std::vector<byte> bKey(key.begin(), key.end());
        std::vector<byte> bIV(iv.begin(), iv.end());
        std::string decoded;
        StringSource(encrypted, true, new Base64Decoder(new StringSink(decoded)));
        std::vector<byte> bCipherText(decoded.begin(), decoded.end());

        AES::Decryption aesDecryption(bKey.data(), bKey.size());
        CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, bIV.data());

        std::vector<byte> decryptedText(bCipherText.size());
        cbcDecryption.ProcessData(decryptedText.data(), bCipherText.data(), bCipherText.size());

        decryptedText = PKCS7UnPadding(decryptedText);
        return std::string(decryptedText.begin(), decryptedText.end());
    }

    std::string GetCurrentFile() {
        wchar_t path[MAX_PATH];
        int result = GetModuleFileNameW(NULL, path, MAX_PATH);
        if (result == 0) {
            return "";
        }
        std::wstring wstr(path);
        std::string str(wstr.begin(), wstr.end());
        return str;
    }

    std::string SHA256Checksum(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Could not open file: " + filePath);
        }

        CryptoPP::SHA256 hash;
        CryptoPP::byte buffer[1024];
        while (file) {
            file.read(reinterpret_cast<char*>(buffer), 1024);
            hash.Update(buffer, file.gcount());
        }

        CryptoPP::byte digest[CryptoPP::SHA256::DIGESTSIZE];
        hash.Final(digest);

        std::string hexString;
        CryptoPP::HexEncoder encoder;
        encoder.Attach(new CryptoPP::StringSink(hexString));
        encoder.Put(digest, sizeof(digest));
        encoder.MessageEnd();

        return hexString;
    }

    std::string RSAEncryptWithPublicKey(const std::string& plaintext, CryptoPP::RSA::PublicKey publicKey) {
        CryptoPP::AutoSeededRandomPool rng;
        std::string ciphertext;
        CryptoPP::RSAES_PKCS1v15_Encryptor enc(publicKey);
        CryptoPP::StringSource ss1(plaintext, true,
            new CryptoPP::PK_EncryptorFilter(rng, enc,
                new CryptoPP::Base64Encoder(
                    new CryptoPP::StringSink(ciphertext)
                )
            )
        );
        return ciphertext;
    }


    void LoadPublicKey(std::string key) {
        std::string pubkey_decoded;
        Base64Decoder decoder;
        decoder.Attach(new StringSink(pubkey_decoded));
        decoder.Put((const byte*)key.data(), key.size());
        decoder.MessageEnd();

        ArraySource pubkey_array(reinterpret_cast<const byte*>(pubkey_decoded.data()), pubkey_decoded.size(), true);
        pubkey.BERDecode(pubkey_array);
    }
    

    std::string getHwidCore(std::string type) { // from https://github.com/fahrettinenes/hwid
        char buffer[128];
        std::string result = "";
        std::string cmd;

        cmd += "wmic ";
        cmd += type;
        cmd += " get serialnumber ";
        cmd += "| find /v \"SerialNumber|\" | findstr /v \"^$\"";

        FILE* pipe = _popen(cmd.c_str(), "r");
        if (!pipe) throw std::runtime_error("popen() failed!");
        try {
            while (fgets(buffer, sizeof buffer, pipe) != NULL) {
                if (isdigit(buffer[0]))
                    result += buffer;
            }
        }
        catch (...) {
            _pclose(pipe);
            throw;
        }
        _pclose(pipe);

        return result;
    }

    std::string GetHWID(std::string type) { // from https://github.com/fahrettinenes/hwid
        std::string data;

        for (size_t i = 0; i < getHwidCore(type).size(); i++)
        {
            if (isdigit(getHwidCore(type)[i]))
            {
                data += getHwidCore(type)[i];
            }
        }

        return data;
    }

    void api::Init()
    {
        LoadPublicKey(publicKey);

        key = randomKey(32);
        iv = randomKey(16);

        std::map<std::string, std::string> params;
        params["action"] = base64_encode("app_info");
        params["userid"] = base64_encode(userid);
        params["app_name"] = base64_encode(name);
        params["secret"] = aes_encrypt(secret, key, iv);
        params["version"] = aes_encrypt(currentVersion, key, iv);
        params["hash"] = aes_encrypt(SHA256Checksum(GetCurrentFile()), key, iv);
        params["key"] = RSAEncryptWithPublicKey(key, pubkey);
        params["iv"] = RSAEncryptWithPublicKey(iv, pubkey);
       
        std::string result = post(endpoint, params);
        nlohmann::json response = nlohmann::json::parse(result);

        if (response["status"] == "success") {
            application.application_status = aes_decrypt(response["application_status"], key, iv);
            application.application_hash = aes_decrypt(response["application_hash"], key, iv);
            application.application_name = aes_decrypt(response["application_name"], key, iv);
            application.application_version = aes_decrypt(response["application_version"], key, iv);
            application.update_url = aes_decrypt(response["update_url"], key, iv);
            application.user_count = aes_decrypt(response["user_count"], key, iv);

            initialized = true;
        }
        else if (response["status"] == "update_available") {
            application.update_url = aes_decrypt(response["update_url"], key, iv);
            application.application_version = aes_decrypt(response["application_version"], key, iv);

            api::UpdateApplication(application.update_url, application.application_version);
            return;
        }
        else if (response["status"] == "invalid_hash") {
            Error(ApplicationManipulated);
            return;
        }
        else if (response["status"] == "invalid_app") {
            Error(InvalidApplication);
            return;
        }
        else if (response["status"] == "paused") {
            Error(ApplicationPaused);
            return;
        }
        else if (response["status"] == "locked") {
            Error(ApplicationDisabled);
            return;
        }

    }

    bool api::Login(std::string username, std::string password) {
        if (!initialized) {
            Error(NotInitialized);
            return false;
        }

        if (StringEmpty(username) || StringEmpty(password)) {
            Error(InvalidLoginInfo);
            return false;
        }

        key = randomKey(32);
        iv = randomKey(16);

        std::map<std::string, std::string> params;
        params["action"] = base64_encode("login");
        params["userid"] = base64_encode(userid);
        params["app_name"] = base64_encode(name);
        params["secret"] = aes_encrypt(secret, key, iv);
        params["username"] = aes_encrypt(username, key, iv);
        params["password"] = aes_encrypt(password, key, iv);
        params["hwid"] = aes_encrypt(GetHWID("baseboard"), key, iv);
        params["key"] = RSAEncryptWithPublicKey(key, pubkey);
        params["iv"] = RSAEncryptWithPublicKey(iv, pubkey);

        std::string result = post(endpoint, params);
        nlohmann::json response = nlohmann::json::parse(result);

        if (response["status"] == "ok") {

            user.username = aes_decrypt(response["username"], key, iv);
            user.email = aes_decrypt(response["email"], key, iv);
            user.ip = aes_decrypt(response["ip"], key, iv);
            user.expires = aes_decrypt(response["expires"], key, iv);
            user.hwid = aes_decrypt(response["hwid"], key, iv);
            user.last_login = aes_decrypt(response["last_login"], key, iv);
            user.created_at = aes_decrypt(response["created_at"], key, iv);
            user.variable = aes_decrypt(response["variable"], key, iv);
            user.level = aes_decrypt(response["level"], key, iv);

            std::string app_variables = aes_decrypt(response["app_variables"], key, iv);
            std::stringstream ss(app_variables);
            std::string item;
            while (std::getline(ss, item, ';'))
            {
                std::string key, value;
                std::stringstream pair(item);
                std::getline(pair, key, ':');
                std::getline(pair, value, ':');
                Variables[key] = value;
            }

            return true;
        }
        else if (response["status"] == "invalid_user") {
            Error(InvalidUserCredentials);
            return false;
        }
        else if (response["status"] == "invalid_details") {
            Error(InvalidUserCredentials);
            return false;
        }
        else if (response["status"] == "license_expired") {
            Error(UserLicenseExpired);
            return false;
        }
        else if (response["status"] == "invalid_hwid") {
            Error(UserLicenseTaken);
            return false;
        }
        else if (response["status"] == "banned") {
            Error(UserBanned);
            return false;
        }
        else if (response["status"] == "blacklisted") {
            Error(UserBlacklisted);
            return false;
        }
        else if (response["status"] == "vpn_blocked") {
            Error(VPNBlocked);
            return false;
        }
        else {
            return false;
        }
    }

    bool api::Register(std::string username, std::string password, std::string license, std::string email) {
        if (!initialized) {
            Error(NotInitialized);
            return false;
        }

        if (StringEmpty(username) || StringEmpty(password) || StringEmpty(license)) {
            Error(InvalidLoginInfo);
            return false;
        }

        key = randomKey(32);
        iv = randomKey(16);

        std::map<std::string, std::string> params;
        params["action"] = base64_encode("register");
        params["userid"] = base64_encode(userid);
        params["app_name"] = base64_encode(name);
        params["secret"] = aes_encrypt(secret, key, iv);
        params["username"] = aes_encrypt(username, key, iv);
        params["password"] = aes_encrypt(password, key, iv);
        params["license"] = aes_encrypt(license, key, iv);
        params["email"] = aes_encrypt(email, key, iv);
        params["hwid"] = aes_encrypt(GetHWID("baseboard"), key, iv);
        params["key"] = RSAEncryptWithPublicKey(key, pubkey);
        params["iv"] = RSAEncryptWithPublicKey(iv, pubkey);

        std::string result = post(endpoint, params);
        nlohmann::json response = nlohmann::json::parse(result);

        if (response["status"] == "user_added") {
            return true;
        }
        else if (response["status"] == "user_limit_reached") {
            Error(UserLimitReached);
            return false;
        }
        else if (response["status"] == "invalid_details") {
            Error(RegisterInvalidDetails);
            return false;
        }
        else if (response["status"] == "email_taken") {
            Error(RegisterEmailTaken);
            return false;
        }
        else if (response["status"] == "invalid_license") {
            Error(RegisterInvalidLicense);
            return false;
        }
        else if (response["status"] == "user_already_exists") {
            Error(UserExists);
            return false;
        }
        else if (response["status"] == "blacklisted") {
            Error(UserBlacklisted);
            return false;
        }
        else if (response["status"] == "vpn_blocked") {
            Error(VPNBlocked);
            return false;
        }
        else {
            return false;
        }
    }

    bool api::License(std::string license) {
        if (!initialized) {
            Error(NotInitialized);
            return false;
        }

        if (StringEmpty(license)) {
            Error(InvalidLoginInfo);
            return false;
        }

        key = randomKey(32);
        iv = randomKey(16);

        std::map<std::string, std::string> params;
        params["action"] = base64_encode("license");
        params["userid"] = base64_encode(userid);
        params["app_name"] = base64_encode(name);
        params["secret"] = aes_encrypt(secret, key, iv);
        params["license"] = aes_encrypt(license, key, iv);
        params["hwid"] = aes_encrypt(GetHWID("baseboard"), key, iv);
        params["key"] = RSAEncryptWithPublicKey(key, pubkey);
        params["iv"] = RSAEncryptWithPublicKey(iv, pubkey);

        std::string result = post(endpoint, params);
        nlohmann::json response = nlohmann::json::parse(result);

        if (response["status"] == "ok") {

            user.username = aes_decrypt(response["username"], key, iv);
            user.email = aes_decrypt(response["email"], key, iv);
            user.ip = aes_decrypt(response["ip"], key, iv);
            user.expires = aes_decrypt(response["expires"], key, iv);
            user.hwid = aes_decrypt(response["hwid"], key, iv);
            user.last_login = aes_decrypt(response["last_login"], key, iv);
            user.created_at = aes_decrypt(response["created_at"], key, iv);
            user.variable = aes_decrypt(response["variable"], key, iv);
            user.level = aes_decrypt(response["level"], key, iv);

            std::string app_variables = aes_decrypt(response["app_variables"], key, iv);
            std::stringstream ss(app_variables);
            std::string item;
            while (std::getline(ss, item, ';'))
            {
                std::string key, value;
                std::stringstream pair(item);
                std::getline(pair, key, ':');
                std::getline(pair, value, ':');
                Variables[key] = value;
            }

            return true;
        }
        else if (response["status"] == "invalid_user") {
            Error(InvalidUserCredentials);
            return false;
        }
        else if (response["status"] == "user_limit_reached") {
            Error(UserLimitReached);
            return false;
        }
        else if (response["status"] == "invalid_license") {
            Error(RegisterInvalidLicense);
            return false;
        }
        else if (response["status"] == "license_expired") {
            Error(UserLicenseExpired);
            return false;
        }
        else if (response["status"] == "invalid_hwid") {
            Error(UserLicenseTaken);
            return false;
        }
        else if (response["status"] == "banned") {
            Error(UserBanned);
            return false;
        }
        else if (response["status"] == "license_taken") {
            Error(UserLicenseTaken);
            return false;
        }
        else if (response["status"] == "blacklisted") {
            Error(UserBlacklisted);
            return false;
        }
        else if (response["status"] == "vpn_blocked") {
            Error(VPNBlocked);
            return false;
        }
        else {
            return false;
        }
    }

    bool api::AddLog(std::string username, std::string action) {
        if (!initialized) {
            Error(NotInitialized);
            return false;
        }

        if (StringEmpty(username) || StringEmpty(action)) {
            Error(InvalidLoginInfo);
            return false;
        }

        key = randomKey(32);
        iv = randomKey(16);

        std::map<std::string, std::string> params;
        params["action"] = base64_encode("log");
        params["userid"] = base64_encode(userid);
        params["app_name"] = base64_encode(name);
        params["secret"] = aes_encrypt(secret, key, iv);
        params["username"] = aes_encrypt(username, key, iv);
        params["user_action"] = aes_encrypt(action, key, iv);
        params["key"] = RSAEncryptWithPublicKey(key, pubkey);
        params["iv"] = RSAEncryptWithPublicKey(iv, pubkey);

        std::string result = post(endpoint, params);
        nlohmann::json response = nlohmann::json::parse(result);

        if (response["status"] == "log_added") {
            return true;
        }
        else if (response["status"] == "failed") {
            Error(FailedToAddLog);
            return false;
        }
        else if (response["status"] == "invalid_log_info") {
            Error(InvalidLogInfo);
            return false;
        }
        else if (response["status"] == "log_limit_reached") {
            Error(LogLimitReached);
            return false;
        }
    }

    std::string api::GetVariable(std::string secret) {
        if (!initialized) {
            Error(NotInitialized);
            return "N/A";
        }

        if (StringEmpty(user.username) || StringEmpty(user.hwid)) {
            Error(NotLoggedIn);
            return "N/A";
        }

        try {
            return Variables.at(secret);
        }
        catch (const std::out_of_range&) {
            return "N/A";
        }
    }

    void api::UpdateApplication(const std::string& updateURL, const std::string& version) {
        int wide_version_length = MultiByteToWideChar(CP_UTF8, 0, version.c_str(), -1, NULL, 0);
        wchar_t* wide_version = new wchar_t[wide_version_length];
        MultiByteToWideChar(CP_UTF8, 0, version.c_str(), -1, wide_version, wide_version_length);

        wchar_t wide_message[100];
        wsprintfW(wide_message, L"%ls update available! Install it now?", wide_version);

        int wide_caption_length = MultiByteToWideChar(CP_UTF8, 0, application.application_name.c_str(), -1, NULL, 0);
        wchar_t* wide_caption = new wchar_t[wide_caption_length];
        MultiByteToWideChar(CP_UTF8, 0, application.application_name.c_str(), -1, wide_caption, wide_caption_length);

        int result = MessageBoxW(NULL, wide_message, wide_caption, MB_YESNO | MB_ICONERROR);
        if (result == IDYES) {
            try {
                int wide_update_url_length = MultiByteToWideChar(CP_UTF8, 0, application.update_url.c_str(), -1, NULL, 0);
                wchar_t* wide_update_url = new wchar_t[wide_update_url_length];
                MultiByteToWideChar(CP_UTF8, 0, application.update_url.c_str(), -1, wide_update_url, wide_update_url_length);
                ShellExecuteW(NULL, L"open", wide_update_url, NULL, NULL, SW_SHOWNORMAL);
                delete[] wide_update_url;
            }
            catch (...) {
            }
            std::exit(0);
        }
        else {
            std::exit(0);
        }

        delete[] wide_version;
        delete[] wide_caption;
    }

}
