
<h1 align="center">
  <br>
  <a href="https://authspire.com"><img src="https://i.ibb.co/KxvFZ5B/logo.png" alt="AuthSpire" width="200"></a>
  <br>
  AuthSpire
  <br>
</h1>

<h4 align="center">A FREE and secure licensing & authentication solution<br>using hybrid encryption.</h4>

<p align="center">
  <a href="#key-features">Key Features</a> •
  <a href="#how-to-use">How To Use</a> •
  <a href="#functions">API Functions</a> •
</p>

<div align="center">
    <img src="https://media.giphy.com/media/V6v60D0r4St0xXNJqo/giphy.gif" width="450"> 
</div>


## Key Features

* License your software / application
  - Restrict access from other users and increase security
* Manage Users
  - See who uses your application, set expiry dates for your licenses & more
* Variables
  - Set custom hidden variables that are secured on our server and can not be cracked
* Blacklists
  - Block users by IP or a Unique Identifier from accessing your application
* Logging
  - Handle all logs and see what is happening inside of your application
* Hybrid Encryption System
  - Encryption combined using AES 256 (Advanced Encryption Standard) and RSA to ensure the most security

## How To Use

Create an account on the <a href="https://authspire.com/sign-up">AuthSpire</a> website.
Create your application.

Install VS 2022 or any other compiler for C++
You will require <a href="https://curl.se/download.html">Curl</a> and <a href="https://www.cryptopp.com/#download">Crypto++</a>

To Install Curl and Crypto++ to VS 2022 follow these steps for each one

<b>Curl</b><br>
Download curl zip package from <a href="https://curl.se/download.html">here</a><br>
Extract downloaded package to a folder of your choice (e.g. C:\curl\)<br>
Open Developer Command Prompt for VS 2022 (see Windows Start menu or %PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Visual Studio 2017\Visual Studio Tools\) and cd to C:\curl\winbuild\<br>
Run nmake /f Makefile.vc mode=static. This will build curl as a static library into C:\curl\builds\libcurl-vc-x86-release-static-ipv6-sspi-winssl\<br>
Create a new project in Visual Studio (e.g. a Windows Console Application)<br>
In Project Properties -> VC++ Directories -> Include Directories add C:\curl\builds\libcurl-vc-x86-release-static-ipv6-sspi-winssl\include\ <br>
In Project Properties -> VC++ Directories -> Library Directories add C:\curl\builds\libcurl-vc-x86-release-static-ipv6-sspi-winssl\lib\ there <br>
In Project Properties -> Linker -> Input -> Additional Dependencies add libcurl_a.lib, Ws2_32.lib, Crypt32.lib, Wldap32.lib and Normaliz.lib <br>
Add CURL_STATICLIB to Configuration Properties -> C/C++ -> Preprocessor -> Preprocessor Definitions. <br>

<b>Crypto++</b><br>
Download crypto++ zip package from <a href="https://www.cryptopp.com/#download">here</a><br>
Extract downloaded package to a folder of your choice (e.g. C:\cryptopp\)<br>
Open cryptest.sln in VS 2022<br>
In Project Properties -> C/C++ -> Code Generation -> Runtime Library select Multi-threaded (/MT) and set it to Release mode<br>
Build the cryptlib project<br>
In your project Properties -> Linker -> Input -> Additional Dependencies add path to cryptlib.lib (can be found where you compiled crpylib before)<br>
In your project Properties -> C/C++ -> Code Generation -> Runtime Library select Multi-threaded (/MT) so it works with the crypto++ library<br>
In your project Properties -> VC++ Directories -> Include Directories add C:\cryptopp\ if that was your installation location<br>



<br>
<br>
Name: Name of your application in the dashboard<br>
UserID: UserID found in your account page<br>
Secret: Secret of your application in the dashboard<br>
Version: Version 1.0 by default (for updates change the version accordingly)<br>
Public Key: Public Key for encryption found in the dashboard<br>
<br>


AuthSpire-API.cpp file
```cpp
// replace with your details!

authSpire::api api(
    "your app name",
    "your userid",
    "your secret",
    "1.0",
    "your public key"
);
```


## Functions

<b>Initializing your application</b>

Before using any other functions it is necessary to initialize your application with our server and retrieve all data.
This can be done by calling this method in your main index.php file.

```cpp
int main() {
    api.Init();
    return 0;
}
```

<b>Register a user</b>

To register and add a new user to your application you will first require a valid license key which you can generate in 
your authspire dashboard in your selected application.

Register a user by calling this method and validate the registration

```cpp
bool registered = api.Register(username, password, license, email);
if (registered)
{
    std::cout << "Thanks for registering!" << std::endl;
}
```

<b>Authenticate a user</b>

To login and add retrieve all user data you can call this method

```cpp
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
```

<b>Adding logs</b>

Sometimes it is necessary to have an overview of what is going on inside your application. For that you can use logs

To add a log you can call this method.

```cpp
api.AddLog(username, action);
std::cout << "Log added!" << std::endl;
```

<b>Getting Variables</b>

You can store server-sided strings. Your application can then retrieve these strings with a secret key that will be generated in your panel
when you generate your variable. This protects your strings from being decompiled or cracked.

```cpp
api.GetVariable(secret);
```

<b>Authenticate with only a license</b>

Sometimes you want to keep it simple. A user can register/login with only using a license. For this you can use this function

```cpp
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
```

## License

MIT
