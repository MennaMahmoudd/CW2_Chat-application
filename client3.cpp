#include <iostream>
#include <thread>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <cctype>
#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

const int SHIFT = 3;
bool accessGranted = false;

using namespace std;

// AES encryption functions
void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

// Function declarations
bool initialize();
void signUp();
void login(string& username);
void encrypt(string &text);
void decrypt(string &text);
bool checkUsernameInFile(string encryptedUsername);
bool checkPasswordInFile(string encryptedUsername, string encryptedPassword);
void saveToFile(string username, string password);
void appendToChatHistory(const string& username, const string& message);
void showChatHistory(const string& username);
void SendMsg(int s, const string& username, unsigned char *key, unsigned char *iv);
void ReceiveMsg(int s, unsigned char *key, unsigned char *iv);

bool initialize() {
    return true;
}

void encrypt(string &text) {
    for (char &c : text) {
        if (isalpha(c)) {
            char base = islower(c) ? 'a' : 'A';
            c = base + (c - base + SHIFT) % 26;
        }
    }
}

void decrypt(string &text) {
    for (char &c : text) {
        if (isalpha(c)) {
            char base = islower(c) ? 'a' : 'A';
            c = base + (c - base - SHIFT + 26) % 26;
        }
    }
}

void saveToFile(string username, string password) {
    ofstream outFile("accounts_info.txt", ios::app);
    if (outFile.is_open()) {
        outFile << "Username: " << username << ", Password: " << password << endl;
        outFile.close();
    } else {
        cout << "Unable to open file!" << endl;
    }
}

bool checkUsernameInFile(string encryptedUsername) {
    ifstream inFile("accounts_info.txt");
    if (inFile.is_open()) {
        string line;
        while (getline(inFile, line)) {
            if (line.find("Username: " + encryptedUsername) != string::npos) {
                inFile.close();
                return true;
            }
        }
        inFile.close();
    } else {
        cout << "Unable to open file!" << endl;
    }
    return false;
}

bool checkPasswordInFile(string encryptedUsername, string encryptedPassword) {
    ifstream inFile("accounts_info.txt");
    if (inFile.is_open()) {
        string line;
        while (getline(inFile, line)) {
            if (line.find("Username: " + encryptedUsername) != string::npos) {
                if (line.find("Password: " + encryptedPassword) != string::npos) {
                    inFile.close();
                    return true;
                }
            }
        }
        inFile.close();
    } else {
        cout << "Unable to open file!" << endl;
    }
    return false;
}

void signUp() {
    string choice;
    cout << "Enter your username: ";
    string username;
    cin >> username;
    encrypt(username);
    cout << "Enter your password: ";
    string password;
    cin >> password;
    encrypt(password);

    cout << "Account successfully registered!" << endl;
    saveToFile(username, password);
    login(username);
}

void login(string& username) {
    accessGranted = false;
    while (!accessGranted) {
        bool usernameCorrect = false;
        bool passwordCorrect = false;

        while (!usernameCorrect) {
            cout << "Enter your username: ";
            cin >> username;
            encrypt(username);
            if (checkUsernameInFile(username)) {
                usernameCorrect = true;
            } else {
                cout << "Username does not exist. Please try again." << endl;
            }
        }
        while (!passwordCorrect) {
            cout << "Enter your password: ";
            string password;
            cin >> password;
            encrypt(password);

            if (checkPasswordInFile(username, password)) {
                passwordCorrect = true;
            } else {
                cout << "Incorrect password. Please try again." << endl;
            }
        }

        cout << "You have access" << endl;
        accessGranted = true;
        decrypt(username);
    }
}

void appendToChatHistory(const string& username, const string& message) {
    string encryptedMessage = message;
    encrypt(encryptedMessage);

    ofstream outFile(username + "chat_history.txt", ios::app);
    if (outFile.is_open()) {
        outFile << encryptedMessage << endl;
        outFile.close();
    } else {
        cout << "Unable to open chat history file for appending." << endl;
    }
}
void showChatHistory(const string& username) {
    ifstream inFile(username + "chat_history.txt");
    if (inFile.is_open()) {
        string line;
        while (getline(inFile, line)) {
            string decryptedLine = line;
            decrypt(decryptedLine);
            size_t messagePos = decryptedLine.find(", Message: ");
            if (messagePos != string::npos) {
                string message = decryptedLine.substr(messagePos + 11);
                cout << message << endl;
            }
        }
        inFile.close();
    } else {
        cout << "No chat history found." << endl;
    }
}

void SendMsg(int s, const string& username, unsigned char *key, unsigned char *iv) {
    cout << "Enter your message / If you want to stop the application enter quit" << endl;
    string message;

    while (true) {
        getline(cin, message);

        unsigned char ciphertext[4096];
        string fullMessage = "Username: " + username + ", Message: " + message;
        int ciphertext_len = encrypt((unsigned char *)fullMessage.c_str(), fullMessage.length(), key, iv, ciphertext);

        int bytesent = send(s, ciphertext, ciphertext_len, 0);
        if (bytesent == -1) {
            cout << "Error sending message." << endl;
        } else {
            appendToChatHistory(username, fullMessage);
        }

        if (message == "quit") {
            cout << "Stopping the application." << endl;
            break;
        }
    }

    close(s);
}

void ReceiveMsg(int s, unsigned char *key, unsigned char *iv) {
    unsigned char buffer[4096];
    int recvlength;

    while (true) {
        recvlength = recv(s, buffer, sizeof(buffer), 0);
        if (recvlength <= 0) {
            cout << "Disconnected from the server." << endl;
            break;
        } else {
            unsigned char decryptedtext[4096];
            int decryptedtext_len = decrypt(buffer, recvlength, key, iv, decryptedtext);
            decryptedtext[decryptedtext_len] = '\0';

            string decryptedMessage((char*)decryptedtext);
            size_t usernamePos = decryptedMessage.find("Username: ");
            size_t messagePos = decryptedMessage.find(", Message: ");

            if (usernamePos != string::npos && messagePos != string::npos) {
                string username = decryptedMessage.substr(usernamePos + 10, messagePos - (usernamePos + 10));
                string message = decryptedMessage.substr(messagePos + 11);
                cout << "Received from " << username << ": " << message << endl;

                appendToChatHistory(username, decryptedMessage);
            }
        }
    }

    close(s);
}

int main() {
    if (!initialize()) {
        cout << "Initialization failed." << endl;
        return 1;
    }

    unsigned char key[] = "01234567890123456789012345678901";
    unsigned char iv[] = "0123456789012345";

    int s = socket(AF_INET, SOCK_STREAM, 0);

    if (s == -1) {
        cout << "Invalid socket created." << endl;
        return 1;
    }

    int port;
    cout << "Enter the port number: ";
    cin >> port;
    string serveraddr = "127.0.0.1";
    sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, serveraddr.c_str(), &server.sin_addr);

    if (connect(s, reinterpret_cast<sockaddr*>(&server), sizeof(server)) == -1) {
        cout << "Not able to connect to server." << endl;
        perror("connect");
        close(s);
        return 1;
    }

    cout << "Successfully connected to server." << endl;

    int choice;
    cout << "Choose an option:" << endl;
    cout << "1. Sign Up" << endl;
    cout << "2. Log In" << endl;
    cout << "3. Show Chat History" << endl;
    cout << "Enter your choice: ";
    cin >> choice;
    cin.ignore();
    
    string username;

    switch (choice) {
        case 1:
            signUp();
            break;
        case 2:
            login(username);
            break;
        case 3:
            login(username);
            showChatHistory(username);
            close(s);
            return 0;
        default:
            cout << "Invalid choice." << endl;
            close(s);
            return 1;
    }

    thread senderThread(SendMsg, s, username, key, iv);
    thread receiverThread(ReceiveMsg, s, key, iv);

    senderThread.join();
    receiverThread.join();

    return 0;
}
