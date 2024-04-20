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

class SecureChatSystem {
private:
    bool accessGranted;
    unsigned char key[32];
    unsigned char iv[16];

    // AES encryption functions
    void handleErrors() {
        ERR_print_errors_fp(stderr);
        abort();
    }

    int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
        EVP_CIPHER_CTX *ctx;
        int len;
        int ciphertext_len;

        /* Create and initialise the context */
        if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

        /* Initialise the encryption operation. */
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();

        /* Provide the message to be encrypted, and obtain the encrypted output.
         * EVP_EncryptUpdate can be called multiple times if necessary
         */
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
            handleErrors();
        ciphertext_len = len;

        /* Finalise the encryption. */
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
        ciphertext_len += len;

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        return ciphertext_len;
    }

    // AES decryption functions (not used in this example)
    int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
        EVP_CIPHER_CTX *ctx;
        int len;
        int plaintext_len;

        /* Create and initialise the context */
        if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

        /* Initialise the decryption operation. */
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();

        /* Provide the message to be decrypted, and obtain the plaintext output.
         * EVP_DecryptUpdate can be called multiple times if necessary
         */
        if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
            handleErrors();
        plaintext_len = len;

        /* Finalise the decryption. */
        if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
        plaintext_len += len;

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

        return plaintext_len;
    }

    // Function declarations
    bool initialize();
    void signUp();
    void login(std::string &username); // Forward declaration for login
    void encrypt(std::string &text);
    void decrypt(std::string &text);
    bool checkUsernameInFile(std::string encryptedUsername);
    bool checkPasswordInFile(std::string encryptedUsername, std::string encryptedPassword);
    void saveToFile(std::string username, std::string password);
    void SendMsg(int s, const std::string &username, unsigned char *key, unsigned char *iv);
    void ReceiveMsg(int s, unsigned char *key, unsigned char *iv);

public:
    SecureChatSystem() : accessGranted(false) {
        // Initialize AES key and IV
        std::strcpy(reinterpret_cast<char*>(key), "01234567890123456789012345678901");
        std::strcpy(reinterpret_cast<char*>(iv), "0123456789012345");
    }

    // Main function
    void startChatSystem();
};

bool SecureChatSystem::initialize() {
    return true;
}

// Function to encrypt a string using Caesar cipher
void SecureChatSystem::encrypt(std::string &text) {
    const int SHIFT = 3;
    for (char &c : text) {
        if (std::isalpha(c)) {
            char base = std::islower(c) ? 'a' : 'A';
            c = base + (c - base + SHIFT) % 26;
        }
    }
}

// Function to decrypt a string
void SecureChatSystem::decrypt(std::string &text) {
    const int SHIFT = 3;
    for (char &c : text) {
        if (std::isalpha(c)) {
            char base = std::islower(c) ? 'a' : 'A';
            c = base + (c - base - SHIFT + 26) % 26; // Decrypt by shifting backwards
        }
    }
}

// Function to save the account information to a file
void SecureChatSystem::saveToFile(std::string username, std::string password) {
    // Open file in append mode
    std::ofstream outFile("accounts_info.txt", std::ios::app);
    // Check if the file is successfully opened
    if (outFile.is_open()) {
        // Write username and password to the file
        outFile << "Username: " << username << ", Password: " << password << std::endl;
        // Close the file
        outFile.close();
    } else {
        std::cout << "Unable to open file!" << std::endl;
    }
}

// Helper function to check if encrypted username exists in file
bool SecureChatSystem::checkUsernameInFile(std::string encryptedUsername) {
    // Open the accounts_info.txt file
    std::ifstream inFile("accounts_info.txt");
    // Check if the file is successfully opened
    if (inFile.is_open()) {
        // Variable to store each line of the file
        std::string line;
        // Loop through each line of the file
        while (std::getline(inFile, line)) {
            // Check if the line contains the encrypted username
            if (line.find("Username: " + encryptedUsername) != std::string::npos) {
                // Close the file
                inFile.close();
                return true; // Return true if the encrypted username is found
            }
        }
        // Close the file
        inFile.close();
    } else {
        // Print an error message if the file cannot be opened
        std::cout << "Unable to open file!" << std::endl;
    }
    // Return false if the encrypted username is not found or if there's an error opening the file
    return false;
}

// Helper function to check if encrypted username and password match in file
bool SecureChatSystem::checkPasswordInFile(std::string encryptedUsername, std::string encryptedPassword) {
    // Open the accounts_info.txt file
    std::ifstream inFile("accounts_info.txt");
    // Check if the file is successfully opened
    if (inFile.is_open()) {
        // Variable to store each line of the file
        std::string line;
        // Loop through each line of the file
        while (std::getline(inFile, line)) {
            // Check if the line contains the encrypted username
            if (line.find("Username: " + encryptedUsername) != std::string::npos) {
                // Found matching username, now check password
                if (line.find("Password: " + encryptedPassword) != std::string::npos) { // Check if the line contains the encrypted password
                    inFile.close();
                    return true;
                }
            }
        }
        inFile.close();
    } else {
        std::cout << "Unable to open file!" << std::endl;
    }
    return false;
}

// Function to sign up
void SecureChatSystem::signUp() {
    std::string choice;
    std::cout << "Enter your username: ";
    std::string username;
    std::cin >> username;
    encrypt(username);
    std::cout << "Enter your password: ";
    std::string password;
    std::cin >> password;
    encrypt(password);

    std::cout << "Account successfully registered!" << std::endl;
    saveToFile(username, password);
    login(username);
}

void SecureChatSystem::login(std::string &username) {
    accessGranted = false;
    while (!accessGranted) {
        bool usernameCorrect = false;
        bool passwordCorrect = false;

        while (!usernameCorrect) {
            std::cout << "Enter your username: ";
            std::cin >> username;
            encrypt(username);
            if (checkUsernameInFile(username)) {
                usernameCorrect = true;
            } else {
                std::cout << "Username does not exist. Please try again." << std::endl;
            }
        }
        while (!passwordCorrect) {
            std::cout << "Enter your password: ";
            std::string password;
            std::cin >> password;
            encrypt(password);

            // Check if encrypted username and password match in file
            if (checkPasswordInFile(username, password)) {
                passwordCorrect = true;
            } else {
                std::cout << "Incorrect password. Please try again." << std::endl;
            }
        }

        std::cout << "You have access" << std::endl;
        accessGranted = true;
        decrypt(username);
    }
}

void SecureChatSystem::SendMsg(int s, const std::string &username, unsigned char *key, unsigned char *iv) {
    std::cout << "Enter your message / If you want to stop the application enter quit" << std::endl;
    std::string message;

    while (true) {
        std::getline(std::cin, message);

        // Encrypt the message before sending
        unsigned char ciphertext[4096];
        std::string fullMessage = "Username: " + username + ", Message: " + message;
        int ciphertext_len = encrypt((unsigned char *)fullMessage.c_str(), fullMessage.length(), key, iv, ciphertext);

        int bytesent = send(s, ciphertext, ciphertext_len, 0);
        if (bytesent == -1) {
            std::cout << "Error sending message." << std::endl;
        }

        if (message == "quit") {
            std::cout << "Stopping the application." << std::endl;
            break;
        }
    }

    close(s);
}

void SecureChatSystem::ReceiveMsg(int s, unsigned char *key, unsigned char *iv) {
    unsigned char buffer[4096];
    int recvlength;

    while (true) {
        recvlength = recv(s, buffer, sizeof(buffer), 0);
        if (recvlength <= 0) {
            std::cout << "Disconnected from the server." << std::endl;
            break;
        } else {
            // Decrypt the received message
            unsigned char decryptedtext[4096];
            int decryptedtext_len = decrypt(buffer, recvlength, key, iv, decryptedtext);
            decryptedtext[decryptedtext_len] = '\0';

            // Extract username and message from the decrypted text
            std::string decryptedMessage((char*)decryptedtext);
            size_t usernamePos = decryptedMessage.find("Username: ");
            size_t messagePos = decryptedMessage.find(", Message: ");

            if (usernamePos != std::string::npos && messagePos != std::string::npos) {
                std::string username = decryptedMessage.substr(usernamePos + 10, messagePos - (usernamePos + 10));
                std::string message = decryptedMessage.substr(messagePos + 11);
                std::cout << "Received from " << username << ": " << message << std::endl;
            }
        }
    }

    close(s);
}

// Main function
void SecureChatSystem::startChatSystem() {
    if (!initialize()) {
        std::cout << "Initialization failed." << std::endl;
        return;
    }

    int s = socket(AF_INET, SOCK_STREAM, 0);

    if (s == -1) {
        std::cout << "Invalid socket created." << std::endl;
        return;
    }

    int port;
    std::cout << "Enter the port number: ";
    std::cin >> port;
    std::string serveraddr = "127.0.0.1";
    sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, serveraddr.c_str(), &server.sin_addr);

    if (connect(s, reinterpret_cast<sockaddr*>(&server), sizeof(server)) == -1) {
        std::cout << "Not able to connect to server." << std::endl;
        perror("connect");
        close(s);
        return;
    }

    std::cout << "Successfully connected to server." << std::endl;

    int choice;
    std::cout << "Choose an option:" << std::endl;
    std::cout << "1. Sign Up" << std::endl;
    std::cout << "2. Log In" << std::endl;
    std::cout << "Enter your choice: ";
    std::cin >> choice;
    std::cin.ignore();

    std::string username;

    switch (choice) {
        case 1:
            signUp();
            break;
        case 2:
            login(username); // Pass username to login function
            break;
        default:
            std::cout << "Invalid choice." << std::endl;
            close(s);
            return;
    }

    // Now, pass the socket as an argument to the thread functions correctly
    // Assuming username is known after login
    std::thread senderThread(&SecureChatSystem::SendMsg, this, s, username, key, iv);
    std::thread receiverThread(&SecureChatSystem::ReceiveMsg, this, s, key, iv);

    senderThread.join();
    receiverThread.join();
}

int main() {
    SecureChatSystem chatSystem;
    chatSystem.startChatSystem();
    return 0;
}
