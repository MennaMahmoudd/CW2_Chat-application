#include <iostream> // Input/output stream library
#include <thread> // Thread library
#include <fstream> // File stream library
#include <cstdlib> // Standard library definitions
#include <ctime> // Time functions
#include <cctype> // Character handling functions
#include <string> // String library
#include <cstring> // String manipulation functions
#include <arpa/inet.h> // Definitions for internet operations
#include <netinet/in.h> // Internet address family
#include <sys/socket.h> // Socket library
#include <unistd.h> // Standard symbolic constants and types
#include <openssl/conf.h> // OpenSSL configuration functions
#include <openssl/evp.h> // OpenSSL symmetric cipher functions
#include <openssl/err.h> // OpenSSL error handling functions

const int SHIFT = 3; // Caesar cipher shift value
bool accessGranted = false; // Flag to indicate if access is granted

using namespace std; // Standard namespace

// AES encryption functions
void handleErrors(); // Function to handle OpenSSL errors
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext); // Function to encrypt using AES
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext); // Function to decrypt using AES

// Function declarations
bool initialize(); // Function to initialize
void signUp(string& username); // Function to sign up
void login(string& username); // Function to login
void encrypt(string &text); // Function to encrypt text
void decrypt(string &text); // Function to decrypt text
bool checkUsernameInFile(string encryptedUsername); // Function to check if username exists in file
bool checkPasswordInFile(string encryptedUsername, string encryptedPassword); // Function to check if password matches username in file
void saveToFile(string username, string password); // Function to save username and password to file
void appendToChatHistory(const string& username, const string& message); // Function to append message to chat history
void showChatHistory(const string& username); // Function to show chat history
void SendMsg(int s, const string& username, unsigned char *key, unsigned char *iv); // Function to send message
void ReceiveMsg(int s, unsigned char *key, unsigned char *iv); // Function to receive message

// Function definitions

// Function to handle OpenSSL errors
void handleErrors() {
    ERR_print_errors_fp(stderr); // Print error messages to standard error
    abort(); // Abort program
}

// Function to encrypt using AES
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx; // Create EVP cipher context
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) // Create new EVP cipher context
        handleErrors(); // Handle errors

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) // Initialize encryption
        handleErrors(); // Handle errors

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) // Update encryption
        handleErrors(); // Handle errors
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) // Finalize encryption
        handleErrors(); // Handle errors
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx); // Free EVP cipher context

    return ciphertext_len; // Return length of ciphertext
}

// Function to decrypt using AES
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx; // Create EVP cipher context
    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) // Create new EVP cipher context
        handleErrors(); // Handle errors

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) // Initialize decryption
        handleErrors(); // Handle errors

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) // Update decryption
        handleErrors(); // Handle errors
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) // Finalize decryption
        handleErrors(); // Handle errors
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx); // Free EVP cipher context

    return plaintext_len; // Return length of plaintext
}

// Function to save username and password to file
void saveToFile(string username, string password) {
    ofstream outFile("accounts_info.txt", ios::app); // Open file in append mode
    if (outFile.is_open()) { // If file is open
        outFile << "Username: " << username << ", Password: " << password << endl; // Write username and password to file
        outFile.close(); // Close file
    } else {
        cout << "Unable to open file!" << endl; // Print error message
    }
}

// Function to check if username exists in file
bool checkUsernameInFile(string encryptedUsername) {
    ifstream inFile("accounts_info.txt"); // Open file for reading
    if (inFile.is_open()) { // If file is open
        string line;
        while (getline(inFile, line)) { // Read lines from file
            if (line.find("Username: " + encryptedUsername) != string::npos) { // If encrypted username is found in line
                inFile.close(); // Close file
                return true; // Return true
            }
        }
        inFile.close(); // Close file
    } else {
        cout << "Unable to open file!" << endl; // Print error message
    }
    return false; // Return false
}

// Function to check if password matches username in file
bool checkPasswordInFile(string encryptedUsername, string encryptedPassword) {
    ifstream inFile("accounts_info.txt"); // Open file for reading
    if (inFile.is_open()) { // If file is open
        string line;
        while (getline(inFile, line)) { // Read lines from file
            if (line.find("Username: " + encryptedUsername) != string::npos) { // If encrypted username is found in line
                if (line.find("Password: " + encryptedPassword) != string::npos) { // If encrypted password is found in line
                    inFile.close(); // Close file
                    return true; // Return true
                }
            }
        }
        inFile.close(); // Close file
    } else {
        cout << "Unable to open file!" << endl; // Print error message
    }
    return false; // Return false
}

// Function to sign up
void signUp(string& username) {
    string choice;
    cout << "Enter your username: ";
    cin >> username; // Input username
    encrypt(username); // Encrypt username
    cout << "Enter your password: ";
    string password;
    cin >> password; // Input password
    encrypt(password); // Encrypt password

    cout << "Account successfully registered!" << endl; // Print success message
    saveToFile(username, password); // Save username and password to file
    login(username); // Login
}

// Function to login
void login(string& username) {
    accessGranted = false; // Reset access flag
    while (!accessGranted) { // While access is not granted
        bool usernameCorrect = false;
        bool passwordCorrect = false;

        while (!usernameCorrect) { // While username is not correct
            cout << "Enter your username: ";
            cin >> username; // Input username
            encrypt(username); // Encrypt username
            if (checkUsernameInFile(username)) { // If username exists
                usernameCorrect = true; // Set username correct
            } else {
                cout << "Username does not exist. Please try again." << endl; // Print error message
            }
        }
        while (!passwordCorrect) { // While password is not correct
            cout << "Enter your password: ";
            string password;
            cin >> password; // Input password
            encrypt(password); // Encrypt password

            if (checkPasswordInFile(username, password)) { // If password matches username
                passwordCorrect = true; // Set password correct
            } else {
                cout << "Incorrect password. Please try again." << endl; // Print error message
            }
        }

        cout << "You have access" << endl; // Print success message
        accessGranted = true; // Set access granted
        decrypt(username); // Decrypt username
    }
}

// Function to append message to chat history
void appendToChatHistory(const string& username, const string& message) {
    string encryptedMessage = message;
    encrypt(encryptedMessage); // Encrypt message

    ofstream outFile(username + "chat_history.txt", ios::app); // Open chat history file for appending
    if (outFile.is_open()) { // If file is open
        outFile << encryptedMessage << endl; // Write encrypted message to file
        outFile.close(); // Close file
    } else {
        cout << "Unable to open chat history file for appending." << endl; // Print error message
    }
}

// Function to show chat history
void showChatHistory(const string& username) {
    ifstream inFile(username + "chat_history.txt"); // Open chat history file for reading
    if (inFile.is_open()) { // If file is open
        string line;
        while (getline(inFile, line)) { // Read lines from file
            string decryptedLine = line;
            decrypt(decryptedLine); // Decrypt line
            size_t messagePos = decryptedLine.find(", Message: "); // Find position of message
            if (messagePos != string::npos) { // If message position is found
                string message = decryptedLine.substr(messagePos + 11); // Extract message
                cout << message << endl; // Print message
            }
        }
        inFile.close(); // Close file
    } else {
        cout << "No chat history found." << endl; // Print error message
    }
}

// Function to send message
void SendMsg(int s, const string& username, unsigned char *key, unsigned char *iv) {
    cout << "Enter your message / If you want to stop the application enter quit" << endl;
    string message;

    while (true) {
        getline(cin, message); // Input message

        unsigned char ciphertext[4096];
        string fullMessage = "Username: " + username + ", Message: " + message; // Construct full message
        int ciphertext_len = encrypt((unsigned char *)fullMessage.c_str(), fullMessage.length(), key, iv, ciphertext); // Encrypt full message

        int bytesent = send(s, ciphertext, ciphertext_len, 0); // Send encrypted message
        if (bytesent == -1) {
            cout << "Error sending message." << endl; // Print error message
        } else {
            appendToChatHistory(username, fullMessage); // Append message to chat history
        }

        if (message == "quit") { // If message is quit
            string disconnectMessage = "Username: " + username + ", Message: " + "quit"; // Construct disconnect message
            int disconnect_len = encrypt((unsigned char *)disconnectMessage.c_str(), disconnectMessage.length(), key, iv, ciphertext); // Encrypt disconnect message
            send(s, ciphertext, disconnect_len, 0); // Send encrypted disconnect message

            cout << "Stopping the application." << endl; // Print stop message
            break; // Break the loop
        }
    }

    close(s); // Close socket
}

// Function to receive message
void ReceiveMsg(int s, unsigned char *key, unsigned char *iv) {
    unsigned char buffer[4096];
    int recvlength;

    while (true) {
        recvlength = recv(s, buffer, sizeof(buffer), 0); // Receive message
        if (recvlength <= 0) {
            cout << "Disconnected from the server." << endl; // Print disconnection message
            break; // Break the loop
        } else {
            unsigned char decryptedtext[4096];
            int decryptedtext_len = decrypt(buffer, recvlength, key, iv, decryptedtext); // Decrypt message
            decryptedtext[decryptedtext_len] = '\0';

            string decryptedMessage((char*)decryptedtext);
            size_t usernamePos = decryptedMessage.find("Username: ");
            size_t messagePos = decryptedMessage.find(", Message: ");

            if (usernamePos != string::npos && messagePos != string::npos) {
                string username = decryptedMessage.substr(usernamePos + 10, messagePos - (usernamePos + 10));
                string message = decryptedMessage.substr(messagePos + 11);
                cout << "send from " << username << ": " << message << endl;

                appendToChatHistory(username, decryptedMessage); // Append message to chat history
            }
        }
    }

    close(s); // Close socket
}

int main() {
    if (!initialize()) { // If initialization failed
        cout << "Initialization failed." << endl; // Print error message
        return 1; // Exit with error
    }

    unsigned char key[] = "01234567890123456789012345678901"; // AES encryption key
    unsigned char iv[] = "0123456789012345"; // AES initialization vector

    int s = socket(AF_INET, SOCK_STREAM, 0); // Create socket

    if (s == -1) { // If socket creation failed
        cout << "Invalid socket created." << endl; // Print error message
        return 1; // Exit with error
    }

    int port = 12345;
    string serveraddr = "127.0.0.1";
    sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, serveraddr.c_str(), &server.sin_addr);

    if (connect(s, reinterpret_cast<sockaddr*>(&server), sizeof(server)) == -1) { // If connection failed
        cout << "Not able to connect to server." << endl; // Print error message
        perror("connect"); // Print error
        close(s); // Close socket
        return 1; // Exit with error
    }

    cout << "Successfully connected to server." << endl; // Print success message

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
            signUp(username); // Sign up
            break;
        case 2:
            login(username); // Login
            break;
        case 3:
            login(username); // Login
            showChatHistory(username); // Show chat history
            close(s); // Close socket
            return 0; // Exit
        default:
            cout << "Invalid choice." << endl; // Print error message
            close(s); // Close socket
            return 1; // Exit with error
    }

    thread senderThread(SendMsg, s, username, key, iv); // Create sender thread
    thread receiverThread(ReceiveMsg, s, key, iv); // Create receiver thread

    senderThread.join(); // Join sender thread
    receiverThread.join(); // Join receiver thread

    return 0; // Exit
}
