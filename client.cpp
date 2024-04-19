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

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /* Finalise the encryption. */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
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
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* Finalise the decryption. */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

// Function declarations
bool initialize();
void signUp();
void login();
void encrypt(string &text);
bool checkUsernameInFile(string encryptedUsername);
bool checkPasswordInFile(string encryptedUsername, string encryptedPassword);
void saveToFile(string username, string password);
void SendMsg(int s, const string& username, unsigned char *key, unsigned char *iv);
void ReceiveMsg(int s, unsigned char *key, unsigned char *iv);

bool initialize() {
    return true;
}

// Function to encrypt a string using Caesar cipher
void encrypt(string &text) {
    for (char &c : text) {
        if (isalpha(c)) {
            char base = islower(c) ? 'a' : 'A';
            c = base + (c - base + SHIFT) % 26;
        }
    }
}

// Function to save the account information to a file
void saveToFile(string username, string password) {
    // Open file in append mode
    ofstream outFile("accounts_info.txt", ios::app);
    // Check if the file is successfully opened
    if (outFile.is_open()) {
        // Write username and password to the file
        outFile << "Username: " << username << ", Password: " << password << endl;
        // Close the file
        outFile.close();
    } else {
        cout << "Unable to open file!" << endl;
    }
}

// Helper function to check if encrypted username exists in file
bool checkUsernameInFile(string encryptedUsername) {
    // Open the accounts_info.txt file
    ifstream inFile("accounts_info.txt");
    // Check if the file is successfully opened
    if (inFile.is_open()) {
        // Variable to store each line of the file
        string line;
        // Loop through each line of the file
        while (getline(inFile, line)) {
            // Check if the line contains the encrypted username
            if (line.find("Username: " + encryptedUsername) != string::npos) {
                // Close the file
                inFile.close();
                return true; // Return true if the encrypted username is found
            }
        }
        // Close the file
        inFile.close();
    } else {
        // Print an error message if the file cannot be opened
        cout << "Unable to open file!" << endl;
    }
    // Return false if the encrypted username is not found or if there's an error opening the file
    return false;
}

// Helper function to check if encrypted username and password match in file
bool checkPasswordInFile(string encryptedUsername, string encryptedPassword) {
    // Open the accounts_info.txt file
    ifstream inFile("accounts_info.txt");
    // Check if the file is successfully opened
    if (inFile.is_open()) {
        // Variable to store each line of the file
        string line;
        // Loop through each line of the file
        while (getline(inFile, line)) {
            // Check if the line contains the encrypted username
            if (line.find("Username: " + encryptedUsername) != string::npos) {
                // Found matching username, now check password
                if (line.find("Password: " + encryptedPassword) != string::npos) { // Check if the line contains the encrypted password
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

// Function to sign up
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
    login();
}

// Function to log in
void login() {
    accessGranted = false;
    while (!accessGranted) {
        bool usernameCorrect = false;
        bool passwordCorrect = false;
        string username;

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

            // Check if encrypted username and password match in file
            if (checkPasswordInFile(username, password)) {
                passwordCorrect = true;
            } else {
                cout << "Incorrect password. Please try again." << endl;
            }
        }
        cout << "You have access" << endl;
        accessGranted = true;
    }
}

// Function to send messages
void SendMsg(int s, const string& username, unsigned char *key, unsigned char *iv) {
    cout << "Enter your message" << endl;
    string message;

    while (true) {
        getline(cin, message);

        // Encrypt the message before sending
        unsigned char ciphertext[4096];
        int ciphertext_len = encrypt((unsigned char *)message.c_str(), message.length(), key, iv, ciphertext);

        int bytesent = send(s, ciphertext, ciphertext_len, 0);
        if (bytesent == -1) {
            cout << "Error sending message." << endl;
        }

        if (message == "quit") {
            cout << "Stopping the application." << endl;
            break;
        }
    }

    close(s);
}

// Function to receive messages
void ReceiveMsg(int s, unsigned char *key, unsigned char *iv) {
    unsigned char buffer[4096];
    int recvlength;
    string msg = "";

    while (true) {
        recvlength = recv(s, buffer, sizeof(buffer), 0);
        if (recvlength <= 0) {
            cout << "Disconnected from the server." << endl;
            break;
        } else {
            // Decrypt the received message
            unsigned char decryptedtext[4096];
            int decryptedtext_len = decrypt(buffer, recvlength, key, iv, decryptedtext);
            decryptedtext[decryptedtext_len] = '\0';

            cout << "Received: " << decryptedtext << endl;
        }
    }

    close(s);
}

// Main function
int main() {
    if (!initialize()) {
        cout << "Initialization failed." << endl;
        return 1;
    }

    // AES key and IV (Initialization Vector)
    unsigned char key[] = "01234567890123456789012345678901";
    unsigned char iv[] = "0123456789012345";

    int s = socket(AF_INET, SOCK_STREAM, 0);

    if (s == -1) {
        cout << "Invalid socket created." << endl;
        return 1;
    }

    int port = 12346;
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
    cout << "Enter your choice: ";
    cin >> choice;
    cin.ignore(); // Ignore newline character left in the input buffer

    switch (choice) {
        case 1:
            signUp();
            break;
        case 2:
            login();
            break;
        default:
            cout << "Invalid choice." << endl;
            close(s);
            return 1;
    }

   // Now, pass the socket as an argument to the thread functions correctly
    string username; // Assuming username is known after login
    thread senderThread(SendMsg, s, username, key, iv);
    thread receiverThread(ReceiveMsg, s, key, iv);

    senderThread.join();
    receiverThread.join();

    return 0;
}

