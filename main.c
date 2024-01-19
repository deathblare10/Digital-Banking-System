#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#define MAX_USERS 100
#define MAX_STRING_LENGTH 50
#define MIN_PASSWORD_LENGTH 8
#define TRANSACTION_LIMIT 50
#define INACTIVITY_THRESHOLD 300
#define MAX_TRANSACTION_HISTORY 100

// Logging function
void logMessage(const char *message) {
    time_t currentTime = time(NULL);
    printf("[%s] %s\n", ctime(&currentTime), message);
}

typedef struct {
    char username[MAX_STRING_LENGTH];
    char loginPassword[MAX_STRING_LENGTH];
    char transactionPassword[MAX_STRING_LENGTH];
    int tokens;
    time_t lastActivityTime;
    int transactionHistory[MAX_TRANSACTION_HISTORY];
    int transactionCount;
} User;

User users[MAX_USERS];
int userCount = 0;

// Function prototypes
int isPasswordStrong(const char *password);
void registerUser();
void makePayment(int senderIndex);
void checkBalance(int userIndex);
void displayTransactionHistory(int userIndex);
void adminModifyTokens();
int authenticateUser(char *username, char *password);
void resetLastActivityTime(int userIndex);
int checkInactivity(int userIndex);
void changePassword(int userIndex, char *newPassword, char *passwordType);

int isPasswordStrong(const char *password) {
    int minLength = MIN_PASSWORD_LENGTH;
    int hasUppercase = 0, hasLowercase = 0, hasDigit = 0, hasSpecialChar = 0;

    for (int i = 0; password[i] != '\0'; i++) {
        if (isupper(password[i])) {
            hasUppercase = 1;
        } else if (islower(password[i])) {
            hasLowercase = 1;
        } else if (isdigit(password[i])) {
            hasDigit = 1;
        } else {
            hasSpecialChar = 1;
        }
    }

    return (strlen(password) >= minLength) && hasUppercase && hasLowercase && hasDigit && hasSpecialChar;
}

void registerUser() {
    if (userCount >= MAX_USERS) {
        printf("User limit reached. Cannot register more users.\n");
        return;
    }

    printf("Enter your username: ");
    scanf("%49s", users[userCount].username);

    char loginPassword[MAX_STRING_LENGTH];
    char transactionPassword[MAX_STRING_LENGTH];

    // Prompt user to set login password
    do {
        printf("Enter your login password: ");
        scanf("%49s", loginPassword);

        if (!isPasswordStrong(loginPassword)) {
            printf("Weak password. Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.\n");
        }
    } while (!isPasswordStrong(loginPassword));

    // Prompt user to set transaction password
    do {
        printf("Enter your transaction password: ");
        scanf("%49s", transactionPassword);

        if (!isPasswordStrong(transactionPassword)) {
            printf("Weak password. Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.\n");
        }
    } while (!isPasswordStrong(transactionPassword));

    strcpy(users[userCount].loginPassword, loginPassword);
    strcpy(users[userCount].transactionPassword, transactionPassword);
    users[userCount].tokens = 100;
    users[userCount].lastActivityTime = time(NULL);
    users[userCount].transactionCount = 0;

    userCount++;
    printf("Registration successful!\n");
    logMessage("User registered successfully.");
}

void makePayment(int senderIndex) {
    char username[MAX_STRING_LENGTH];
    char transactionPassword[MAX_STRING_LENGTH];
    int amount;

    printf("Enter recipient's username: ");
    scanf("%49s", username);

    int recipientIndex = -1;
    for (int i = 0; i < userCount; i++) {
        if (strcmp(users[i].username, username) == 0) {
            recipientIndex = i;
            break;
        }
    }

    if (recipientIndex == -1) {
        printf("Recipient not found.\n");
        return;
    }

    // Prompt user for transaction password before making payment
    printf("Enter your transaction password for verification: ");
    scanf("%49s", transactionPassword);

    // Check if the entered transaction password is correct
    if (strcmp(users[senderIndex].transactionPassword, transactionPassword) != 0) {
        printf("Incorrect transaction password. Payment canceled.\n");
        return;
    }

    printf("Enter the amount of tokens to transfer: ");
    if (scanf("%d", &amount) != 1 || amount <= 0 || amount > users[senderIndex].tokens || amount > TRANSACTION_LIMIT) {
        printf("Invalid amount or exceeding transaction limit or insufficient tokens in the sender's account.\n");
        return;
    }

    // Update sender and recipient balances
    users[senderIndex].tokens -= amount;
    users[recipientIndex].tokens += amount;

    // Add transaction to sender's history
    if (users[senderIndex].transactionCount < MAX_TRANSACTION_HISTORY) {
        users[senderIndex].transactionHistory[users[senderIndex].transactionCount++] = -amount; // Negative amount indicates payment sent
    }

    // Add transaction to recipient's history
    if (users[recipientIndex].transactionCount < MAX_TRANSACTION_HISTORY) {
        users[recipientIndex].transactionHistory[users[recipientIndex].transactionCount++] = amount; // Positive amount indicates payment received
    }

    printf("Payment successful!\n");
    logMessage("Payment successful.");
}

void checkBalance(int userIndex) {
    printf("Your token balance: %d\n", users[userIndex].tokens);
    logMessage("Checked balance.");
}

void displayTransactionHistory(int userIndex) {
    printf("Transaction History:\n");
    for (int i = 0; i < users[userIndex].transactionCount; i++) {
        printf("%d. %s %d tokens\n", i + 1, (users[userIndex].transactionHistory[i] < 0) ? "Sent" : "Received", abs(users[userIndex].transactionHistory[i]));
    }
    logMessage("Displayed transaction history.");
}

void adminModifyTokens() {
    char adminUsername[MAX_STRING_LENGTH];
    char adminPassword[MAX_STRING_LENGTH];
    printf("Enter admin username: ");
    scanf("%49s", adminUsername);
    printf("Enter admin password: ");
    scanf("%49s", adminPassword);

    // Implement more secure admin authentication here (e.g., hashing)

    if (strcmp(adminUsername, "admin") == 0 && strcmp(adminPassword, "adminpass") == 0) {
        char username[MAX_STRING_LENGTH];
        int amount;
        printf("Enter username to modify tokens: ");
        scanf("%49s", username);

        int userIndex = -1;
        for (int i = 0; i < userCount; i++) {
            if (strcmp(users[i].username, username) == 0) {
                userIndex = i;
                break;
            }
        }

        if (userIndex != -1) {
            printf("Enter the amount of tokens to add (positive) or remove (negative): ");
            if (scanf("%d", &amount) != 1) {
                printf("Invalid input for token modification.\n");
                return;
            }

            users[userIndex].tokens += amount;
            printf("Tokens modified successfully!\n");
            logMessage("Admin modified user tokens.");
        } else {
            printf("User not found.\n");
            logMessage("Admin token modification failed. User not found.");
        }
    } else {
        printf("Admin authentication failed. Access denied.\n");
        logMessage("Admin authentication failed.");
    }
}

void changePassword(int userIndex, char *newPassword, char *passwordType) {
    while (1) {
        printf("Enter your current %s password: ", passwordType);
        char currentPassword[MAX_STRING_LENGTH];
        scanf("%49s", currentPassword);

        if (strcmp(passwordType, "login") == 0) {
            // Check the current login password
            if (strcmp(users[userIndex].loginPassword, currentPassword) != 0) {
                printf("Incorrect current login password. Password change failed.\n");
                return;
            }
        } else if (strcmp(passwordType, "transaction") == 0) {
            // Check the current transaction password
            if (strcmp(users[userIndex].transactionPassword, currentPassword) != 0) {
                printf("Incorrect current transaction password. Password change failed.\n");
                return;
            }
        }

        // Check the new password strength
        if (!isPasswordStrong(newPassword)) {
            printf("Weak password. Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.\n");
        } else {
            // Update the password
            if (strcmp(passwordType, "login") == 0) {
                strcpy(users[userIndex].loginPassword, newPassword);
            } else if (strcmp(passwordType, "transaction") == 0) {
                strcpy(users[userIndex].transactionPassword, newPassword);
            }
            printf("%s password changed successfully!\n", passwordType == "login" ? "Login" : "Transaction");
            logMessage("Password changed successfully.");
            break;
        }
    }
}

int authenticateUser(char *username, char *password) {
    for (int i = 0; i < userCount; i++) {
        if (strcmp(users[i].username, username) == 0 && strcmp(users[i].loginPassword, password) == 0) {
            return i; // Return the user index
        }
    }
    return -1; // User not found or incorrect password
}

void resetLastActivityTime(int userIndex) {
    users[userIndex].lastActivityTime = time(NULL);
}

int checkInactivity(int userIndex) {
    time_t currentTime = time(NULL);
    return difftime(currentTime, users[userIndex].lastActivityTime) > INACTIVITY_THRESHOLD;
}

int main() {
    int choice;
    int loggedInUserIndex = -1; // Variable to store the index of the logged-in user

    while (1) {
        if (loggedInUserIndex == -1) {
            // User is not logged in
            printf("\n1. Register\n2. Login\n3. Admin View\n4. Quit\n");
        } else {
            // User is logged in
            printf("\n1. Make Payment\n2. Check Balance\n3. Transaction History\n4. Logout\n5. Change Password\n");
        }

        printf("Enter your choice: ");
        if (scanf("%d", &choice) != 1) {
            printf("Invalid input. Please try again.\n");
            while (getchar() != '\n'); // Clear input buffer
            continue;
        }

        switch (choice) {
            case 1:
                if (loggedInUserIndex == -1) {
                    registerUser();
                } else {
                    makePayment(loggedInUserIndex);
                    resetLastActivityTime(loggedInUserIndex);
                }
                break;
            case 2:
                if (loggedInUserIndex == -1) {
                    char username[MAX_STRING_LENGTH];
                    char password[MAX_STRING_LENGTH];
                    printf("Enter your username: ");
                    scanf("%49s", username);
                    printf("Enter your login password: ");
                    scanf("%49s", password);

                    loggedInUserIndex = authenticateUser(username, password);
                    if (loggedInUserIndex != -1) {
                        printf("Login successful!\n");
                        resetLastActivityTime(loggedInUserIndex);
                        logMessage("User logged in successfully.");
                    } else {
                        printf("Login failed. User not found or incorrect password.\n");
                        logMessage("Login failed. User not found or incorrect password.");
                    }
                } else {
                    checkBalance(loggedInUserIndex);
                    resetLastActivityTime(loggedInUserIndex);
                }
                break;
            case 3:
                if (loggedInUserIndex == -1) {
                    adminModifyTokens();
                } else {
                    displayTransactionHistory(loggedInUserIndex);
                    resetLastActivityTime(loggedInUserIndex);
                }
                break;
            case 4:
                if (loggedInUserIndex == -1) {
                    exit(0);
                } else {
                    printf("Logged out.\n");
                    logMessage("User logged out.");
                    loggedInUserIndex = -1;
                }
                break;
            case 5:
                if (loggedInUserIndex != -1) {
                    char newPassword[MAX_STRING_LENGTH];

                    printf("Choose password to change:\n1. Login Password\n2. Transaction Password\n");
                    int passwordChoice;
                    if (scanf("%d", &passwordChoice) != 1 || (passwordChoice != 1 && passwordChoice != 2)) {
                        printf("Invalid choice. Please try again.\n");
                        logMessage("Invalid password change choice.");
                        break;
                    }

                    printf("Enter your new password: ");
                    scanf("%49s", newPassword);

                    if (passwordChoice == 1) {
                        changePassword(loggedInUserIndex, newPassword, "login");
                    } else {
                        changePassword(loggedInUserIndex, newPassword, "transaction");
                    }
                } else {
                    printf("Please log in to change your password.\n");
                }
                break;
            default:
                printf("Invalid choice. Please try again.\n");
                logMessage("Invalid user choice.");
        }

        // Check for inactivity and logout if necessary
        if (loggedInUserIndex != -1 && checkInactivity(loggedInUserIndex)) {
            printf("Logout due to inactivity.\n");
            logMessage("Logout due to inactivity.");
            loggedInUserIndex = -1;
        }
    }

    return 0;
}
