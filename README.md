# Digital-Banking-System


These  Transaction System is a command-line interface program written in C that facilitates token-based transactions. Users can register, log in, make payments, check their token balance, view transaction history, and manage their passwords. An admin view is also available for modifying user tokens.

## Features

### User Registration
Users can register by providing a unique username along with strong login and transaction passwords.

### User Authentication
Secure user authentication is implemented using usernames and login passwords. Failed login attempts are logged for security purposes.

### Token Transactions
Logged-in users can make token payments to other registered users. The system maintains a transaction history for each user.

### Balance Inquiry
Users can check their current token balance at any time.

### Transaction History
Users can view a detailed list of their previous transactions, including sent and received tokens.

### Password Management
Users can securely change their login and transaction passwords to enhance account security.

### Admin View
An admin has the capability to modify the token balance of any registered user, providing a level of control over the system.

### Inactivity Logout
To enhance security, users are automatically logged out after a period of inactivity.

## Requirements

- The program requires a C compiler for building and execution.

## Usage

1. **Compile the Program:**
    ```bash
    gcc -o token_system token_system.c
    ```

2. **Run the Program:**
    ```bash
    ./token_system
    ```

3. **Follow On-Screen Instructions:**
    - Register as a new user or log in with an existing account.
    - Use the menu options to perform various actions such as making payments, checking balances, viewing transaction history, and more.

4. **Admin Access:**
    - Admin access is available for modifying user token balances.
    - Admin credentials are required for authentication.

## Security Considerations

- The system uses strong password requirements to enhance security.
- Passwords are securely managed, and failed login attempts are logged.
- Admin access is protected by credentials to prevent unauthorized access.

## Notes

- This program is a basic implementation and may lack certain security features found in production-grade systems.
- In a real-world scenario, additional security measures, such as password hashing and encryption, would be implemented.
- Continuous improvements and updates to the program can be made based on evolving security standards and user requirements.
