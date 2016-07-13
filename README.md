# MFA Server

Enrole and validate users with one-time passwords based on RFC 6238 (TOTP).
The MFA Server implements a ReST interface for applications to consume in order to add multi-factor authentication security.

The MFA server can enrole a user, storing a unique TOTP secret for each use in a Hashicorp Vault instance. Calls to the ReST API can then also be used to validate a one time password provided for that user.

## Prerequisites
Hashicorp Vault (https://www.vaultproject.io/) is needed as the backend store for the MFA secrets. The Vault instance will need to implement AppId authentication (https://www.vaultproject.io/docs/auth/app-id.html).

An LDAP server is also needed to authenticate the users' passwords.

## Configuration
Below is an example JSON configuration for the MFA server. It includes all available keys but not all of these are necessarily needed.
```
{
  "MFAServer": {
    "ListenerSocket": "0.0.0.0:8443",
    "TLS": {
      "Enabled": true,
      "CertificateFile": "/path/to/servercert.pem",
      "KeyFile": "/path/to/certkey.pem"
    },
    "LogFile": "/path/to/mfaserver.log",
    "LogLevel": "INFO"
  },
  "Vault": {
    "VaultConnection": {
      "EndPoint": "https://192.168.1.100:8200",
      "TrustCACert": "/path/to/trustedcert.pem"
    },
    "AppIDRead": "01bd2fe7-e5ab-47c8-ad48-9888ae6348a5",
    "AppIDWrite": "01bd2fe7-e5ab-47c8-ad48-9888ae6348a5",
    "UserIDFile": "/path/to/file/containing/vaultUserId",
    "UserID": "0ecd7b5d-4885-45c1-a03f-5949e485c6bf",
    "MFASecretsPath": "/secret/mfatest"
  },
  "LDAP": {
    "EndPoint": "ldaps://192.168.1.200:636",
    "TrustCACert": "/path/to/trustedcert.pem",
    "UserDN": "uid={username},ou=users,dc=example,dc=com"
  }
}
```
The configuration keys are explained below
* MFAServer: This section details how to configure the MFAServer service
  * ListenerSocket: The IP and port for the MFA server to listen for requests on.
  * TLS: This section details how to configure TLS for the MFA Server
    * Enabled: Whether to enable TLS for the MFA Server (true|false)
    * CertificateFile: Path to the certificate file to use for TLS configuration.
    * KeyFile: Path to the certificate key file
  * Logfile: Path to where the MFA server should log to.
  * LogLevel: The log level to use (DEBUG|INFO|WARNING|ERROR)
* Vault: This section defines how to connect and authenticate to the Vault instance.
  * EndPoint: The URL endpoint of the Vault instance.
  * TrustCACert: The certificate to trust that signed the server certificate of the Vault instance.
  * AppIDRead: The Vault AppId used when performing read operations from the Vault.
  * AppIDWrite: The Vault AppId used when performing write operations to the Vault.
  * UserIDFile: (Recommended) The file that holds the UserID secret used to authenticate to the Vault. The format of this file is given below. The file permissions of this file should be highly restrictive so only the MFA server process user can read it.
  * UserID: (Optional) Specify the UserID here rather than in its own file. It is recommended not to use this but rather to put the UserID in a seperate file.
  * MFASecretPath: The path within Vault where the MFA secrets will be held.
* LDAP: This section defines how to connect to an LDAP server to authenticate the username and password.
  * EndPoint: The URL endpoint of the LDAP server.
  * TrustCACert: The certificate to trust that signed the server certificate of the LDAP server. Required if ldaps:// is used to connect to the LDAP server.
  * UserDN: The full LDAP distinguished name (DN) to bind to LDAP with using "{username}" to indicate where the username provided should be inserted.

#### UserID File
If using a UserID file it should have this format:
```
{
  "UserID": "0ecd7b5d-4885-45c1-a03f-5949e485c6bf"
}
```

## Running
To start the MFA Server run this command:
```
./mfaserver -config=/path/to/mfaserver-config.json
```

## Use
The MFA Server implements a simple API:

* /enrole - create and store a new MFA secret for a user
  * Request POST data:
  ```
  {
    "issuer": "issuer",
    "domain": "domainname",
    "username": "username",
    "password": "password"
  }
  ```
  * Response data:
    If the "Accept-Encoding" header value is set to "image/png" then a png QR code image is returned suitable for use with the Google Authenticator application.
    Else the following JSON is returned:
  ```
  {
    "secret": "secretstring"
  }
  ```
* /validate - validate a one time password for a specified user
  * Request POST data:
  ```
  {
    "issuer": "issuer",
    "domain": "domainname",
    "username": "username",
    "password": "password",
    "otp": "123456"
  }
  ```
  * Response:
    * HTTP Response code 204 - indicates the OTP is valid at this moment in time for the user specified
    * HTTP response code 401 - indicates the OTP is not valid
* /update - create and store a new MFA secret for an existing user
  * Not yet implemented

## Enhancements
* Need to check the user has not already been enroled
* Need to implement the update part of the API that will require the current OTP