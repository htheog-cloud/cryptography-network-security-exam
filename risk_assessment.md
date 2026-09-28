# Risk Assessment

## 1. Assets, Vulnerabilities and Possible Consequences

| Asset                                      | Vulnerability                              | Possible Consequence                                                                                     |
| ------------------------------------------ | ------------------------------------------ | -------------------------------------------------------------------------------------------------------- |
| Central student records server             | Guest network access to the records server | Unauthorized users may access, modify, or delete confidential student records.                           |
| Student files transferred between campuses | Unencrypted file transfers                 | Attackers may intercept and read or modify sensitive student information.                                |
| IT staff accounts and systems              | Weak passwords and outdated software       | Attackers may compromise staff accounts or exploit software vulnerabilities to gain unauthorized access. |

## 2. Risk Ranking

| Rank | Risk                                                    | Likelihood | Impact | Reason                                                                                 |
| ---- | ------------------------------------------------------- | ---------- | ------ | -------------------------------------------------------------------------------------- |
| 1    | Unauthorized guest network access to the records server | High       | High   | Guest users may have a direct path to a highly sensitive server.                       |
| 2    | Interception of unencrypted file transfers              | High       | High   | Unencrypted data can potentially be captured and read during transmission.             |
| 3    | Weak passwords and outdated software                    | High       | High   | Weak passwords can be guessed and outdated software may contain known vulnerabilities. |

## 3. Recommended Controls

### Risk 1: Unauthorized Guest Network Access

**Control: Network segmentation and firewall traffic filtering**

The guest network should be isolated from the internal network containing the student records server. Firewall rules should block guest-network traffic to the records server and allow access only from authorized systems.

### Risk 2: Unencrypted File Transfers

**Control: Encrypted file transfer**

The institution should replace unencrypted file transfers with a secure protocol such as SFTP. Encryption helps protect the confidentiality and integrity of files while they are transferred between campuses.

### Risk 3: Weak Passwords and Outdated Software

**Control: Strong authentication and regular patching**

Staff should use strong, unique passwords and multi-factor authentication where possible. Operating systems and applications should also be regularly updated with security patches.

## 4. Security Observation

The repeated attempts to reach the server from an unfamiliar external address should be investigated. Firewall and server logs should be reviewed to determine whether the attempts represent scanning or attempted unauthorized access.

## 5. Conclusion

The assessment identified three major risks:

1. Unauthorized guest network access to the student records server.
2. Unencrypted file transfers between campuses.
3. Weak passwords and outdated software.

The recommended controls are network segmentation and firewall filtering, encrypted file transfers, and stronger authentication together with regular software patching.
