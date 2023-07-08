# win_server_security_standards

This chef cookbook contains a chef recipe to enforce a set of Windows server hardening policies in order to secure Windows operating systems.
These settings are recommended by various industry standards like CIS, NIST and frameworks, i.e. Mitre ATT&CK

* The policies are categorized into different sections based on the nature of their implementation and the OS components that they're trying to secure:
    1. Account and Password Policies
    2. Audit Policies
    3. Logging configuration
    4. Windows Firewall policies
    5. Windows Network Security Policies: Client and Server
    6. Windows Domain Member policies
    7. Windows UAC (User Account Policies)
    8. Windows System policies
    9. Windows Cryptographic configurations
    10. User Right Assignment policies
    11. Windows System Object policies

* To use this cookbook, add the below chef recipe to your node's runlist: 

        recipe[win_server_security_standards::win_server_security_policy]
