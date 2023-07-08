# win_server_security_standards

This chef cookbook contains a chef recipe to enforce set of windows server hardening policies in order to secure windows operating systems.
These settings are recommended by various industry standards like CIS, NIST & frameworks i.e. Mitre ATT&CK

The policies are categorised in different section based on the nature of their implemtation & the OS components that they're trying to secure:
    1. Account & Password pilicies
    2. Audit Policies
    3. Logging configuration
    4. Windows Firewall policies
    5. Windows Network Security policies - Client & Server
    6. Windows Domain Memeber policies
    7. Windows UAC (User Account Policies)
    8. Windows System policies
    9. Windows Cryptographic configurations
    10. User Right Assignment policies
    11. Windows System objects policies

To use this cookbook, add the below chef recipe in you node's runlist:

    recipe[win_server_security_standards::win_server_security_policy]
