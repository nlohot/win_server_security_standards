#
# Cookbook:: win_server_security_standards
# Recipe:: win_server_security_policy
# Author(s): Nandkishor Lohot
#
# Copyright:: 2023, The Authors, All Rights Reserved.

# Skipping if tagged
if run_context.node['tags'].include?('skip_enforcement')
  Chef::Log.info('Skipping windows server security enforcment on this node')
  return
end

require 'chef/win32/version'
require 'win32/service'
require 'win32/registry'

# Enforce Account Policies
unless run_context.node['tags'].include?('skip_account_policies')
  account_policy 'enforce account policies' do
    policies  PasswordHistroySize: 24,            # Enforce password history
              MaximumPasswordAge: 90,             # Maximum password age
              MinimumPasswordAge: 1,              # Minimum password age
              MinimumPasswordLength: 14,          # Minimum password length
              PasswordComplexity: 1,              # Password must meet complexity requirements
              ClearTextPassword: 0,               # Store passwords using reversible encryption
              LockoutDuration: 15,                # Account Lockout Duration
              LockoutBadCount: 5,                 # Account lockout threshold
              ResetLockoutCount: 15,              # Reset account lockout counter after 15 minutes
              EnableGuestAccount: 0,              # Ensure 'Accounts: Guest account status' is set to 'Disabled'
              NewGuestName: '"NotGuest"',         # Configure Accounts: Rename guest account
              NewAdministratorName: '"SrvAdmin"', # Accounts: Rename administrator account
              LSAAnonymousNameLookup: 0,          # Network access: Allow anonymous SID/Name translation
              ForceLogoffWhenHourExpire: 1        # Network security: Force logoff when logon hours expire
  end
end

# Enforce Audit Policies
unless run_context.node['tags'].include?('skip_audit_policies')
  audit_policy 'enforce audit policies' do
    policies  Credential_validation: 'Success,Failure', # Audit Credential Validation
              Application_Group_Management: 'Success,Failure', # Audit Application Group Management
              Security_Group_Management: 'Success', # Audit Security Group Management
              User_Account_Management: 'Success,Failure', # Audit User Account Management
              Process_Creation: 'Success', # Audit Process Creation
              Account_Lockout: 'Failure', # Audit Account Lockout
              Logoff: 'Success', # Audit Logoff
              Logon: 'Success,Failure', # Audit Logon
              Special_Logon: 'Success', # Audit Special Logon
              'MPSSVC_Rule-Level_Policy_Change' => 'Success,Failure', # Audit MPSSVC Rule-Level Policy Change
              Other_Policy_Change_Events: 'Failure' # Audit Other Policy Change Events
  end
end

# Local System - Enforce logging policies
system_policy 'enforce logging policies' do
  policies  'Application: Control Event Log behavior when the log file reaches its maximum size' => '0', # Disabled
            'Application: Specify the maximum log file size (KB)' => '32768',
            'Security: Control Event Log behavior when the log file reaches its maximum size' => '0', # Disabled
            'Security: Specify the maximum log file size (KB)' => '196608',
            'Setup: Control Event Log behavior when the log file reaches its maximum size' => '0', # Disabled
            'Setup: Specify the maximum log file size (KB)' => '32768',
            'System: Control Event Log behavior when the log file reaches its maximum size' => '0', # Disabled
            'System: Specify the maximum log file size (KB)' => '32768'
end

# Enforce Local System - Devices policies
system_policy 'enforce local devices policies' do
  policies  'Devices: Allowed to format and eject removable media' => '0', # Disabled
            'Devices: Prevent users from installing printer drivers' => '1' # Enabled
end

# Enforce Local System - Domain Member policies
system_policy 'enforce domain memeber policies' do
  policies  'Domain member: Digitally encrypt or sign secure channel data (always)' => '1', # Enabled
            'Domain member: Digitally encrypt secure channel data (when possible)' => '1', # Enabled
            'Domain member: Digitally sign secure channel data (when possible)' => '1', # Enabled
            'Domain member: Disable machine account password changes' => '0', # Disable
            'Domain member: Maximum machine account password age' => '30', # 3o days
            'Domain member: Require strong (Windows 2000 or later) session key' => '1' # Enabled
end

# Enforce Local System - Interactive Logon policies
system_policy 'enforce interactive logon policies' do
  policies  'Interactive logon: Do not require CTRL+ALT+DEL' => '0', # Disabled
            'Interactive logon: Machine inactivity limit' => '900', # seconds
            'Interactive logon: Prompt user to change password before expiration' => '14' # days
end

# Enforce Local System - Microsoft Network Client & Server Policies
system_policy 'enforce network client and server policies' do
  policies  'Microsoft network client: Digitally sign communications (always)' => '1', # Enabled
            'Microsoft network client: Digitally sign communications (if server agrees)' => '1', # Enabled
            'Microsoft network client: Send unencrypted password to third-party SMB servers' => '0', # Disabled
            'Microsoft network server: Amount of idle time required before suspending session' => '15', # Minutes
            'Microsoft network server: Digitally sign communications (always)' => '1', # Enabled
            'Microsoft network server: Digitally sign communications (if client agrees)' => '1' # Enabled
end

# Enforce Local System - Network Access Policies
system_policy 'enforce network access policies' do
  policies  'Network access: Do not allow anonymous enumeration of SAM accounts' => '1', # Enabled
            'Network access: Do not allow anonymous enumeration of SAM accounts and shares' => '1', # Enabled
            'Network access: Let Everyone permissions apply to anonymous users' => '0', # Disabled
            'Network access: Named Pipes that can be accessed anonymously' => [
              'LSARPC',
              'NETLOGON',
              'SAMR'
            ],
            'Network access: Remotely accessible registry paths' => [
              'System\\CurrentControlSet\\Control\\ProductOptions',
              'System\\CurrentControlSet\\Control\\Server Applications',
              'Software\\Microsoft\\Windows NT\\CurrentVersion'
            ]
end

# Enforce Local System - Network Security Policies
system_policy 'enforce network security policies' do
  policies  'Network security: Allow Local System to use computer identity for NTLM' => '1', # Enabled
            'Network security: Allow LocalSystem NULL session fallback' => '1', # Enabled
            'Network Security: Allow PKU2U authentication requests to this computer to use online identities' => '0', # Disabled
            'Network security: Configure encryption types allowed for Kerberos' => '2147483640', # AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types.
            'Network security: Do not store LAN Manager hash value on next password change' => '1' # Enabled
end

# Enforce Local System - System Objects Policies
system_policy 'enforce system object policies' do
  policies  'System objects: Require case insensitivity for non-Windows subsystems' => '1', # Enabled
            'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' => '1' # Enabled
end

# Enforce Local System - User Account Control Policies
system_policy 'enforce UAC policies' do
  policies  'User Account Control: Admin Approval Mode for the Built-in Administrator account' => '1', # Enabled
            'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' => '2', # Prompt for creds on secure desktop
            'User Account Control: Behavior of the elevation prompt for standard users' => '0', # Automatically deny elevation request
            'User Account Control: Detect application installations and prompt for elevation' => '1', # Enabled
            'User Account Control: Only elevate UIAccess applications that are installed in secure locations' => '1' # Enabled
end

# Enforce Local System - Host-Based Firewall Policies
system_policy 'enforce advanced windows firewall policies' do
  policies  'Windows Firewall: Domain: Firewall state' => '1', # Enabled
            'Windows Firewall: Domain: Inbound connections' => '0', # Allow
            'Windows Firewall: Domain: Outbound connections' => '0', # Allow
            'Windows Firewall: Private: Firewall state' => '1', # Enabled
            'Windows Firewall: Private: Inbound connections' => '0', # Allow
            'Windows Firewall: Private: Outbound connections' => '0', # Allow
            'Windows Firewall: Public: Firewall state' => '1', # Enabled
            'Windows Firewall: Public: Inbound connections' => '0', # Allow
            'Windows Firewall: Public: Outbound connections' => '0' # Allow
end

# Enforce Cryptographic controls
system_policy 'enforce cryptographic controls' do
  policies  'Disable NULL cipher suites' => '0',
            'Disable DES cipher suites' => '0',
            'Disable RC2 40/128 cipher suites' => '0',
            'Disable RC2 56/128 cipher suites' => '0',
            'Disable RC2 128/128 cipher suites' => '0',
            'Disable RC4 40/128 cipher suites' => '0',
            'Disable RC4 56/128 cipher suites' => '0',
            'Disable RC4 64/128 cipher suites' => '0',
            'Disable RC4 128/128 cipher suites' => '0',
            'Disable MD5 Hashing Algorithm' => '0',
            'Disable SHA1 Hashing Algorithm' => '0',
            'Disable PCT 1.0 - Client' => '0',
            'Disable PCT 1.0 - Server' => '0',
            'Disable Multi-Protocol Unified Hello - Client' => '0',
            'Disable Multi-Protocol Unified Hello - Server' => '0',
            'Disable SSL v2.0 - Client' => '0',
            'Disable SSL v2.0 - Server' => '0',
            'Disable SSL v3.0 - Client' => '0',
            'Disable SSL v3.0 - Server' => '0',
            'Disable TLS v1.0 - Client' => '0',
            'Disable TLS v1.0 - Server' => '0',
            'Disable TLS v1.1 - Client' => '0',
            'Disable TLS v1.1 - Server' => '0',
            'Enable AES 128/128 cipher suites' => '4294967295',
            'Enable AES 256/256 cipher suites' => '4294967295',
            'Enable Triple DES cipher suites' => '4294967295',
            'Enable TLS v1.2 - Client' => '1',
            'Enable TLS v1.2 - Server' => '1',
            'Enable TLS v1.3 - Client' => '1',
            'Enable TLS v1.3 - Server' => '1',
            'Ensure TLS Cipher suites ordering is configured' => 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256,TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,TLS_DHE_DSS_WITH_AES_256_CBC_SHA,TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,TLS_DHE_DSS_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA'
end

# Enforce additonal Local System Policies
system_policy 'enforce local system polcicies' do
  policies  'Configure SMB v1 client driver' => '0', # Enabled:Disable driver
            'Configure SMB v1 server' => '0', # Disabled
            'NetBT NodeType configuration' => '2', # P-node
            'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' => '0', # Disabled
            'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' => '2', # Highest protection, source routing is completely disabled
            'Turn off multicast name resolution' => '0', # Enabled
            'Prohibit installation and configuration of Network Bridge on your DNS domain network' => '0', # Enabled
            'Require domain users to elevate when setting a network\'s location' => '0', # Enabled
            'Minimize the number of simultaneous connections to the Internet or a Windows Domain' => '1', # Enabled: 1 = Minimize simultaneous connections
            'Include command line in process creation events' => '1', # Enabled
            'Encryption Oracle Remediation' => '0', # Force Updated Clients
            'Configure Offer Remote Assistance' => '0', # Disabled
            'Configure Solicited Remote Assistance' => '0', # Disabled
            'Enable RPC Endpoint Mapper Client Authentication' => '1', # Enabled
            'Turn off real-time protection' => '0', # Disabled
            'Turn on behavior monitoring' => '0', # Enabled
            'Always prompt for password upon connection' => '1', # Enabled
            'Require secure RPC communication' => '1', # Enabled
            'Always install with elevated privileges' => '0', # Disabled
            'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' => '300000', # Enabled: 300,000 or 5 minutes
            'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' => '0', # Disabled
            'Set time limit for active but idle Remote Desktop Services sessions' => '900000', # 15 Minutes
            'Set time limit for disconnected sessions' => '60000' # 1 Minute
end

# Enforce User Right Assignment Policies
directory 'C:\\Temp' do
  action :create
  ignore_failure true
end

unless run_context.node['tags'].include?('skip_user_rights')
  cookbook_file 'C:\\temp\\UserRights.psm1' do
    source 'UserRights.psm1'
    action :create_if_missing
    ignore_failure true
  end

  powershell_script 'assign user rights' do
    code <<-URA
    $rights = @{
      SeNetworkLogonRight = @('Administrators','Authenticated Users');
      SeInteractiveLogonRight = "Administrators";
      SeRemoteInteractiveLogonRight = @('Administrators','Remote Desktop Users');
      SeBackupPrivilege = "Administrators";
      SeSystemtimePrivilege = @('Administrators','LOCAL SERVICE');
      SeCreateGlobalPrivilege = @('Administrators','LOCAL SERVICE','NETWORK SERVICE','SERVICE');
      SeDenyInteractiveLogonRight = "Guest";
      SeImpersonatePrivilege = @('Administrators','LOCAL SERVICE','NETWORK SERVICE','SERVICE');
      SeDenyNetworkLogonRight = "Guest";
      SeAssignPrimaryTokenPrivilege = @('LOCAL SERVICE','NETWORK SERVICE');
      SeTakeOwnershipPrivilege = "Administrators"
    }
    Import-Module C:\\temp\\UserRights.psm1
    foreach ($key in $rights.Keys){
        Grant-UserRight -Right $key -Account $($rights[$key]) -ErrorAction SilentlyContinue
    }
    URA
  end
end
