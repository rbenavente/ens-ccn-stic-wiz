
resource "wiz_cloud_configuration_rule" "ccn_442_acc5r1_4" {
  description              = "This rule checks whether the ESXi host is configured with a number of passwords to remember for each user.\n\nThis rule fails if `Security.PasswordHistory` is set to any value lower than `24`.\n\nPassword complexity guidelines might allow users to reuse older passwords. Setting the value of this setting to 24 or higher helps prevent password reuse."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host number of passwords to remember should be set to 24 or higher for ENS Classification Level Basic | Medium |High"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nhasPasswordHistory {\n\toption := input.Config.option[_]\n\tlower(option.key) == \"security.passwordhistory\"\n   \toption.value >= 24\n}\n\nresult = \"fail\" {\n\tnot hasPasswordHistory\n}\n\ncurrentConfiguration := \"Security.PasswordHistory is not set to 24 or higher\"\nexpectedConfiguration := \"Security.PasswordHistory should be set to 24 or higher\""
  remediation_instructions = "Perform the following command to set a number of passwords to remember via PowerCLI:\n\n```  \nGet-VMHost -Name {{ESXiHost}} | Get-AdvancedSetting Security.PasswordHistory | Set-AdvancedSetting -Value 24\n```\n"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_acc5r2_1" {
  description              = "This rule checks whether the ESXi host is configured with a proper user password policy.\n\nThis rule fails if `Security.PasswordQualityControl` is set to any value lower than `retry=3 min=disabled,disabled,disabled,disabled,10 max=64 similar=deny passphrase=3`.\n\nFor syntax specification, please refer to VMware [guidelines on ESXi passwords](https://docs.vmware.com/en/VMware-vSphere/7.0/com.vmware.vsphere.hostclient.doc/GUID-EA3DF94F-7CCD-4F27-BA41-8EB0D4DFFE69.html).\n\nWhen set, this setting enforces required password length and character class requirements, to ensure only secure passwords can be used."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host password policy should be set for ENS Classification Level Medium"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nhasPasswordQualityControl {\n\toption := input.Config.option[_]\n\tlower(option.key) == \"security.passwordqualitycontrol\"\n   \tlower(option.value) == \"retry=3 min=disabled,disabled,disabled,disabled,10 max=64 similar=deny passphrase=3\"\n}\n\nresult = \"fail\" {\n\tnot hasPasswordQualityControl\n}\n\ncurrentConfiguration := \"Security.PasswordQualityControl is not set to properly\"\nexpectedConfiguration := \"Security.PasswordQualityControl should be set\""
  remediation_instructions = "Perform the following command to set a password policy via PowerCLI:\n\n```  \nGet-VMHost -Name {{ESXiHost}} | Get-AdvancedSetting Security.PasswordQualityControl | Set-AdvancedSetting -Value \"retry=3 min=disabled,disabled,disabled,disabled,10 max=64 similar=deny passphrase=3\"\n```\n"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_acc5r1_3" {
  description              = "This rule checks whether the ESXi host is configured with the proper Security.AccountLockFailure\n\nThis rule fails if `Security.AccountLockFailure` is set to any value different to `8`.\n\n"
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi  should have Security.AccountLockFailures is set to  8 for ENS Classification Level Basic | Medium |High"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nhasPasswordHistory {\n\toption := input.Config.option[_]\n\tlower(option.key) == \"Security.AccountLockFailure\"\n   \toption.value != 8\n}\n\nresult = \"fail\" {\n\tnot hasPasswordHistory\n}\n\ncurrentConfiguration := \"Security.AccountLockFailure is not set to 8\"\nexpectedConfiguration := \"Security.AccountLockFailure should be set to 8\""
  remediation_instructions = "Perform the following command to set a number of passwords to remember via PowerCLI:\n\n```  \nGet-VMHost -Name {{ESXiHost}} | Get-AdvancedSetting Security.AccountLockFailure | Set-AdvancedSetting -Value 8\n```\n"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp2r1_12" {
  description              = "This rule checks whether unauthorized connections of devices are enabled.\n\nThis rule fails if `isolation.device.connectable.disable` is not set to `TRUE`.\n\nWhen enabled, users and VM processes without root or administrator privileges can connect devices, such as network adapters and CD-ROM drives.\n\nDisabling unauthorized connection of devices helps prevent unauthorized changes within the guest operating system, which could be used to gain unauthorized access, cause denial of service conditions, and negatively affect the security of the operating system."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi virtual machine unauthorized connection of devices should be disabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\ndeviceConnectionsDisabled {\n\tconfigItem := input.Config.extraConfig[_]\n    lower(configItem.key) == \"isolation.device.connectable.disable\"\n    upper(configItem.value) == \"TRUE\"\n}\n\nresult = \"fail\" {\n\tnot deviceConnectionsDisabled\n}\n\ncurrentConfiguration := \"isolation.device.connectable.disable is not set to TRUE\"\nexpectedConfiguration := \"isolation.device.connectable.disable should be set to TRUE\""
  remediation_instructions = "Perform the following command to prevent unauthorized device connections via PowerCLI:  \n  \n```  \nGet-VM | New-AdvancedSetting -Name \"isolation.device.connectable.disable\" -value $true  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#virtualMachine"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_acc5r1_1" {
  description              = "This rule checks whether the ESXi host is configured with a proper user password policy.\n\nThis rule fails if `Security.PasswordQualityControl` is set to any value lower than `retry=3 min=disabled,disabled,disabled,disabled,8 max=64 similar=deny passphrase=3`.\n\nFor syntax specification, please refer to VMware [guidelines on ESXi passwords](https://docs.vmware.com/en/VMware-vSphere/7.0/com.vmware.vsphere.hostclient.doc/GUID-EA3DF94F-7CCD-4F27-BA41-8EB0D4DFFE69.html).\n\nWhen set, this setting enforces required password length and character class requirements, to ensure only secure passwords can be used."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host password policy should be set for ENS Classification Level Basic"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nhasPasswordQualityControl {\n\toption := input.Config.option[_]\n\tlower(option.key) == \"security.passwordqualitycontrol\"\n   \tlower(option.value) == \"retry=3 min=disabled,disabled,disabled,disabled,8 max=64 similar=deny passphrase=3\"\n}\n\nresult = \"fail\" {\n\tnot hasPasswordQualityControl\n}\n\ncurrentConfiguration := \"Security.PasswordQualityControl is not set to properly\"\nexpectedConfiguration := \"Security.PasswordQualityControl should be set\""
  remediation_instructions = "Perform the following command to set a password policy via PowerCLI:\n\n```  \nGet-VMHost -Name {{ESXiHost}} | Get-AdvancedSetting Security.PasswordQualityControl | Set-AdvancedSetting -Value \"retry=3 min=disabled,disabled,disabled,disabled,8 max=64 similar=deny passphrase=3\"\n```\n"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp2r1_10" {
  description              = "This rule checks whether virtual disk shrinking is disabled.\n\nThis rule fails if `isolation.tools.diskShrink.disable` is not set to `TRUE`. \n\nWhen done repeatedly, virtual disk shrinking might cause the virtual disk to become unavailable, resulting in a denial of service. \n\nShrinking a virtual disk reclaims unused space in it. If there is empty space in the disk, this process reduces the amount of space the virtual disk occupies on the host drive. Normal users and processes - that is, users and processes without root or administrator privileges - within virtual machines have the capability to invoke this procedure. \n\nHowever, if this is done repeatedly, the virtual disk can become unavailable while this shrinking is being performed, effectively causing a denial of service. In most data center environments, disk shrinking is not done, so you should disable this feature. \n\nRepeated disk shrinking can make a virtual disk unavailable."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host virtual disk shrinking should be disabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nshrinkingDisabled {\n\tconfigItem := input.Config.extraConfig[_]\n    lower(configItem.key) == \"isolation.tools.diskshrink.disable\"\n    upper(configItem.value) == \"TRUE\"\n}\n\nresult = \"fail\" {\n\tnot shrinkingDisabled\n}\n\ncurrentConfiguration := \"isolation.tools.diskShrink.disable is enabled\"\nexpectedConfiguration := \"isolation.tools.diskShrink.disable should be disabled\""
  remediation_instructions = "Perform the following command via PowerCLI:  \n  \n```  \nGet-VM | New-AdvancedSetting -Name \"isolation.tools.diskShrink.disable\" -value $true  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#virtualMachine"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_acc7r2_1" {
  description              = "This rule checks whether the ESXi host is restricting access to the host.\n\nThis rule fails if `AllowedHosts.AllIp` is set to `true`. \n\nUnrestricted access to services running on an ESXi host can expose a host to unauthorized access.\n\nIt is recommended to reduce the risk by configuring the ESXi firewall to only allow access from authorized IP addresses and networks."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host firewall should be configured to restrict access"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nresult = \"fail\" {\n\tinput.Config.firewall.ruleset[_].allowedHosts.allIp\n}\n\ncurrentConfiguration := \"The firewall allows all IPs to access a service\"\nexpectedConfiguration := \"The firewall should restrict allowed IPs\""
  remediation_instructions = "To properly restrict access to services running on an ESXi host, perform the following from the vSphere web client:  \n  \n1. Select a host  \n2. Click `Configure` then expand `System` then select `Firewall`.  \n3. Click `Edit` to view services which are enabled (indicated by a check).  \n4. For each enabled service, (e.g., ssh, vSphere Web Access, http client) provide a list of allowed IP addresses.  \n5. Click `OK`."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "HIGH"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_acc5r2_2" {
  description              = "This rule checks whether the account lockout period is set to 60 minutes.\n\nThis rule fails if `Security.AccountUnlockTime` is set to any value other than 3600.\n\nAn account is automatically locked after the maximum number of failed consecutive login attempts is reached. The account should be automatically unlocked after 15 minutes. Otherwise, administrators will need to manually unlock accounts per user request.\n\nThis setting reduces inconvenience for benign users and overhead on administrators, while also severely slowing down any brute force password attacks."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi should have account lockout period set to 60 minutes for ENS Classification Level  Medium"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nhasProperAccountUnlockTime {\n\toption := input.Config.option[_]\n\tlower(option.key) == \"security.accountunlocktime\"\n   \toption.value == 3600\n}\n\nresult = \"fail\" {\n\tnot hasProperAccountUnlockTime\n}\n\ncurrentConfiguration := \"Security.AccountUnlockTime is not set to 3600\"\nexpectedConfiguration := \"Security.AccountUnlockTime should be set to 3600\""
  remediation_instructions = "Perform the following command to set the account lockout to 60 minutes via PowerCLI:  \n  \n```  \nGet-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime | Set-AdvancedSetting -Value 3600  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp2r1_1" {
  description              = "This rule checks whether the vSwitch Forged Transmits policy is set to reject.\n\nThis rule fails if `ForgedTransmits` is set to `true`. \n\nIf the virtual machine operating system changes the MAC address, the operating system can send frames with an impersonated source MAC address at any time. This allows an operating system to stage malicious attacks on the devices in a network by impersonating a network adapter authorized by the receiving network.\n\nSetting forged transmissions to accept means the virtual switch does not compare the source and effective MAC addresses.\n\nTo protect against MAC address impersonation, all virtual switches should have forged transmissions set to reject."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host vSwitch forged transmits policy should be set to reject"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nresult = \"fail\" {\n\tinput.Config.network.vswitch[_].spec.policy.security.forgedTransmits == true\n}\n\ncurrentConfiguration := \"ForgedTransmits is set to Accept\"\nexpectedConfiguration := \"ForgedTransmits should be set to Reject\""
  remediation_instructions = "Perform the following command to set the policy to reject forged transmissions, perform the following via PowerCLI:  \n  \n```  \nesxcli network vswitch standard policy security set -v vSwitch2 -f false  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp2r1_9" {
  description              = "This rule checks whether GUI options are enabled.\n\nThis rule fails if `isolation.tools.setGUIOptions.enable` is set to `TRUE`.\n\nVM console and paste GUI options are disabled by default."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi virtual machine console GUI options should be disabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nGUIOperationsEnabled {\n\tconfigItem := input.Config.extraConfig[_]\n    lower(configItem.key) == \"isolation.tools.setguioptions.enable\"\n    upper(configItem.value) == \"TRUE\"\n}\n\nresult = \"fail\" {\n\tGUIOperationsEnabled\n}\n\ncurrentConfiguration := \"isolation.tools.setGUIOptions.enable is not set to TRUE\"\nexpectedConfiguration := \"isolation.tools.setGUIOptions.enable should be set to TRUE\""
  remediation_instructions = "Perform the following command to disable VM console and paste GUI options via PowerCLI:  \n  \n```  \nGet-VM | New-AdvancedSetting -Name \"isolation.tools.setGUIOptions.enable\" -value $false  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#virtualMachine"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp8r2_2" {
  description              = "This rule checks whether remote logging is configured on the ESXi host.\n\nThis rule fails if `Syslog.global.logHost` is missing.\n\nBy default, ESXi logs are stored on a local scratch volume or ramdisk. To preserve logs, you can configure remote logging to a central log host for the ESXi hosts.\n\nRemote logging to a central log host provides a secure, centralized store for ESXi logs by easily monitoring all hosts with a single tool and aggregating analysis and searching to look for such things as coordinated attacks on multiple hosts. Logging to a secure, centralized log server helps prevent log tampering and provides a long-term audit record."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host remote logging should be configured"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nlogHostExists {\n\tconfigItem := input.Config.option[_]\n    lower(configItem.key) == \"syslog.global.loghost\"\n    count(configItem.value) > 0\n}\n\nresult = \"fail\" {\n\tnot logHostExists\n}\n\ncurrentConfiguration := \"Syslog.global.logHost is empty\"\nexpectedConfiguration := \"Syslog.global.logHost should not be empty\""
  remediation_instructions = "Perform the following command to configure remote logging via PowerCLI:  \n  \n```  \nGet-VMHost | Foreach { Set-<span>AdvancedSetting </span><span>-VMHost $_ -Name Syslog.global.logHost -Value \"<NewLocation>\" }</span>  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_acc5r3_2" {
  description              = "This rule checks whether the account lockout period is set to 90 minutes.\n\nThis rule fails if `Security.AccountUnlockTime` is set to any value other than 5400.\n\nAn account is automatically locked after the maximum number of failed consecutive login attempts is reached. The account should be automatically unlocked after 15 minutes. Otherwise, administrators will need to manually unlock accounts per user request.\n\nThis setting reduces inconvenience for benign users and overhead on administrators, while also severely slowing down any brute force password attacks."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi should have account lockout period set to 90 minutes for ENS Classification Level High"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nhasProperAccountUnlockTime {\n\toption := input.Config.option[_]\n\tlower(option.key) == \"security.accountunlocktime\"\n   \toption.value == 5400\n}\n\nresult = \"fail\" {\n\tnot hasProperAccountUnlockTime\n}\n\ncurrentConfiguration := \"Security.AccountUnlockTime is not set to 5400\"\nexpectedConfiguration := \"Security.AccountUnlockTime should be set to 5400\""
  remediation_instructions = "Perform the following command to set the account lockout to 90 minutes via PowerCLI:  \n  \n```  \nGet-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime | Set-AdvancedSetting -Value 5400  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp3r1_1" {
  description              = "This rule checks whether Network Time Protocol (NTP) synchronization is enabled on the ESXi host.\n\nThis rule fails if `DateTimeInfo.Enabled` is set to `null`. \n\nEnabling Network Time Protocol (NTP) synchronization ensures accurate time for system event logs. The time sources used by the ESXi hosts should be in sync with an agreed-upon time standard such as UTC.\n\nBy ensuring that all systems use the same relative time source and that the relative time source can be correlated to an agreed-upon time standard, it is simpler to track and correlate an intruder's actions when reviewing the relevant log files. Incorrect time settings can also make auditing inaccurate."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host NTP time synchronization should be enabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nresult = \"fail\" {\n\tis_null(input.Config.dateTimeInfo.enabled)\n}\n\ncurrentConfiguration := \"DateTimeInfo.NtpConfig is Null\"\nexpectedConfiguration := \"DateTimeInfo.NtpConfig should be set to True\""
  remediation_instructions = "Perform the following command to enable NTP synchronization, via PowerCLI:  \n  \n```  \n$NTPServers = \"pool.ntp.org\", \"pool2.ntp.org\"  \nGet-VMHost | Add-VmHostNtpServer $NTPServers  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_acc5r3_3" {
  description              = "This rule checks whether the ESXi host is configured to enforce a 45 day password rotation policy\n\nThis rule fails if `Security.PasswordMaxDays` is set to any value higher than 45 "
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi should  enforce a 45 day password rotation policy  for ENS Classification Level High"
  opa_policy               = "# AI generated Rego code: ESXi should  enforce 45 day password rotation policy\npackage wiz\n\ndefault result = \"pass\"\n\nresult = \"fail\" {\n    not has_password_rotation_policy\n}\n\nhas_password_rotation_policy {\n    option := input.Config.option[_]\n    lower(option.key) == \"Security.PasswordMaxDays\"\n    to_number(option.value) <= 45\n}\n\ncurrentConfiguration := sprintf(\"Password rotation policy is set to %s days\", [input.Config.option[i].value]) {\n    input.Config.option[i].key == \"Security.PasswordMaxDays\"\n}\n\nexpectedConfiguration := \"Password rotation policy should be set to 45 days or less\""
  remediation_instructions = "Perform the following command to set a password policy via PowerCLI:\n\n```  \nGet-VMHost -Name {{ESXiHost}} | Get-AdvancedSetting Security.PasswordMaxDays | Set-AdvancedSetting -Value 45\n```\n"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_acc5r1_2" {
  description              = "This rule checks whether the account lockout period is set to 30 minutes.\n\nThis rule fails if `Security.AccountUnlockTime` is set to any value other than 1800.\n\nAn account is automatically locked after the maximum number of failed consecutive login attempts is reached. The account should be automatically unlocked after 15 minutes. Otherwise, administrators will need to manually unlock accounts per user request.\n\nThis setting reduces inconvenience for benign users and overhead on administrators, while also severely slowing down any brute force password attacks."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi should have account lockout period set to 30 minutes for ENS Classification Level Basic"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nhasProperAccountUnlockTime {\n\toption := input.Config.option[_]\n\tlower(option.key) == \"security.accountunlocktime\"\n   \toption.value == 1800\n}\n\nresult = \"fail\" {\n\tnot hasProperAccountUnlockTime\n}\n\ncurrentConfiguration := \"Security.AccountUnlockTime is not set to 1800\"\nexpectedConfiguration := \"Security.AccountUnlockTime should be set to 1800\""
  remediation_instructions = "Perform the following command to set the account lockout to 30 minutes via PowerCLI:  \n  \n```  \nGet-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime | Set-AdvancedSetting -Value 1800  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp8r2_1" {
  description              = "This rule checks whether the ESXi host is configured with informational logging level.\n\nThis rule fails if `Config.HostAgent.log.level` is not set to `info`. \n\nIt is recommended to ensure that informational logging level is set in order to ensure that enough information is present in audit logs for diagnostics and forensics."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host should have an informational logging level"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nhasInfoLogLevel {\n\toption := input.Config.option[_]\n\tlower(option.key) == \"config.hostagent.log.level\"\n   \tlower(option.value) == \"info\"\n}\n\nresult = \"fail\" {\n\tnot hasInfoLogLevel\n}\n\ncurrentConfiguration := \"Config.HostAgent.log.level is not set to info\"\nexpectedConfiguration := \"Config.HostAgent.log.level should be set to info\""
  remediation_instructions = "Perform the following command to set the logging level via PowerCLI:\n\n```\nGet-VMHost -Name {{ESXiHost}} | Get-AdvancedSetting Config.HostAgent.log.level | Set-AdvancedSetting -Value info\n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_acc6r3_2" {
  description              = "This rule checks whether the ESXi host has a proper idle timeout configured for shell and SSH sessions.\n\nThis rule fails if `UserVars.ESXiShellInteractiveTimeOut` is set to 600 or less.\n\nThe `ESXiShellInteractiveTimeOut` allows automatically terminating idle ESXi shell and SSH sessions. The permitted idle time should be 600 seconds or less.\n\nIf a user forgets to log out of an ESXi shell or SSH session, the idle session will exist indefinitely, increasing the potential for someone to gain unauthorized privileged access to the host, unless a timeout is set."
  enabled                  = true
  function_as_control      = false
  name                     = "Idle ESXi host shell and SSH sessions should time out after 600 seconds or less  for ENS Classification Level High"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nhasIdleTimeout {\n\toption := input.Config.option[_]\n\tlower(option.key) == \"uservars.esxishellinteractivetimeout\"\n   \toption.value <= 600\n    option.value > 0 # 0 indicates a disabled state\n}\n\nresult = \"fail\" {\n\tnot hasIdleTimeout\n}\n\ncurrentConfiguration := \"UserVars.ESXiShellInteractiveTimeOut is disabled or higher than 600\"\nexpectedConfiguration := \"UserVars.ESXiShellInteractiveTimeOut should be set to 600 or less\""
  remediation_instructions = "Perform the following command to set shell and SSH idle timeout via PowerCLI:  \n  \n```  \nGet-VMHost | Get-AdvancedSetting -Name 'UserVars.ESXiShellInteractiveTimeOut' | Set-AdvancedSetting -Value \"600\"  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp2r1_4" {
  description              = "This rule checks whether Managed Object Browser (MOB) is enabled.\n\nThis rule fails if `Config.HostAgent.plugins.solo.enableMob` is set to `true`.\n\nThe Managed Object Browser (MOB) is a web-based server application that lets you examine objects that exist on the server side, explore the object model used by the VM kernel to manage the host, and change configurations. It is installed and started automatically when vCenter is installed.\n\nWhile it is meant to be used primarily for debugging the vSphere SDK, the MOB could also be used as a method to obtain information about a host being targeted for unauthorized access, as there are no access controls. Thus, it is recommended to leave the MOB disabled."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host Managed Object Browser (MOB) should be disabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nmobEnabled {\n\toption := input.Config.option[_]\n\tlower(option.key) == \"config.hostagent.plugins.solo.enablemob\"\n   \toption.value == true\n}\n\nresult = \"fail\" {\n\tmobEnabled\n}\n\ncurrentConfiguration := \"Config.HostAgent.plugins.solo.enableMob is set to True\"\nexpectedConfiguration := \"Config.HostAgent.plugins.solo.enableMob should be set to False\""
  remediation_instructions = "Perform the following steps to disable MOB via vSphere portal:  \n  \n1. Select a host  \n2. Click `Configure`, expand `System`, and select `Advanced System Settings`.  \n3. Click `Edit` and search for `Config.HostAgent.plugins.solo.enableMob`  \n4. Set the value to `false`.  \n5. Click `OK`.  \n  \n>**Note**  \nMOB cannot be disabled while a host is in lockdown mode."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_acc5r3_1" {
  description              = "This rule checks whether the ESXi host is configured with a proper user password policy.\n\nThis rule fails if `Security.PasswordQualityControl` is set to any value lower than `retry=3 min=disabled,disabled,disabled,disabled,12 max=64 similar=deny passphrase=3`.\n\nFor syntax specification, please refer to VMware [guidelines on ESXi passwords](https://docs.vmware.com/en/VMware-vSphere/7.0/com.vmware.vsphere.hostclient.doc/GUID-EA3DF94F-7CCD-4F27-BA41-8EB0D4DFFE69.html).\n\nWhen set, this setting enforces required password length and character class requirements, to ensure only secure passwords can be used."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host password policy should be set for ENS Classification Level High"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nhasPasswordQualityControl {\n\toption := input.Config.option[_]\n\tlower(option.key) == \"security.passwordqualitycontrol\"\n   \tlower(option.value) == \"retry=3 min=disabled,disabled,disabled,disabled,12 max=64 similar=deny passphrase=3\"\n}\n\nresult = \"fail\" {\n\tnot hasPasswordQualityControl\n}\n\ncurrentConfiguration := \"Security.PasswordQualityControl is not set to properly\"\nexpectedConfiguration := \"Security.PasswordQualityControl should be set\""
  remediation_instructions = "Perform the following command to set a password policy via PowerCLI:\n\n```  \nGet-VMHost -Name {{ESXiHost}} | Get-AdvancedSetting Security.PasswordQualityControl | Set-AdvancedSetting -Value \"retry=3 min=disabled,disabled,disabled,disabled,12 max=64 similar=deny passphrase=3\"\n```\n"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_acc5r1_5" {
  description              = "This rule checks whether the ESXi host is configured to enforce a 90 day password rotation policy\n\nThis rule fails if `Security.PasswordMaxDays` is set to any value higher than 90 "
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi should  enforce a 90 day password rotation policy  for ENS Classification Level Basic"
  opa_policy               = "# AI generated Rego code: ESXi should  enforce a 90 day password rotation policy\npackage wiz\n\ndefault result = \"pass\"\n\nresult = \"fail\" {\n    not has_password_rotation_policy\n}\n\nhas_password_rotation_policy {\n    option := input.Config.option[_]\n    lower(option.key) == \"Security.PasswordMaxDays\"\n    to_number(option.value) <= 90\n}\n\ncurrentConfiguration := sprintf(\"Password rotation policy is set to %s days\", [input.Config.option[i].value]) {\n    input.Config.option[i].key == \"Security.PasswordMaxDays\"\n}\n\nexpectedConfiguration := \"Password rotation policy should be set to 90 days or less\""
  remediation_instructions = "Perform the following command to set a password policy via PowerCLI:\n\n```  \nGet-VMHost -Name {{ESXiHost}} | Get-AdvancedSetting Security.PasswordMaxDays | Set-AdvancedSetting -Value 90\n```\n"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp2r1_15" {
  description              = "This rule checks whether PCI device passthrough is disabled.\n\nThis rule fails if `pciPassthru*.present` is not empty.\n\nUsing the VMware DirectPath I/O feature to pass through a PCI or PCIe device to a virtual machine can result in a potential security vulnerability.\n\nThe vulnerability can be triggered by buggy or malicious code running in privileged mode in the guest OS, such as a device driver."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host PCI and PCIe device passthrough should be disabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\npciPassthruDisabled {\n\tconfigItem := input.Config.extraConfig[_]\n    lower(configItem.key) == \"pcipassthru*.present\"\n    configItem.value == \"\"\n}\n\nresult = \"fail\" {\n\tnot pciPassthruDisabled\n}\n\ncurrentConfiguration := \"pciPassthru*.present is not set\"\nexpectedConfiguration := \"pciPassthru*.present should be set to none\""
  remediation_instructions = "Perform the following command via PowerCLI:  \n  \n```  \nGet-VM | New-AdvancedSetting -Name \"pciPassthru*.present\" -value \"\"  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#virtualMachine"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp2r1_11" {
  description              = "This rule checks whether virtual disk wiping is disabled.\n\nThis rule fails if `isolation.tools.diskWiper.disable` is not set to `TRUE`. \n\nWiping a virtual disk reclaims all unused space in it. If there is empty space in the disk, this process reduces the amount of space the virtual disk occupies on the host drive. If virtual disk wiping is done repeatedly, it can cause the virtual disk to become unavailable while wiping occurs.\n\nIn most data center environments, disk wiping is not needed, but normal users and processes - without administrative privileges - can issue disk wipes unless the feature is disabled.\n\nVirtual disk wiping can effectively cause a denial of service."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host virtual disk wiping should be disabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\ndiskWiperDisabled {\n\tconfigItem := input.Config.extraConfig[_]\n    lower(configItem.key) == \"isolation.tools.diskwiper.disable\"\n    upper(configItem.value) == \"TRUE\"\n}\n\nresult = \"fail\" {\n\tnot diskWiperDisabled\n}\n\ncurrentConfiguration := \"isolation.tools.diskWiper.disable is enabled\"\nexpectedConfiguration := \"isolation.tools.diskWiper.disable should be disabled\""
  remediation_instructions = "Perform the following command to disable virtual disk wiping via PowerCLI:  \n  \n```  \nGet-VM | New-AdvancedSetting -Name \"isolation.tools.diskWiper.disable\" -value $true  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#virtualMachine"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp2r1_18" {
  description              = "This rule checks whether the ESXi host has SNMP service enabled.\n\nThis rule fails if the service policy of `snmpd` is set to `on` or `running` is set to `true`.\n\nSimple Network Management Protocol (SNMP) is commonly used by management programs to monitor a variety of networked devices.\n\nIf SNMP is not properly configured, monitoring information can be sent to a malicious host. The malicious host might use this information for malicious purposes.\n\nIf not used, the `snmpd` service should be disabled."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host SNMP service should be disabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nisServiceEnabled(service) {\n   \tlower(service.policy) == \"on\"\n} {\n\tservice.running == true\n}\n\nresult = \"fail\" {\n\tservice := input.Config.service.service[_]\n    lower(service.key) == \"snmpd\"\n\tisServiceEnabled(service)\n}\n\ncurrentConfiguration := \"snmpd service is runnning or its policy is set to on\"\nexpectedConfiguration := \"snmpd should be disabled\"\n"
  remediation_instructions = "Perform the following command to set a password policy via PowerCLI:\n\n```\nGet-VMHostService -VMHost {{ESXiHost}} | where {$_.Key -eq 'snmpd'} | Set-VMHostService -Policy Off\nGet-VMHostService -VMHost {{ESXiHost}} | where {$_.Key -eq 'snmpd'} | Stop-VMHostService\n```\n"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp2r1_6" {
  description              = "This rule checks whether the ESXi host BPDU filter is enabled.  \nThis rule fails if `Net.BlockGuestBPDU` is set to `0`.   \nBPDU Guard and Portfast are commonly enabled on the physical switch to which the ESXi host is directly connected to reduce the spanning tree convergence delay.   \nIf a BPDU packet is sent from a virtual machine on the ESXi host to the physical switch configured, a cascading lockout of all the uplink interfaces from the ESXi host can occur.  \nTo prevent this type of lockout, BPDU Filter can be enabled on the ESXi host to drop any BPDU packets being sent to the physical switch.\n"
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host BPDU filter should be enabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nBDPUDisabled {\n\toption := input.Config.option[_]\n\tlower(option.key) == \"net.blockguestbpdu\"\n   \toption.value == 0\n}\n\nresult = \"fail\" {\n\tBDPUDisabled\n}\n\ncurrentConfiguration := \"Net.BlockGuestBPDU is set to 0\"\nexpectedConfiguration := \"Net.BlockGuestBPDU should be set to 1\"\n"
  remediation_instructions = "Perform the following command to enable BPDU filter via PowerCLI:\n\n```\nGet-VMHost -Name {{ESXiHost}} | Get-AdvancedSetting Net.BlockGuestBPDU | Set-AdvancedSetting -Value 1\n```\n"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp2r1_3" {
  description              = "This rule checks whether vSwitch Promiscuous Mode policy is set to reject.\n\nThis rule fails if `AllowPromiscuous` is set to `true`. \n\nWhen promiscuous mode is enabled for a virtual switch, all virtual machines connected to the dvPortgroup have the potential of reading all packets crossing that network. \nThis could enable unauthorized access to the contents of those packets."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host vSwitch promiscuous mode policy should be set to reject"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nresult = \"fail\" {\n\tinput.Config.network.vswitch[_].spec.policy.security.allowPromiscuous == true\n}\n\ncurrentConfiguration := \"AllowPromiscuous is set to Accept\"\nexpectedConfiguration := \"AllowPromiscuous should be set to Reject\""
  remediation_instructions = "Perform the following command to set the policy to reject, perform the following via PowerCLI:  \n  \nAlternatively, perform the following via ESXi shell:  \n  \n```  \nesxcli network vswitch standard policy security set -v vSwitch2 -p false  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp8r2_4" {
  description              = "This rule checks whether log file size is limited.\n\nThis rule fails if `log.rotateSize` is not set to `8192000`. \n\nA new log file is created only when a host is rebooted, so the file can grow to be quite large. You can ensure that new log files are created more frequently by limiting the maximum size of the log files. \n\nTo restrict the total size of logging data, VMware recommends saving 10 log files, each one limited to 1 MB. If the maximum number of log files already exists, when a new one is created, the oldest log file is deleted.\n\nVirtual machine users and processes can abuse logging either on purpose or inadvertently, so that large amounts of data flood the log file. \n\nWithout restrictions on maximum log file size, over time a log file can consume enough file system space to cause a denial of service."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host should restrict VM log file size to 8M  for ENS Classification Level  Medium |High "
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nproperRotation {\n\tconfigItem := input.Config.extraConfig[_]\n    lower(configItem.key) == \"log.rotatesize\"\n    configItem.value == \"8192000\"\n}\n\nresult = \"fail\" {\n\tnot properRotation\n}\n\ncurrentConfiguration := \"log.rotateSize is not set to '8192000'\"\nexpectedConfiguration := \"log.rotateSize should be set to '8192000'\""
  remediation_instructions = "Perform the following command to limit the maximum log file size via PowerCLI:  \n  \n```  \nGet-VM | New-AdvancedSetting -Name \"log.rotateSize\" -value \"8192000\"  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["vsphere#virtualMachine"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp2r1_14" {
  description              = "This rule checks whether informational messages are limited.\n\nThis rule fails if `tools.setInfo.sizeLimit` is missing.\n\nIt is recommended to limit informational messages from the virtual machine to the virtual machine extensions file to avoid filling the datastore. The configuration file containing these name-value pairs is limited to a size of 1 MB by default.\n\nFilling the datastore with informational messages from the VM to the VMX file could cause a denial of service."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host should restrict informational messages"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\ninfoMsgRestricted {\n\tconfigItem := input.Config.extraConfig[_]\n    lower(configItem.key) == \"tools.setinfo.sizelimit\"\n}\n\nresult = \"fail\" {\n\tnot infoMsgRestricted\n}\n\ncurrentConfiguration := \"tools.setInfo.sizeLimit is not set\"\nexpectedConfiguration := \"tools.setInfo.sizeLimit should be set\""
  remediation_instructions = "Perform the following command via PowerCLI:  \n  \n```  \nGet-VM | New-AdvancedSetting -Name \"tools.setInfo.sizeLimit\" -value 1048576  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["vsphere#virtualMachine"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp2r1_5" {
  description              = "This rule checks whether the ESXi virtual machine has TPS memory sharing enabled.\n\nThis rule fails if `sched.mem.pshare.salt` is set.\n\nTransparent Page Sharing (TPS) is a method to reduce the memory footprint of virtual machines. Under highly controlled conditions, it can be used to gain unauthorized access to data on neighboring virtual machines. VMs that do not have the `sched.mem.pshare.salt` option set cannot share memory with any other VMs, making it more secure."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi virtual machine should restrict memory sharing between VMs"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nmemoryShared {\n\tconfigItem := input.Config.extraConfig[_]\n    lower(configItem.key) == \"sched.mem.pshare.salt\"\n}\n\nresult = \"fail\" {\n\tmemoryShared\n}\n\ncurrentConfiguration := \"sched.mem.pshare.salt is set\"\nexpectedConfiguration := \"sched.mem.pshare.salt should not be set\""
  remediation_instructions = "Perform the following command to restrict memory sharing via PowerCLI:\n\n```\nGet-VM -Name {{VMName}} | Remove-AdvancedSetting -Name sched.mem.pshare.salt\n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#virtualMachine"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp2r1_13" {
  description              = "This rule checks whether unauthorized modification and disconnection of devices are disabled.\n\nThis rule fails if `isolation.device.edit.disable` is not set to `TRUE`.\n\nIn a virtual machine, users and processes without root or administrator privileges can disconnect devices, such as network adapters and CD-ROM drives, and modify device settings within the guest operating system.\n\nDisabling unauthorized modification and disconnection of devices helps prevent unauthorized changes within the guest operating system, which could be used to gain unauthorized access, cause denial of service conditions, and otherwise negatively affect the security of the guest operating system."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi virtual machine unauthorized modification of devices should be disabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\ndeviceModificationsDisabled {\n\tconfigItem := input.Config.extraConfig[_]\n    lower(configItem.key) == \"isolation.device.edit.disable\"\n    upper(configItem.value) == \"TRUE\"\n}\n\nresult = \"fail\" {\n\tnot deviceModificationsDisabled\n}\n\ncurrentConfiguration := \"isolation.device.edit.disable is not set to TRUE\"\nexpectedConfiguration := \"isolation.device.edit.disable should be set to TRUE\""
  remediation_instructions = "Perform the following command to prevent unauthorized device modifications and disconnections via PowerCLI:  \n  \n```  \nGet-VM | New-AdvancedSetting -Name \"isolation.device.edit.disable\" -value $true  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#virtualMachine"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp2r1_8" {
  description              = "This rule checks whether VM console paste operations are disabled.\n\nThis rule fails if `isolation.tools.paste.disable` is not set to `True`.\n\nBy default, the ability to copy and paste text, graphics, and files is disabled. When enabled, you can copy and paste rich text, and depending on the VMware product, graphics and files from your clipboard to the guest operating system in a virtual machine. Non-privileged users and processes running in the virtual machine can access the clipboard on the computer where the console window is running.\n\nTo avoid risks associated with this feature, it is recommended to disable paste operations."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi virtual machine console paste operations should be disabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\npasteOperationsEnabled {\n\tconfigItem := input.Config.extraConfig[_]\n    lower(configItem.key) == \"isolation.tools.paste.disable\"\n    upper(configItem.value) != \"TRUE\"\n}\n\nresult = \"fail\" {\n\tpasteOperationsEnabled\n}\n\ncurrentConfiguration := \"isolation.tools.paste.disable is not set to TRUE\"\nexpectedConfiguration := \"isolation.tools.paste.disable should be set to TRUE\""
  remediation_instructions = "Perform the following command to disable VM console paste operations via PowerCLI:  \n  \n```  \nGet-VM | New-AdvancedSetting -Name \"isolation.tools.paste.disable\" -value $true  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#virtualMachine"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_acc6r3_1" {
  description              = "This rule checks whether idle timeout for shell and SSH services is configured with a proper value of one hour or less.\n\nThis rule fails if `UserVars.ESXiShellTimeOut` is set to a value higher than `600`.\n\nWhen the ESXi shell or SSH services are enabled on a host, they will run indefinitely. To avoid this, `ESXiShellTimeOut` can be set, which defines a window of time after which the ESXi shell and SSH services will automatically be terminated.\n\nThis reduces the risk of an inactive ESXi shell or SSH service being misused by an unauthorized party to compromise a host."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi shell services should have a timeout value of 1o minutes for for ENS Classification Level High"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nhasIdleServiceTimeout {\n\toption := input.Config.option[_]\n\tlower(option.key) == \"uservars.esxishelltimeout\"\n   \toption.value <= 600\n    option.value > 0 # 0 indicates a disabled state\n}\n\nresult = \"fail\" {\n\tnot hasIdleServiceTimeout\n}\n\ncurrentConfiguration := \"UserVars.ESXiShellTimeOut is disabled or higher than 600\"\nexpectedConfiguration := \"UserVars.ESXiShellTimeOut should be set to 600 or less\""
  remediation_instructions = "Perform the following command to set idle timeout for shell services via PowerCLI:  \n  \n```  \nGet-VMHost | Get-AdvancedSetting -Name 'UserVars.ESXiShellTimeOut' | Set-AdvancedSetting -Value \"600\"  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp2r1_16" {
  description              = "This rule checks whether VMware Tools is configured to disable sending host information to guests.\n\nThis rule fails if `tools.guestlib.enableHostInfo` is not set to `FALSE`. \n\nConfigure VMware Tools to disable host information from being sent to guests unless a particular VM requires this information for performance monitoring purposes.\n\nBy enabling a VM to get detailed information about the physical host, an adversary could potentially use this information to inform further attacks on the host."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host information should not be sent to guests"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nhostInfoNotSent {\n\tconfigItem := input.Config.extraConfig[_]\n    lower(configItem.key) == \"tools.guestlib.enablehostinfo\"\n    upper(configItem.value) == \"FALSE\"\n}\n\nresult = \"fail\" {\n\tnot hostInfoNotSent\n}\n\ncurrentConfiguration := \"tools.guestlib.enableHostInfo is enabled\"\nexpectedConfiguration := \"tools.guestlib.enableHostInfo should be disabled\""
  remediation_instructions = "Perform the following command to prevent host information from being sent to guests via PowerCLI:  \n  \n```  \nGet-VM | New-AdvancedSetting -Name \"tools.guestlib.enableHostInfo\" -value $false  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#virtualMachine"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_acc5r2_3" {
  description              = "This rule checks whether the ESXi host is configured to enforce a 60 day password rotation policy\n\nThis rule fails if `Security.PasswordMaxDays` is set to any value higher than 60 "
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi should  enforce a 60 day password rotation policy  for ENS Classification Level Medium"
  opa_policy               = "# AI generated Rego code: ESXi should  enforce 60 day password rotation policy\npackage wiz\n\ndefault result = \"pass\"\n\nresult = \"fail\" {\n    not has_password_rotation_policy\n}\n\nhas_password_rotation_policy {\n    option := input.Config.option[_]\n    lower(option.key) == \"Security.PasswordMaxDays\"\n    to_number(option.value) <= 60\n}\n\ncurrentConfiguration := sprintf(\"Password rotation policy is set to %s days\", [input.Config.option[i].value]) {\n    input.Config.option[i].key == \"Security.PasswordMaxDays\"\n}\n\nexpectedConfiguration := \"Password rotation policy should be set to 60 days or less\""
  remediation_instructions = "Perform the following command to set a password policy via PowerCLI:\n\n```  \nGet-VMHost -Name {{ESXiHost}} | Get-AdvancedSetting Security.PasswordMaxDays | Set-AdvancedSetting -Value 60\n```\n"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_mpcom3r1_1" {
  description              = "This rule checks whether bidirectional CHAP authentication is used.\n\nThis rule fails if `ChapAuthenticationType` is set to `chapRequired`.\n\nvSphere allows for the use of bidirectional authentication of both the iSCSI target and host. Bidirectional Challenge-Handshake Authentication Protocol (CHAP), also known as Mutual CHAP, should be enabled to provide bidirectional authentication.\n\nBy not authenticating both the iSCSI target and host, there is a potential for a man-in-the-middle attack in which an attacker might impersonate either side of the connection to steal data. Bidirectional authentication can mitigate this risk."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host iSCSI bidirectional CHAP authentication should be enabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nresult = \"fail\" {\n\tauthProperties := input.Config.storageDevice.hostBusAdapter[_].authenticationProperties\n\tauthProperties.chapAuthEnabled\n\tlower(authProperties.chapAuthenticationType) == \"chaprequired\"\n}\n\ncurrentConfiguration := \"chapRequired is not set\"\nexpectedConfiguration := \"chapRequired should be set\""
  remediation_instructions = "Perform the following command to enable bidirectional CHAP authentication for iSCSI traffic via PowerCLI:  \n  \n```  \nGet-VMHost | Get-VMHostHba | Where {$_.Type -eq \"Iscsi\"} | Set-VMHostHba  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp8r2_3" {
  description              = "This rule checks whether the ESXi host logging is configured with a persistent datastore.\n\nThis rule fails if the value of `Syslog.global.LogDir` is empty or contains `scratch`.\n\nESXi can be configured to store log files on an in-memory file system. This occurs when `Syslog.global.LogDir` is set to a non-persistent location, such as `/scratch`. When this is done, only a single day's worth of logs is stored. Additionally, log files are reinitialized on each reboot.\n\nNon-persistent logging presents a security risk as user activity logged on the host is only stored temporarily and is not preserved across reboots, which can complicate auditing and make it harder to monitor events and diagnose issues.\n\nESXi host logging should be configured with a persistent datastore."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi should be configured with persistent logging"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nhasPersistentLogging {\n\toption := input.Config.option[_]\n\tlower(option.key) == \"syslog.global.logdir\"\n   \toption.value != \"\"\n    not contains(lower(option.value), \"scratch\")\n}\n\nresult = \"fail\" {\n\tnot hasPersistentLogging\n}\n\ncurrentConfiguration := \"Syslog.global.logDir is empty or pointing to a temporary location\"\nexpectedConfiguration := \"Syslog.global.logDir should be set to a persistent location\""
  remediation_instructions = "Perform the following command to configure persistent logging via PowerCLI:  \n  \n```  \nGet-VMHost | Foreach { Set-AdvancedConfiguration -VMHost $_ -Name Syslog.global.logDir -Value \"<NewLocation>\" }  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp2r1_7" {
  description              = "This rule checks whether VM console copy operations are enabled.\n\nThis rule fails if `isolation.tools.copy.disable` is not set to `TRUE`.\n\nBy default, the ability to copy and paste text, graphics, and files is disabled. When enabled, you can copy and paste rich text, and depending on the VMware product, graphics and files from your clipboard to the guest operating system in a virtual machine. Non-privileged users and processes running in the virtual machine can access the clipboard on the computer where the console window is running.\n\nTo avoid risks associated with this feature, it is recommended to disable copy operations."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi virtual machine console copy operations should be disabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\ncopyOperationsEnabled {\n\tconfigItem := input.Config.extraConfig[_]\n    lower(configItem.key) == \"isolation.tools.copy.disable\"\n    upper(configItem.value) != \"TRUE\"\n}\n\nresult = \"fail\" {\n\tcopyOperationsEnabled\n}\n\ncurrentConfiguration := \"isolation.tools.copy.disable is not set to TRUE\"\nexpectedConfiguration := \"isolation.tools.copy.disable should be set to TRUE\""
  remediation_instructions = "Perform the following command to explicitly disable VM console copy operations via PowerCLI:  \n  \n```  \nGet-VM | New-AdvancedSetting -Name \"isolation.tools.copy.disable\" -value $true  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#virtualMachine"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp2r1_17" {
  description              = "This rule checks whether SSH is enabled on the ESXi host.\n\nThis rule fails if the `TSM-SSH` service policy is set to `on`\n\nThe ESXi shell, when enabled, can be accessed directly from the host console through the DCUI or remotely using SSH. Disabling SSH for the ESXi host helps prevent remote access to the ESXi shell. Only enable SSH when needed for troubleshooting or diagnostics.\n\nRemote access to the host should be limited to the vSphere Client, remote command-line tools (vCLI/PowerCLI), and through the published APIs.\n\nIt is recommended that remote access to the host using SSH should be disabled."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi SSH should be disabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nsshEnabled {\n\tservice := input.Config.service.service[_]\n\tupper(service.key) == \"TSM-SSH\"\n   \tlower(service.policy) == \"on\"\n}\n\nresult = \"fail\" {\n\tsshEnabled\n}\n\ncurrentConfiguration := \"TSM-SSH service policy is set to on\"\nexpectedConfiguration := \"TSM-SSH service policy should be set to off\""
  remediation_instructions = "Perform the following command to disable SSH via PowerCLI:  \n  \n```  \nGet-VMHost | Get-VMHostService | Where { $_.key -eq \"TSM-SSH\" } | Set-VMHostService -Policy Off  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}

resource "wiz_cloud_configuration_rule" "ccn_442_opexp2r1_2" {
  description              = "This rule checks whether MAC Address Change policy is set to reject.\n\nThis rule fails if `MacChanges` is set to `true`. \n\nIf the virtual machine operating system changes the MAC address, it can send frames with an impersonated source MAC address at any time. This allows it to stage malicious attacks on the devices in a network by impersonating a network adapter authorized by the receiving network."
  enabled                  = true
  function_as_control      = false
  name                     = "ESXi host vSwitch MAC address change policy should be set to reject"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nresult = \"fail\" {\n\tinput.Config.network.vswitch[_].spec.policy.security.macChanges == true\n}\n\ncurrentConfiguration := \"MacChanges is set to Accept\"\nexpectedConfiguration := \"MacChanges should be set to Reject\""
  remediation_instructions = "Perform the following command to set the policy to reject, perform the following via PowerCLI:  \n  \n```  \nesxcli network vswitch standard policy security set -v vSwitch2 -m false  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["vsphere#hostSystem"]
}
