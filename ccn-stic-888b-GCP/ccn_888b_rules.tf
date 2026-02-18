
resource "wiz_cloud_configuration_rule" "ccn_888b_op_exp_11_1" {
  description              = "This rule checks if the Storage Bucket storage service is using a Customer-managed key for encryption.  \nThis rule fails when the `encryption.defaultKmsKeyName` does not exist.   \nUsing Customer-managed keys provides additional capabilities to control rotation of the key encryption key or cryptographically erase data.  \nIt is recommended to specify a Customer-managed key, in order to prevent performing actions such as reading metadata, listing objects, and deleting objects even after disabling or destroying the associated Customer-managed encryption key."
  enabled                  = true
  function_as_control      = false
  name                     = "Bucket should be encrypted with a customer-managed key"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nresult = \"fail\" {\n\tnot input.encryption.defaultKmsKeyName\n}\n\ncurrentConfiguration := \"defaultKmsKeyName is missing\"\nexpectedConfiguration := \"Customer managed encryption key should be configured\"\n"
  remediation_instructions = "Follow these steps to set Customer-managed encryption key for the bucket:  \n  \n1. Sign in to the GCP and navigate to storage dashboard <https://console.cloud.google.com/storage>  \n2. Select the desired project and bucket and go to 'CONFIGURATION'  \n3. Go to 'Encryption Type' and click the edit icon (pencil).  \n4. Click on 'Customer-managed encryption key (CMEK)' and then select the desired customer managed key.  \n5. Click 'Save'."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["storage#bucket"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.common as common_lib\nimport data.generic.terraform as terraLib\n\nencryptionBlockNotExist(storageBucket) {\n\tnot common_lib.valid_key(storageBucket, \"encryption\")\t\n}{\n\tcount(storageBucket.encryption) < 1\n}\n\nWizPolicy[result] {\n\tstorageBucket := input.document[i].resource.google_storage_bucket[name]\n\t\n\tencryptionBlockNotExist(storageBucket)\n    \n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceType\": \"google_storage_bucket\",\n\t\t\"resourceName\": terraLib.get_resource_name(storageBucket, name),\n\t\t\"searchKey\": sprintf(\"google_storage_bucket[%s]\", [name]),\n\t\t\"issueType\": \"MissingAttribute\",\n\t\t\"keyExpectedValue\": sprintf(\"google_storage_bucket[%s].encryption.default_kms_key_name should be defined and not null\", [name]),\n\t\t\"keyActualValue\": sprintf(\"google_storage_bucket[%s].encryption.default_kms_key_name is undefined or null\", [name]),\n\t\t\"remediation\": \"encryption.default_kms_key_name is defined\",\n\t\t\"remediationType\": \"addition\",\n\t\t\"resourceTags\": terraLib.get_resource_labels(storageBucket),\n\t}\n}\n"
    remediation_instructions = "```\nresource \"google_storage_bucket\" \"example_bucket\" {\n  encryption {\n    default_kms_key_name = \"<your_kms_key>\" // Replace with your KMS key\n  }\n}\n```\n"
    type                     = "TERRAFORM"
  }
}



resource "wiz_custom_control" "ccn_888b_op_acc_1_3" {
  description               = "This user has active access keys that have been unused for over 90 days. Access keys are long-term credentials for an IAM user.\n\nThe long term access keys can be used for longer periods of time. Therefore, an attacker with access to the keys will have persistent access to the user."
  enabled                   = true
  name                      = "User with access keys that have been unused for over 90 days "
  project_id                = "*"
  query                     = "{\"relationships\":[{\"type\":[{\"type\":\"OWNS\"}],\"with\":{\"select\":true,\"type\":[\"ACCESS_KEY\"]}},{\"type\":[{\"reverse\":true,\"type\":\"CONTAINS\"}],\"with\":{\"select\":true,\"type\":[\"SUBSCRIPTION\"]}}],\"select\":true,\"type\":[\"USER_ACCOUNT\"],\"where\":{\"nativeType\":{\"EQUALS\":[\"user\",\"rootUser\"]},\"userDirectory\":{\"EQUALS\":[\"GCP\"]}}}"
  resolution_recommendation = "### Remove unnecessary access\n* Remove or disable stale principals/keys.\n* Do not assign IAM identities to resources who do not require them."
  scope_query               = "{\"type\":[\"USER_ACCOUNT\"]}"
  security_sub_categories   = []
  severity                  = "LOW"
}

resource "wiz_custom_control" "ccn_888b_op_acc_4_1" {
  description               = "Reducing permissions on service accounts: By default, service accounts have the editor role. Excessive permissions increase security risks, so prioritizing service accounts is recommended."
  enabled                   = true
  name                      = "Service accounts with Excessive permissions "
  project_id                = "*"
  query                     = "{\"relationships\":[{\"type\":[{\"reverse\":true,\"type\":\"ALERTED_ON\"}],\"with\":{\"select\":true,\"type\":[\"EXCESSIVE_ACCESS_FINDING\"]}}],\"select\":true,\"type\":[\"SERVICE_ACCOUNT\"],\"where\":{\"userDirectory\":{\"EQUALS\":[\"GCP\"]}}}"
  resolution_recommendation = null
  scope_query               = "{\"type\":[\"SERVICE_ACCOUNT\"]}"
  security_sub_categories   = []
  severity                  = "HIGH"
}

resource "wiz_cloud_configuration_rule" "ccn_888b_op_com_2_1" {
  description              = "This rule checks whether the load balancer forwarding rule uses a secure SSL policy. The rule applies only to forwarding rules with an SSL policy.  \nThis rule skips forwarding rules that do not have an SSL policy.  \nThis rule fails if the forwarding rule SSL policy uses a TLS version lower than `1.2` or if it supports one of the following cipher suites which are considered insecure: `TLS_RSA_WITH_3DES_EDE_CBC_SHA`, `TLS_RSA_WITH_AES_128_CBC_SHA`, `TLS_RSA_WITH_AES_128_GCM_SHA256`, `TLS_RSA_WITH_AES_256_CBC_SHA`, `TLS_RSA_WITH_AES_256_GCM_SHA384`.  \nThe forwarding rule SSL policy defines the features of SSL permitted to use in the communication between clients and the load balancer.  \nIt is recommended to configure the forwarding rule SSL policy correctly to ensure the connections between clients and the load balancer are encrypted and safe."
  enabled                  = true
  function_as_control      = false
  name                     = "Load balancer forwarding rule should use a secure SSL policy"
  opa_policy               = "package wiz\n\ndefault result := \"pass\"\n\ninsecureCipher = {\n    \"TLS_RSA_WITH_3DES_EDE_CBC_SHA\",\n    \"TLS_RSA_WITH_AES_128_CBC_SHA\", \n    \"TLS_RSA_WITH_AES_128_GCM_SHA256\",\n    \"TLS_RSA_WITH_AES_256_CBC_SHA\", \n    \"TLS_RSA_WITH_AES_256_GCM_SHA384\"\n}\n\nusingInsecureCipherOrTlsVersion {\n    upper(input.sslPolicy.profile) == \"CUSTOM\"\n    insecureCipher[upper(input.sslPolicy.customFeatures[_])]\n}{\n    upper(input.sslPolicy.profile) == \"COMPATIBLE\"\n}{\n    upper(input.sslPolicy.minTlsVersion) != \"TLS_1_2\"\n}\n\nresult := \"skip\" {\n    is_null(input.sslPolicy)\n} else := \"fail\" {\n    usingInsecureCipherOrTlsVersion\n}\n\ncurrentConfiguration := \"SSL policy is not set or uses insecure cipher suites or TLS version lower than 1.2\"\nexpectedConfiguration := \"SSL policy should be set with secure cipher suites and TLS version 1.2 or higher\""
  remediation_instructions = "Perform the following command to apply a secure SSL policy to a load balancer forwarding rule via GCP CLI:    \n  \n### HTTPS load balancer  \n  \n```  \ngcloud compute target-https-proxies update {{targetProxy}} \\\n    --ssl-policy <secureSslPolicy>  \n```  \n  \n### SSL proxy load balancer  \n  \n```  \ngcloud compute target-ssl-proxies update {{targetProxy}} \\\n    --ssl-policy <secureSslPolicy>  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["compute#forwardingRule"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.common as common_lib\nimport data.generic.terraform as terraLib\n\nWizPolicy[result] {\n\tsslPolicy := input.document[i].resource.google_compute_ssl_policy[name]\n\tsslPolicy.min_tls_version != \"TLS_1_2\"\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceType\": \"google_compute_ssl_policy\",\n\t\t\"resourceName\": terraLib.get_resource_name(sslPolicy, name),\n\t\t\"searchKey\": sprintf(\"google_compute_ssl_policy[%s].min_tls_version\", [name]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"google_compute_ssl_policy[%s].min_tls_version should be TLS_1_2\", [name]),\n\t\t\"keyActualValue\": sprintf(\"google_compute_ssl_policy[%s].min_tls_version is not TLS_1_2\", [name]),\n\t\t\"searchLine\": common_lib.build_search_line([\"resource\", \"google_compute_ssl_policy\", name],[\"min_tls_version\"]),\n\t\t\"remediation\": json.marshal({\n\t\t\t\"before\": sprintf(\"%s\",[sslPolicy.min_tls_version]),\n\t\t\t\"after\": \"TLS_1_2\"\n\t\t}),\n\t\t\"remediationType\": \"update\",\n\t\t\"resourceTags\": terraLib.get_resource_labels(sslPolicy),\n\t}\n}\n\nWizPolicy[result] {\n\tsslPolicy := input.document[i].resource.google_compute_ssl_policy[name]\n\tnot common_lib.valid_key(sslPolicy, \"min_tls_version\")\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceType\": \"google_compute_ssl_policy\",\n\t\t\"resourceName\": terraLib.get_resource_name(sslPolicy, name),\n\t\t\"searchKey\": sprintf(\"google_compute_ssl_policy[%s].min_tls_version\", [name]),\n\t\t\"issueType\": \"MissingAttribute\",\n\t\t\"keyExpectedValue\": sprintf(\"google_compute_ssl_policy[%s].min_tls_version should be TLS_1_2\", [name]),\n\t\t\"keyActualValue\": sprintf(\"google_compute_ssl_policy[%s].min_tls_version is undefined\", [name]),\n\t\t\"searchLine\": common_lib.build_search_line([\"resource\", \"google_compute_ssl_policy\", name],[]),\n\t\t\"remediation\": \"min_tls_version = \\\"TLS_1_2\\\"\",\n\t\t\"remediationType\": \"addition\",\n\t\t\"resourceTags\": terraLib.get_resource_labels(sslPolicy),\n\t}\n}\n"
    remediation_instructions = "```\nresource \"google_compute_ssl_policy\" \"example_ssl_policy\" {\n  min_tls_version = \"TLS_1_2\"\n}\n```\n"
    type                     = "TERRAFORM"
  }
}

resource "wiz_cloud_configuration_rule" "ccn_888b_op_s_2_1" {
  description              = "This rule checks whether the WAF rule `json-sqli-canary` is configured in a Cloud Armor policy.  \nThis rule fails if the `json-sqli-canary` WAF rule is not configured in the Cloud Armor policy or its action is not set to `Deny`.  \nThe `json-sqli-canary` is a GCP preconfigured WAF rule that helps detect and block SQL injection attempts within JSON payloads. SQL injection is a common attack vector that can lead to unauthorized data access or manipulation.  \nIt is recommended to configure this WAF rule in your Cloud Armor policy to enhance protection against SQL injection attacks in JSON-based requests.\n \n**Note:**  \nThis rule is skipped for Cloud Armor Edge policies (`input.type` is `CLOUD_ARMOR_EDGE`).  \nCloud Armor Edge policies are evaluated at the Google network edge and support only limited filtering (IP and geography), so they don't support preconfigured WAF rules that require deep HTTP/HTTPS inspection (headers, query parameters, and body).  "
  enabled                  = true
  function_as_control      = false
  name                     = "Cloud Armor policy should be configured with 'json-sqli-canary' WAF rule"
  opa_policy               = "package wiz\n\ndefault result := \"pass\"\n\nruleExist {\n\tregex.match(\"evaluatePreconfigured(Waf|Expr)\\\\('json-sqli-canary'\",input.rules[i].match.expr.expression)\n\tregex.match(\"^deny\",input.rules[i].action)\n}\n\nresult := \"skip\" {\n\tlower(input.type) == \"cloud_armor_edge\"\n} else := \"fail\" {\n\tnot ruleExist\n}\n\ncurrentConfiguration := \"'json-sqli-canary' WAF rule is not configured in Cloud Armor Policy\"\nexpectedConfiguration := \"'json-sqli-canary' WAF rule should be configured in Cloud Armor Policy\""
  remediation_instructions = "Perform the following command to add the preconfigured WAF rule 'json-sqli-canary' to a Cloud Armor policy via GCP CLI:  \n```  \ngcloud compute security-policies rules create <priority> \\\n    --action=deny-403 \\\n    --security-policy={{name}} \\\n    --expression=evaluatePreconfiguredExpr\\(\\'json-sqli-canary\\'\\)   \n```\n\nReplace `<priority>` with a priority number for this rule. The priority determines the order in which rules are evaluated, with lower numbers having higher priority.\n\n>**Note**  \n>\n>The priority must be a positive integer between 0 and 2147483646, inclusive. The priority must be unique within the security policy.\n"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "HIGH"
  target_native_types      = ["compute#securityPolicy"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.common as common_lib\nimport data.generic.terraform as terraLib\n\nWizPolicy[result] {\n\tresource := input.document[i].resource.google_compute_security_policy[name]\n\trules := terraLib.getArray(resource.rule)\n\tnot ruleExist(rules)\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceType\": \"google_compute_security_policy\",\n\t\t\"resourceName\": terraLib.get_resource_name(resource, name),\n\t\t\"searchKey\": sprintf(\"google_compute_security_policy[%s].rule\", [name]),\n\t\t\"issueType\": \"MissingAttribute\",\n\t\t\"keyExpectedValue\": sprintf(\"google_compute_security_policy[%s].rule should include a 'json-sqli-canary' WAF rule\", [name]),\n\t\t\"keyActualValue\": sprintf(\"google_compute_security_policy[%s].rule does not include a 'json-sqli-canary' WAF rule\", [name]),\n\t\t\"searchLine\": common_lib.build_search_line([\"resource\", \"google_compute_security_policy\", name, \"rule\"], []),\n\t\t\"resourceTags\": terraLib.get_resource_labels(resource),\n\t}\n}\n\nruleExist(rules) {\n\trule := rules[i]\n\tmatch := terraLib.getValueArrayOrObject(rule.match)\n\texpr := terraLib.getValueArrayOrObject(match.expr)\n\tregex.match(\"evaluatePreconfigured(Waf|Expr)\\\\('json-sqli-canary'\", expr.expression)\n\tregex.match(\"^deny\", rule.action)\n}\n"
    remediation_instructions = "```\nresource \"google_compute_security_policy\" \"policy\" {\n  rule {\n    action   = \"deny(403)\"\n    priority = \"1000\"\n    match {\n      expr {\n        expression = \"evaluatePreconfiguredWaf('json-sqli-canary')\"\n      }\n    }\n    description = \"Deny JSON SQL injection attempts\"\n  }\n}\n```\n"
    type                     = "TERRAFORM"
  }
}

resource "wiz_cloud_configuration_rule" "ccn_888b_op_acc_5_1" {
  description              = "This rule checks whether GCP Workspace users have Multi-Factor Authentication (MFA/2SV) enabled.  \nThis rule skips on users that are ` archived` or ` disabled`. \nThis rule fails if both `isEnforcedIn2Sv` and `isEnrolledIn2Sv` are set to `false`.  \n\nMulti-Factor Authentication provides an additional layer of security by requiring users to provide two or more verification factors to gain access to their account. Without MFA, accounts are more vulnerable to unauthorized access through compromised credentials. It is recommended to enable and enforce MFA for all Workspace users to protect against unauthorized access and potential data breaches."
  enabled                  = true
  function_as_control      = false
  name                     = "GCP Workspace user should have MFA enabled"
  opa_policy               = "package wiz\n\ndefault result := \"pass\"\n\niSuspendedOrDisabled {\n    input.suspended == true\n}{\n    input.archived == true\n}\n\nis2svDisabled {\n    input.isEnforcedIn2Sv == false\n    input.isEnrolledIn2Sv == false\n}\n\n# This rule will pass if user can't login - is disabled or archived\nresult := \"skip\" {\n    iSuspendedOrDisabled\n} \n# This rule will fail if the user is active but doesn't have MFA\nelse := \"fail\" {\n    is2svDisabled\n}\n\ncurrentConfiguration := \"User has both 'isEnforcedIn2Sv' and 'isEnrolledIn2Sv' set to 'false'\"\nexpectedConfiguration := \"User should have either 'isEnforcedIn2Sv' or 'isEnrolledIn2Sv' set to 'true'\""
  remediation_instructions = "Perform the following commands to enforce MFA (2-Step Verification) for a Google Workspace user via GAM CLI:\n```\n# Verify the user is enrolled (isEnrolledIn2Sv) before enforcing\ngam info user {{userEmail}} | grep \"2-Step Verification\"\n\n# Enforce 2-Step Verification (isEnforcedIn2Sv) for the user\ngam update user {{userEmail}} enforced2sv on\n```\n\n>**Note**\n>- The user will be prompted to set up 2-Step Verification the next time they sign in; if they have not enrolled a device, they will be blocked from access.\n>- Make sure you have the necessary admin privileges (Super Admin or User Management) to enforce 2SV for users.\n>- Users can also enable 2SV themselves by visiting their Google Account security settings, which changes the isEnrolledIn2Sv status to true.\n>- It's recommended to communicate the change to users before enforcing 2SV."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "HIGH"
  target_native_types      = ["GoogleWorkspaceUser"]
}



resource "wiz_custom_control" "ccn_888b_op_acc_4_3" {
  description               = "Members with excessive privileges in a project: If a member has an overly permissive role in a project, the recommendations should be reviewed to determine what permissions the user should have"
  enabled                   = true
  name                      = "User accounts with Excessive permissions"
  project_id                = "*"
  query                     = "{\"relationships\":[{\"type\":[{\"reverse\":true,\"type\":\"ALERTED_ON\"}],\"with\":{\"select\":true,\"type\":[\"EXCESSIVE_ACCESS_FINDING\"]}}],\"select\":true,\"type\":[\"USER_ACCOUNT\"],\"where\":{\"userDirectory\":{\"EQUALS\":[\"GCP\"]}}}"
  resolution_recommendation = null
  scope_query               = "{\"type\":[\"USER_ACCOUNT\"]}"
  security_sub_categories   = []
  severity                  = "HIGH"
}

resource "wiz_cloud_configuration_rule" "ccn_888b_op_info_3_1" {
  description              = "This rule checks whether disks that are attached to production instances are encrypted with Customer-Supplied Encryption Keys.  \nBy default, Compute Engine service encrypts all data at rest. However, it is recommended to manage the encryption of VM disks with CSEK, in order to have more control and better monitoring of the environment."
  enabled                  = true
  function_as_control      = false
  name                     = "New disks should be encrypted with CSEK"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nresult = \"fail\" {\n\tnot input.diskEncryptionKey\n}\n\ncurrentConfiguration := \"diskEncryptionKey is missing\"\nexpectedConfiguration := \"Customer managed key should be used\""
  remediation_instructions = "Perform the following steps in order to encrypt a disk with CSEK via GCP CLI:  \n1. Run the following command to create a disk with CSEK:  \n```  \ngcloud compute disks create <diskName> --csek-key-file <csekFile>  \n```  \n2. Run the following command to delete the unencrypted disk:  \n```  \ngcloud compute disks delete {{diskName}} --zone={{zone}}  \n```  \n>**Note**  \n>You can only encrypt new persistent disks with your own key. You cannot encrypt existing persistent disks with your own key."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["compute#disk"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.ansible as ansLib\nimport data.generic.common as common_lib\n\nmodules := {\"google.cloud.gcp_compute_disk\", \"gcp_compute_disk\"}\n\nWizPolicy[result] {\n\ttask := ansLib.tasks[id][t]\n\tdisk := task[modules[m]]\n\tansLib.checkState(disk)\n\n\tnot common_lib.valid_key(disk, \"disk_encryption_key\")\n\n\tresult := {\n\t\t\"documentId\": id,\n\t\t\"resourceName\": task.name,\n\t\t\"searchKey\": sprintf(\"name={{%s}}.{{%s}}\", [task.name, modules[m]]),\n\t\t\"issueType\": \"MissingAttribute\",\n\t\t\"keyExpectedValue\": \"gcp_compute_disk.disk_encryption_key should be defined and not null\",\n\t\t\"keyActualValue\": \"gcp_compute_disk.disk_encryption_key is undefined or null\",\n\t\t\"resourceTags\": object.get(disk, \"labels\", {}),\n\t}\n}\n\nWizPolicy[result] {\n\ttask := ansLib.tasks[id][t]\n\tdisk := task[modules[m]]\n\tansLib.checkState(disk)\n\n\tnot common_lib.valid_key(disk.disk_encryption_key, \"raw_key\")\n\tnot common_lib.valid_key(disk.disk_encryption_key, \"kms_key_name\")\n\n\tresult := {\n\t\t\"documentId\": id,\n\t\t\"resourceName\": task.name,\n\t\t\"searchKey\": sprintf(\"name={{%s}}.{{%s}}.disk_encryption_key\", [task.name, modules[m]]),\n\t\t\"issueType\": \"MissingAttribute\",\n\t\t\"keyExpectedValue\": \"gcp_compute_disk.disk_encryption_key.raw_key or gcp_compute_disk.disk_encryption_key.kms_key_name should be defined and not null\",\n\t\t\"keyActualValue\": \"gcp_compute_disk.disk_encryption_key.raw_key and gcp_compute_disk.disk_encryption_key.kms_key_name are undefined or null\",\n\t\t\"resourceTags\": object.get(disk, \"labels\", {}),\n\t}\n}\n\nWizPolicy[result] {\n\ttask := ansLib.tasks[id][t]\n\tdisk := task[modules[m]]\n\tansLib.checkState(disk)\n\n\tkey := check_key_empty(disk.disk_encryption_key)\n\n\tresult := {\n\t\t\"documentId\": id,\n\t\t\"resourceName\": task.name,\n\t\t\"searchKey\": sprintf(\"name={{%s}}.{{%s}}.disk_encryption_key.%s\", [task.name, modules[m], key]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"gcp_compute_disk.disk_encryption_key.%s should not be empty\", [key]),\n\t\t\"keyActualValue\": sprintf(\"gcp_compute_disk.disk_encryption_key.%s is empty\", [key]),\n\t\t\"resourceTags\": object.get(disk, \"labels\", {}),\n\t}\n}\n\ncheck_key_empty(disk_encryption_key) = key {\n\tcommon_lib.valid_key(disk_encryption_key, \"raw_key\")\n\tdisk_encryption_key.raw_key == \"\"\n\tkey := \"raw_key\"\n} else = key {\n\tcommon_lib.valid_key(disk_encryption_key, \"kms_key_name\")\n\tdisk_encryption_key.kms_key_name == \"\"\n\tkey := \"kms_key_name\"\n}\n"
    remediation_instructions = null
    type                     = "ANSIBLE"
  }
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.common as common_lib\n\nWizPolicy[result] {\n\tresource := input.document[i].resources[idx]\n\tresource.type == \"compute.v1.instance\"\n\n\tdisks := resource.properties.disks[d]\n\tnot common_lib.valid_key(disks, \"diskEncryptionKey\")\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": resource.name,\n\t\t\"searchKey\": sprintf(\"resources.name={{%s}}.properties.disks\", [resource.name]),\n\t\t\"issueType\": \"MissingAttribute\",\n\t\t\"keyExpectedValue\": \"'diskEncryptionKey' should be defined and not null\",\n\t\t\"keyActualValue\": \"'diskEncryptionKey' is undefined or null\",\n\t\t\"searchLine\": common_lib.build_search_line([\"resources\", idx, \"properties\", \"disks\", d], []),\n\t}\n}\n\nWizPolicy[result] {\n\tresource := input.document[i].resources[idx]\n\tresource.type == \"compute.v1.instance\"\n\n\tdisks := resource.properties.disks[d]\n\tnot common_lib.valid_key(disks.diskEncryptionKey, \"rawKey\")\n\tnot common_lib.valid_key(disks.diskEncryptionKey, \"kmsKeyName\")\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": resource.name,\n\t\t\"searchKey\": sprintf(\"resources.name={{%s}}.properties.disks.diskEncryptionKey\", [resource.name]),\n\t\t\"issueType\": \"MissingAttribute\",\n\t\t\"keyExpectedValue\": \"'disk_encryption_key.rawKey' or 'disk_encryption_key.kmsKeyName' should be defined and not null\",\n\t\t\"keyActualValue\": \"'disk_encryption_key.rawKey' and 'disk_encryption_key.kmsKeyName' are undefined or null\",\n\t\t\"searchLine\": common_lib.build_search_line([\"resources\", idx, \"properties\", \"disks\", d, \"diskEncryptionKey\"], []),\n\t}\n}\n\nfields := {\"rawKey\", \"kmsKeyName\"}\n\nWizPolicy[result] {\n\tresource := input.document[i].resources[idx]\n\tresource.type == \"compute.v1.instance\"\n\n\tdisks := resource.properties.disks[d]\n\tdisks.diskEncryptionKey[fields[f]] == \"\"\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": resource.name,\n\t\t\"searchKey\": sprintf(\"resources.name={{%s}}.properties.disks.diskEncryptionKey.%s\", [resource.name, fields[f]]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"'diskEncryptionKey.%s' should not be empty\", [fields[f]]),\n\t\t\"keyActualValue\": sprintf(\"'diskEncryptionKey.%s' is empty\", [fields[f]]),\n\t\t\"searchLine\": common_lib.build_search_line([\"resources\", idx, \"properties\", \"disks\", d, \"diskEncryptionKey\", fields[f]], []),\n\t}\n}\n\nvalid_disk_resources := [\"compute.beta.disk\",\"compute.v1.disk\"]\n\nWizPolicy[result] {\n\tresource := input.document[i].resources[idx]\n\tresource.type == valid_disk_resources[_]\n\n\tdisk := resource.properties\n\tnot common_lib.valid_key(disk, \"diskEncryptionKey\")\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": resource.name,\n\t\t\"searchKey\": sprintf(\"resources.name={{%s}}.properties.disks\", [resource.name]),\n\t\t\"issueType\": \"MissingAttribute\",\n\t\t\"keyExpectedValue\": \"'diskEncryptionKey' should be defined and not null\",\n\t\t\"keyActualValue\": \"'diskEncryptionKey' is undefined or null\",\n\t\t\"searchLine\": common_lib.build_search_line([\"resources\", idx, \"properties\"], []),\n\t}\n}\n\nWizPolicy[result] {\n\tresource := input.document[i].resources[idx]\n\tresource.type == valid_disk_resources[_]\n\n\tdisk := resource.properties\n\tnot common_lib.valid_key(disk.diskEncryptionKey, \"rawKey\")\n\tnot common_lib.valid_key(disk.diskEncryptionKey, \"kmsKeyName\")\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": resource.name,\n\t\t\"searchKey\": sprintf(\"resources.name={{%s}}.properties.diskEncryptionKey\", [resource.name]),\n\t\t\"issueType\": \"MissingAttribute\",\n\t\t\"keyExpectedValue\": \"'disk_encryption_key.rawKey' or 'disk_encryption_key.kmsKeyName' should be defined and not null\",\n\t\t\"keyActualValue\": \"'disk_encryption_key.rawKey' and 'disk_encryption_key.kmsKeyName' are undefined or null\",\n\t\t\"searchLine\": common_lib.build_search_line([\"resources\", idx, \"properties\",\"diskEncryptionKey\"], []),\n\t}\n}\n\nWizPolicy[result] {\n\tresource := input.document[i].resources[idx]\n\tresource.type == valid_disk_resources[_]\n\n\tdisk := resource.properties\n\tdisk.diskEncryptionKey[fields[f]] == \"\"\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": resource.name,\n\t\t\"searchKey\": sprintf(\"resources.name={{%s}}.properties.diskEncryptionKey.%s\", [resource.name, fields[f]]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"'diskEncryptionKey.%s' should not be empty\", [fields[f]]),\n\t\t\"keyActualValue\": sprintf(\"'diskEncryptionKey.%s' is empty\", [fields[f]]),\n\t\t\"searchLine\": common_lib.build_search_line([\"resources\", idx, \"properties\",\"diskEncryptionKey\", fields[f]], []),\n\t}\n}\n\n\n"
    remediation_instructions = null
    type                     = "GOOGLE_CLOUD_DEPLOYMENT_MANAGER"
  }
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.common as common_lib\nimport data.generic.terraform as terraLib\n\nWizPolicy[result] {\n\tdocument := input.document[i]\n\tresource := document.resource.google_compute_disk[name]\n\tnot common_lib.valid_key(resource, \"disk_encryption_key\")\n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"resourceType\": \"google_compute_disk\",\n\t\t\"resourceName\": terraLib.get_resource_name(resource, name),\n\t\t\"searchKey\": sprintf(\"google_compute_disk[%s]\", [name]),\n\t\t\"issueType\": \"MissingAttribute\",\n\t\t\"keyExpectedValue\": sprintf(\"'google_compute_disk[%s].disk_encryption_key' should be defined and not null\", [name]),\n\t\t\"keyActualValue\": sprintf(\"'google_compute_disk[%s].disk_encryption_key' is undefined or null\", [name]),\n\t\t\"resourceTags\": terraLib.get_resource_labels(resource),\n\t}\n}\n\nWizPolicy[result] {\n\tdocument := input.document[i]\n\tresource := document.resource.google_compute_disk[name]\n\t\n \tdiskEncryptionKey := terraLib.getValueArrayOrObject(resource.disk_encryption_key)\n\tnot common_lib.valid_key(diskEncryptionKey, \"raw_key\")\n\tnot common_lib.valid_key(diskEncryptionKey, \"kms_key_self_link\")\n\tnot common_lib.valid_key(diskEncryptionKey, \"rsa_encrypted_key\")    \n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"resourceType\": \"google_compute_disk\",\n\t\t\"resourceName\": terraLib.get_resource_name(resource, name),\n\t\t\"searchKey\": sprintf(\"google_compute_disk[%s].disk_encryption_key\", [name]),\n\t\t\"issueType\": \"MissingAttribute\",\n\t\t\"keyExpectedValue\": sprintf(\"'google_compute_disk[%s].disk_encryption_key.raw_key' or 'google_compute_disk[%s].disk_encryption_key.kms_key_self_link' or 'google_compute_disk[%s].disk_encryption_key.rsa_encrypted_key' should be defined and not null\", [name, name, name]),\n\t\t\"keyActualValue\": sprintf(\"'google_compute_disk[%s].disk_encryption_key.raw_key' and 'google_compute_disk[%s].disk_encryption_key.kms_key_self_link' and 'google_compute_disk[%s].disk_encryption_key.rsa_encrypted_key' are undefined or null\", [name, name, name]),\n\t\t\"resourceTags\": terraLib.get_resource_labels(resource),\n\t}\n}\n\nWizPolicy[result] {\n\tdocument := input.document[i]\n\tresource := document.resource.google_compute_disk[name]\n\n\tkeyTypes := {\"raw_key\", \"kms_key_self_link\", \"rsa_encrypted_key\"}\n\tdiskEncryptionKey := terraLib.getValueArrayOrObject(resource.disk_encryption_key)\n\tdiskEncryptionKey[keyTypes[keyType]] == \"\"\n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"resourceType\": \"google_compute_disk\",\n\t\t\"resourceName\": terraLib.get_resource_name(resource, name),\n\t\t\"searchKey\": sprintf(\"google_compute_disk[%s].disk_encryption_key.%s\", [name, keyType]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"'google_compute_disk[%s].disk_encryption_key.%s' should not be empty\", [name, keyType]),\n\t\t\"keyActualValue\": sprintf(\"'google_compute_disk[%s].disk_encryption_key.%s' is empty\", [name, keyType]),\n\t\t\"resourceTags\": terraLib.get_resource_labels(resource),\n\t}\n}\n"
    remediation_instructions = "```\nresource \"google_compute_disk\" \"example_disk\" {\n  disk_encryption_key {\n    kms_key_self_link = \"<kms_key>\" // Add your KMS key \n  }\n}\n// You can also configure \"raw_key\" or \"rsa_encrypted_key\" instead of \"kms_key_self_link\"\n```\n"
    type                     = "TERRAFORM"
  }
}

resource "wiz_cloud_configuration_rule" "ccn_888b_op_acc_1_4" {
  description              = "This rule checks whether the project's access role binding grants permissions to a personal Gmail account.  \nThis rule fails if at least one Gmail account is associated with the access role binding. An access role binding grants the permissions defined in a role to a principal (user account, service account, Google group, or domain). A personal Gmail account is considered less secure than a corporate domain user since it lacks visibility and auditing capabilities."
  enabled                  = true
  function_as_control      = false
  name                     = "Access Role Binding should not bind personal Gmail accounts"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\ngmailAccounts[account]{\n\tregex.match(\"@gmail\\\\.com\",input.members[i])\n    account := regex.find_all_string_submatch_n(\"user:(.*)\",input.members[i],-1)[0][1]\n}\n\nresult = \"fail\" {\n\tcount(gmailAccounts) > 0\n}\n\ncurrentConfiguration := concat(\"\", [\"'members' contains the following Gmail accounts: \", concat(\", \",gmailAccounts)])\nexpectedConfiguration :=\"'members' should not contain any Gmail account\""
  remediation_instructions = "Perform the following command to remove the access role binding via GCP CLI:    \nNote: The `member` and `role` parameters need to be enclosed with single quotes. For example: 'user:test-user@gmail.com', 'roles/editor'.  \n```  \ngcloud projects remove-iam-policy-binding <PROJECT_ID> \\\n    --member= <'user:USER@GMAIL.COM'> \\\n    --role='{{role}}' \\\n    --all  \n```  \n>**Note**  \nOnce the users are removed, it is advised to restrict future identities by the Google Workspace domain(s). Use the following command to restrict the Organization to your domain(s).    \nFor more information on this command click [here](https://cloud.google.com/resource-manager/docs/organization-policy/restricting-domains)."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["AccessRoleBinding"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.common as common_lib\n\nWizPolicy[result] {\n\tmember := input.document[i].resources[resource].accessControl.gcpIamPolicy.bindings[binding].members[memberIndex]\n\tstartswith(member, \"user:\")\n\tendswith(member, \"gmail.com\")\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": input.document[i].resources[resource].name,\n\t\t\"searchKey\": sprintf(\"accessControl.gcpIamPolicy.bindings[%s].members.%s\", [binding, member]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": \"'members' cannot contain Gmail account addresses\",\n\t\t\"keyActualValue\": sprintf(\"'members' has email address: %s\", [member]),\n\t\t\"searchLine\": common_lib.build_search_line([\"resources\", resource, \"accessControl\", \"gcpIamPolicy\", \"bindings\", binding, \"members\"], []),\n\t}\n}\n"
    remediation_instructions = null
    type                     = "GOOGLE_CLOUD_DEPLOYMENT_MANAGER"
  }
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.terraform as terraLib\n\nWizPolicy[result] {\n\tdocument := input.document[i]\n\tresource := document.resource.google_project_iam_binding[name]\n\tmembers := resource.members\n\tmail := members[_]\n\n\tcontains(mail, \"gmail.com\")\n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"resourceType\": \"google_project_iam_binding\",\n\t\t\"resourceName\": terraLib.get_resource_name(members, name),\n\t\t\"searchKey\": sprintf(\"google_project_iam_binding[%s].members.%s\", [name, mail]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": \"'members' cannot contain Gmail account addresses\",\n\t\t\"keyActualValue\": sprintf(\"'members' has email address: %s\", [mail]),\n\t\t\"resourceTags\": terraLib.get_resource_labels(resource),\n\t}\n}\n"
    remediation_instructions = "```\nresource \"google_project_iam_binding\" \"example_binding\" {\n  members = [\n    \"user:jane@example.com\",\n    \"serviceAccount:my-service-account@my-project.iam.gserviceaccount.com\",\n    \"group:admins@example.com\"\n  ]\n}\n```\n"
    type                     = "TERRAFORM"
  }
}


resource "wiz_cloud_configuration_rule" "ccn_888b_op_acc_5_4" {
  description              = "This rule checks whether a Google Workspace user has been inactive for more than 90 days.  \nThis rule fails if the user's `lastLoginTime` is more than 90 days ago.  \nInactive user accounts pose a security risk as they may be compromised without detection. These accounts might have outdated permissions or access to sensitive information that is no longer necessary.  \nIt is recommended to regularly review and disable or remove inactive user accounts to maintain a secure Google Workspace environment and adhere to the principle of least privilege."
  enabled                  = true
  function_as_control      = false
  name                     = "Google Workspace User should not be inactive for more than 90 days"
  opa_policy               = "package wiz\n\nimport future.keywords.in\n\ndefault result := \"pass\"\n\nnow_ns := time.now_ns()\nninety_days_ns := time.parse_duration_ns(\"2160h\") # 90 days in hours\n\nis_suspended_or_disabled {\n    input.suspended != null\n    input.suspended == true\n}{\n    input.archived != null\n    input.archived == true\n}\n\nis_inactive_for_90_days {\n    input.lastLoginTime != null\n    input.lastLoginTime != \"\"\n    last_login_ns := time.parse_rfc3339_ns(input.lastLoginTime)\n    (now_ns - last_login_ns) > ninety_days_ns\n}\n\nresult := \"fail\" {\n    not is_suspended_or_disabled\n    is_inactive_for_90_days\n}\n\ncurrentConfiguration := \"User's last login time is more than 90 days ago\"\nexpectedConfiguration := \"User's last login time should be within the last 90 days\"\n"
  remediation_instructions = "Perform the following steps to address inactive Google Workspace users via CLI:\n\n1. Suspend inactive users:\n\n```\ngam update user {{primaryEmail}} suspended on\n```\n\n2. Delete inactive users:\n\n```\ngam delete user {{primaryEmail}}\n```\n\n3. Force password reset to prompt user login: \n\n```\ngam update user {{primaryEmail}} password random changepassword on\n```\n\n>**Note**  \n>Before taking action on inactive accounts, ensure that you have a clear company policy regarding account inactivity and that you've communicated this policy to all users. Some accounts may be intentionally inactive (e.g., for seasonal employees or specific business purposes), so review each case carefully before suspending or deleting accounts."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["GoogleWorkspaceUser"]
}


resource "wiz_cloud_configuration_rule" "ccn_888b_op_acc_3_2" {
  description              = "This rule checks if the Access Role Binding (IAM policy) contains a Service Account that has Admin privileges.  \nThis rule fails if the Access Role Binding (IAM policy) contains a user-created service account that is granted an Admin, Owner, or Editor role. It skips bindings that do not contain service accounts, and the [GCP APIs Service Agent](https://cloud.google.com/iam/docs/service-account-types#google-apis-service-agent).  \nApplications use service accounts to make requests to the Google Cloud API of services so that the users are not directly involved.  \nIt is recommended to adopt the principle of least privilege (PoLP) and avoid the use of admin access for Service Accounts.\n>**Note**  \n>The findings for this rule are the roles attached to the non-compliant service accounts. See the finding's Current Configuration to view the non-compliant service accounts."
  enabled                  = true
  function_as_control      = false
  name                     = "Service Account should not have Admin privileges"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\n# This rule skips Google APIs Service Agent\n# More info: https://cloud.google.com/iam/docs/service-account-types#google-apis-service-agent\ndefaultGcpSaApiServiceAgent(member) {\n\tendswith(lower(member), \"cloudservices.gserviceaccount.com\")\n\tregex.match(\"^roles/editor$\", input.role)\n}\n\ncontainsServiceAccount := [ saMember | \n\tmember := input.members[_];\n\tstartswith(lower(member), \"serviceaccount\");\n\tnot defaultGcpSaApiServiceAgent(member);\n\tsaMember := split(member, \":\")[1]\n]\n\nresult = \"skip\" {\n\tcount(containsServiceAccount) == 0\n} else = \"fail\" {\n\tcount(containsServiceAccount) > 0\n\tregex.match(\"^roles/editor$|^roles/owner$|^roles/.*Admin$|^roles/.*admin$\", input.role)\n}\n\ncurrentConfiguration := \"Service Accounts are granted Admin privileges\"\nexpectedConfiguration := \"Service Accounts should not be granted Admin privileges\""
  remediation_instructions = "Perform the following steps to remove the overly permissive role from a service account via GCP CLI:\n\nThe following service accounts have overly permissive privileges:  \n{{overlyPermissiveSa}}\n\nUse the following command to remove all the overly permissive role bindings of the project level service accounts listed above.\n```\ngcloud projects remove-iam-policy-binding <PROJECT_ID> \\\n    --member=<'serviceAccount:test123@example.domain.com'> \\\n    --role='{{role}}' \\\n    --all\n```\n\nFollow this [link](https://cloud.google.com/sdk/gcloud/reference/iam/service-accounts/remove-iam-policy-binding) to remove all the overly permissive role bindings of non project-level service accounts.\n"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["AccessRoleBinding"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.common as common_lib\nimport data.generic.terraform as terraLib\n\nWizPolicy[result] {\n\tresources := {\"google_project_iam_binding\", \"google_project_iam_member\"}\n\tdocument := input.document[i]\n\tresource := document.resource[resources[idx]][name]\n\n\tterraLib.check_member(resource, \"serviceAccount:\")\n\thas_improperly_privileges(resource.role)\n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"resourceName\": terraLib.get_resource_name(resource, name),\n\t\t\"resourceType\": resources[r],\n\t\t\"searchKey\": sprintf(\"%s[%s].role\", [resources[idx], name]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"%s[%s].role should not have admin, editor, owner, or write privileges for service account member\", [resources[idx], name]),\n\t\t\"keyActualValue\": sprintf(\"%s[%s].role has admin, editor, owner, or write privilege for service account member\", [resources[idx], name]),\n\t\t\"searchLine\": common_lib.build_search_line([\"resource\", resources[idx], name, \"role\"], []),\n\t\t\"resourceTags\": terraLib.get_resource_labels(resource),\n\t}\n}\n\nhas_improperly_privileges(role) {\n\tprivileges := {\"admin\", \"owner\", \"editor\"}\n\tcontains(lower(role), privileges[x])\n}\n"
    remediation_instructions = "```\nresource \"google_project_iam_binding\" \"example_binding\" {\n  role = \"roles/viewer\"\n  members = [\n    \"serviceAccount:example@example.com\"\n  ]\n}\n\n// Alternatively, you can use a more specific role that doesn't include admin privileges\n// For example: \"roles/monitoring.viewer\", \"roles/storage.objectViewer\", etc.\n```\n"
    type                     = "TERRAFORM"
  }
}


resource "wiz_cloud_configuration_rule" "ccn_888b_op_exp_10_1" {
  description              = "This rule checks whether the Projects effective audit logs is properly configured.\nThis rule fails if the `DATA_READ` logs in `auditLogConfigs` is not set for `iam.googleapis.com` or for `allServices`.\nIt is recommended that Cloud Audit Logging be configured to track all admin activities and read, write access to user data for all users."
  enabled                  = true
  function_as_control      = false
  name                     = "Project IAM data access logs should be properly configured"
  opa_policy               = "package wiz\n\nimport future.keywords.in\n\ndefault result := \"fail\"\n\ncheckService := \"IAM.GOOGLEAPIS.COM\"\nallServices := \"ALLSERVICES\"\n\nproperlyConfiguredAuditLogs(service){\n\tauditConfig := input.WizMetadata.effectiveAuditConfigs[config]\n    upper(auditConfig.service) == service\n\tauditLogConfig := auditConfig.auditLogConfigs\n\t\n    upper(auditLogConfig[_].logType) == \"DATA_READ\"\n}\n\nresult := \"pass\" {\n\tproperlyConfiguredAuditLogs(allServices)\n} else := \"skip\" {\n     not lower(checkService) in input.serviceUsage\n} else := \"pass\" {\n\tproperlyConfiguredAuditLogs(checkService)\n}\n\ncurrentConfiguration := \"'DATA_READ' logs in 'auditConfigs' for 'iam.googleapis.com' is not properly configured\"\nexpectedConfiguration := \"'DATA_READ' should be configured for 'allServices' or at least for 'iam.googleapis.com'\""
  remediation_instructions = "Perform the following commands to properly configure Cloud Data Access Logging on the Project via GCP CLI:\n\n**Caution:** Follow the instructions carefully. You are editing a policy object that contains critical information about who can access your resource. Accidentally altering that information could make your resource unusable. \n\n1. Read your Project's IAM policy and store it in a file:\n```\ngcloud projects get-iam-policy {{projectId}} > /tmp/policy.yaml\n```\n**Note:** When you call `projects get-iam-policy`, the result shows only the policies set in the GCP project, not the policies inherited from a parent organization or folder.\n2. Open and edit the downloaded project policy to include the following fields:\n```\nauditConfigs:\n- auditLogConfigs:\n  - logType: ADMIN_READ\n  - logType: DATA_WRITE\n  - logType: DATA_READ\n  service: allServices\n```\nIn addition, make sure that no `exemptedMembers` exist in any `auditLogConfigs`.\n\n**Caution**: Your edited IAM policy replaces the current policy. Changing parts of your policy not related to audit logging might make your Google Cloud project inaccessible. You must preserve the `bindings:` and `etag:` sections without changes. Failure to do so might cause your Google Cloud project to become unusable.\n\n3. Write your new IAM policy to the project:\n```\ngcloud projects set-iam-policy {{projectId}} /tmp/policy.yaml\n```\n>**Note**  \n>* This is a sensitive configuration. If you prefer remediating the issue via the GCP portal, you may follow this [guide](https://cloud.google.com/logging/docs/audit/configure-data-access#config-console-default) for assistance.\n>* If you prefer, you can set the default configurations at the Organization/Folder level. This way, all the Projects will automatically inherit the parent configuration. You cannot disable a Data Access audit log for a child resource if the audit log was enabled at the parent level. See Cloud Configuration Rules `CloudOrganization-021` and `CloudOrganization-022` for more information.\n>* Data Access audit logs volume can be large. Enabling Data Access logs might result in your Google Cloud project being charged for the additional logs usage.\n"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["project#instance"]
}


resource "wiz_custom_control" "ccn_888b_op_exp_1_1" {
  description               = null
  enabled                   = true
  name                      = "Cloud Asset without cost center or  environment tags"
  project_id                = "*"
  query                     = "{\"select\":true,\"type\":[\"VIRTUAL_MACHINE\",\"DATA_RESOURCE\",\"SERVERLESS\",\"CONTAINER_SERVICE\"],\"where\":{\"tags\":{\"TAG_DOES_NOT_CONTAIN_ANY\":[{\"key\":\"cost center\"},{\"key\":\"environment\"}]}}}"
  resolution_recommendation = null
  scope_query               = "{\"type\":[\"VIRTUAL_MACHINE\",\"DATA_RESOURCE\",\"SERVERLESS\",\"CONTAINER_SERVICE\"]}"
  security_sub_categories   = []
  severity                  = "LOW"
}

resource "wiz_cloud_configuration_rule" "ccn_888b_op_com_4_1" {
  description              = "This rule checks whether GCP projects are using the default VPC network.  \nThis rule fails if it finds a VPC network with 'name = default'.\nIt is recommended to use a network configuration based on personalized security and networking requirements, and not to use the default network configuration."
  enabled                  = true
  function_as_control      = false
  name                     = "Default Network should not exist in a project"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nresult = \"fail\" {\n\tlower(input.name) == \"default\"\n}\n\ncurrentConfiguration := \"Default network exists\"\nexpectedConfiguration := \"Default network should not exist in a project\""
  remediation_instructions = "Perform the following command in order to delete the default VPC network via GCP CLI:  \n```  \ngcloud compute networks delete default  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["compute#network"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.common as common_lib\nimport data.generic.terraform as terraLib\n\nWizPolicy[result] {\n\tproject := input.document[i].resource.google_project[name]\n\tproject.auto_create_network == true\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceType\": \"google_project\",\n\t\t\"resourceName\": terraLib.get_resource_name(project, name),\n\t\t\"searchKey\": sprintf(\"google_project[%s].auto_create_network\", [name]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"google_project[%s].auto_create_network should be set to false\", [name]),\n\t\t\"keyActualValue\": sprintf(\"google_project[%s].auto_create_network is true\", [name]),\n\t\t\"searchLine\": common_lib.build_search_line([\"resource\", \"google_project\", name],[\"auto_create_network\"]),\n\t\t\"remediation\": json.marshal({\n\t\t\t\"before\": \"true\",\n\t\t\t\"after\": \"false\"\n\t\t}),\n\t\t\"remediationType\": \"update\",\n\t\t\"resourceTags\": terraLib.get_resource_labels(project),\n\t}\n}\n\nWizPolicy[result] {\n\tproject := input.document[i].resource.google_project[name]\n\tnot common_lib.valid_key(project, \"auto_create_network\")\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceType\": \"google_project\",\n\t\t\"resourceName\": terraLib.get_resource_name(project, name),\n\t\t\"searchKey\": sprintf(\"google_project[%s]\", [name]),\n\t\t\"issueType\": \"MissingAttribute\",\n\t\t\"keyExpectedValue\": sprintf(\"google_project[%s].auto_create_network should be set to false\", [name]),\n\t\t\"keyActualValue\": sprintf(\"google_project[%s].auto_create_network is undefined\", [name]),\n\t\t\"searchLine\": common_lib.build_search_line([\"resource\", \"google_project\", name],[]),\n\t\t\"remediation\": \"auto_create_network = false\",\n\t\t\"remediationType\": \"addition\",\n\t\t\"resourceTags\": terraLib.get_resource_labels(project),\n\t}\n}\n"
    remediation_instructions = "```\nresource \"google_project\" \"example_project\" {\n  auto_create_network = false\n}\n```\n"
    type                     = "TERRAFORM"
  }
}


resource "wiz_custom_control" "ccn_888b_op_acc_1_2" {
  description               = "To ensure the correct use of identities in GCP, the use of multiple access keys per IAM user should be avoided when they are necessary. Maintaining more than one key increases the risk of unauthorized access and credential compromise. For this same reason, unused keys must not exist"
  enabled                   = true
  name                      = "User with multiple access keys "
  project_id                = "*"
  query                     = "{\"relationships\":[{\"type\":[{\"type\":\"OWNS\"}],\"with\":{\"aggregate\":true,\"aggregateConstraint\":{\"GREATER_THAN\":1},\"select\":true,\"type\":[\"ACCESS_KEY\"]}}],\"select\":true,\"type\":[\"USER_ACCOUNT\"],\"where\":{\"nativeType\":{\"EQUALS\":[\"user\"]},\"userDirectory\":{\"EQUALS\":[\"GCP\"]}}}"
  resolution_recommendation = null
  scope_query               = "{\"type\":[\"USER_ACCOUNT\"]}"
  security_sub_categories   = []
  severity                  = "HIGH"
}

resource "wiz_cloud_configuration_rule" "ccn_888b_op_exp_11_2" {
  description              = "This rule checks whether a KMS Key is set to rotate on a regular schedule. This rule fails if it finds a key without a rotation period. A key is used to protect a certain corpus of data. A collection of files could be encrypted with the same key, and people with decrypt permissions on that key would be able to decrypt those files. It's recommended to ensure that the 'rotation period' is set to a specific time to prevent data from being accessed through the old key.\n>**Note**  \n>This CCR does not assess keys in `disabled`, `destroyed`, or `destroy_scheduled` state, nor keys that their status is not `Available`.\n"
  enabled                  = true
  function_as_control      = false
  name                     = "KMS Key should be set to rotate on a regular schedule"
  opa_policy               = "package wiz\n\nimport future.keywords.in\n\ndefault result = \"pass\"\n\nstatesToSkip := {\"DISABLED\", \"DESTROY_SCHEDULED\", \"DESTROYED\"}\n\nresult = \"skip\" {\n\tupper(input.primary.state) in statesToSkip\n} else = \"skip\" {\n\tnot input.primary\n} else = \"fail\" {\n\tinput.nextRotationTime == \"\"\n}\n\ncurrentConfiguration := \"nextRotationTime is not set\"\nexpectedConfiguration := \"Key rotation should be enabled\"\n"
  remediation_instructions = "Perform the following command in order to add rotation time for KMS cryptokey via GCP CLI:  \n```  \ngcloud kms keys set-rotation-schedule {{key}} --location=global --keyring={{keyRings}} --rotation-period=<period>  \n```  \n>**Note**  \n>* The best security practice is to set the rotation period to 90 days.  \n>* The rotation period value is built from a number followed by a single character (e.g. 7d = seven days, 5h = five hours)\n"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["kms#instance"]
  iac_matchers {
    rego_code                = "\npackage wiz\n\nimport data.generic.common as common_lib\nimport data.generic.terraform as terraLib\n\nWizPolicy[result] {\n\tdocument := input.document[i]\n\tcryptoKey := document.resource.google_kms_crypto_key[name]\n\n\tnot common_lib.valid_key(cryptoKey, \"rotation_period\")\n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"resourceType\": \"google_kms_crypto_key\",\n\t\t\"resourceName\": terraLib.get_resource_name(cryptoKey, name),\n\t\t\"searchKey\": sprintf(\"google_kms_crypto_key[%s]\", [name]),\n\t\t\"issueType\": \"MissingAttribute\",\n\t\t\"keyExpectedValue\": sprintf(\"'google_kms_crypto_key[%s].rotation_period' should be defined\", [name]),\n\t\t\"keyActualValue\": sprintf(\"'google_kms_crypto_key[%s].rotation_period' is undefined\", [name]),\n\t\t\"searchLine\": common_lib.build_search_line([\"resource\", \"google_kms_crypto_key\", name], []),\n\t\t\"remediation\": \"rotation_period = \\\"7776000s\\\"\",\n\t\t\"remediationType\": \"addition\",\n\t\t\"resourceTags\": terraLib.get_resource_labels(cryptoKey),\n\t}\n}\n\nWizPolicy[result] {\n\tdocument := input.document[i]\n\tcryptoKey := document.resource.google_kms_crypto_key[name]\n\n\tcommon_lib.valid_key(cryptoKey, \"rotation_period\")\n\tcryptoKey.rotation_period == null\n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"resourceType\": \"google_kms_crypto_key\",\n\t\t\"resourceName\": terraLib.get_resource_name(cryptoKey, name),\n\t\t\"searchKey\": sprintf(\"google_kms_crypto_key[%s].rotation_period\", [name]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"'google_kms_crypto_key[%s].rotation_period' should not be null\", [name]),\n\t\t\"keyActualValue\": sprintf(\"'google_kms_crypto_key[%s].rotation_period' is null\", [name]),\n\t\t\"searchLine\": common_lib.build_search_line([\"resource\", \"google_kms_crypto_key\", name], [\"rotation_period\"]),\n\t\t\"remediation\": json.marshal({\"before\": \"null\", \"after\": \"\\\"7776000s\\\"\"}),\n\t\t\"remediationType\": \"update\",\n\t\t\"resourceTags\": terraLib.get_resource_labels(cryptoKey),\n\t}\n}\n\n# Helper function to validate rotation period\n# Returns true if rotation_period is invalid (less than or equal to 86400s)\ninvalidRotationPeriod(cryptoKey) {\n\tis_null(cryptoKey.rotation_period)\n}{\n\trotation_period := cryptoKey.rotation_period\n\t# Remove the 's' suffix and convert to number\n\trotation_seconds := trim_suffix(rotation_period, \"s\")\n\trotation_value := to_number(rotation_seconds)\n\t\n\t# Invalid if less than or equal to 86400 (1 day)\n\trotation_value <= 86400\n}"
    remediation_instructions = "```\nresource \"google_kms_crypto_key\" \"example_key\" {\n  rotation_period = \"7776000s\"\n}\n```\n"
    type                     = "TERRAFORM"
  }
}

resource "wiz_custom_control" "ccn_888b_op_acc_3_3" {
  description               = "Apply \"separation of duties\" to service accounts. Do not use basic roles (Owner/Editor) in production."
  enabled                   = true
  name                      = "Service account using basic roles (Owner/Editor) "
  project_id                = "*"
  query                     = "{\"relationships\":[{\"type\":[{\"reverse\":true,\"type\":\"ASSIGNED_TO\"}],\"with\":{\"relationships\":[{\"type\":[{\"type\":\"PERMITS\"}],\"with\":{\"select\":true,\"type\":[\"ACCESS_ROLE\"],\"where\":{\"name\":{\"CONTAINS\":[\"Editor\",\"Owner\"]}}}}],\"select\":true,\"type\":[\"ACCESS_ROLE_BINDING\"]}}],\"select\":true,\"type\":[\"SERVICE_ACCOUNT\"],\"where\":{\"userDirectory\":{\"EQUALS\":[\"GCP\"]}}}"
  resolution_recommendation = null
  scope_query               = "{\"type\":[\"SERVICE_ACCOUNT\"]}"
  security_sub_categories   = []
  severity                  = "MEDIUM"
}

resource "wiz_cloud_configuration_rule" "ccn_888b_op_exp_10_2" {
  description              = "GCP Project Activity Logs are platform logs that provide insight into the admin write actions in the project level events. \nThese logs contain information about operations on each resource in your projects.\n\n>**Note**  \n>This rule should always pass on every Project since the logs are enabled by default and can't be disabled."
  enabled                  = true
  function_as_control      = false
  name                     = "Project activity logs should be enabled"
  opa_policy               = "package wiz\n\n#  GCP activity logs are enabled by default and can't be disabled\n\ndefault result := \"pass\"\n\nresult := \"fail\" {\n    not input.projectId\n}\n\n"
  remediation_instructions = null
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["project#instance"]
}

resource "wiz_cloud_configuration_rule" "ccn_888b_op_acc_5_3" {
  description              = "This rule checks whether a Service Account has been inactive for more than 90 days.  \nThis rule fails if the Service Account has not been used in the last 90 days (`inactiveInLast90Days` is true).  \nService Accounts are used to authenticate applications, services, and other non-human entities to Google Cloud resources. Inactive Service Accounts may indicate unused or forgotten accounts, which could pose a security risk if compromised.  \nIt is recommended to regularly review and remove or disable Service Accounts that have been inactive for extended periods to maintain a secure environment and adhere to the principle of least privilege."
  enabled                  = true
  function_as_control      = false
  name                     = "Service account should not be inactive for more than 90 days"
  opa_policy               = "package wiz\n\ndefault result := \"pass\"\n\nresult := \"fail\" {\n    input.inactiveInLast90Days == true\n}\n\ncurrentConfiguration := \"Service account has been inactive for more than 90 days\"\nexpectedConfiguration := \"Service accounts should be active within the last 90 days\""
  remediation_instructions = "Perform the following command to delete inactive service accounts via GCP CLI:\n\n```\ngcloud iam service-accounts delete {{email}} --project={{projectId}}\n```\n\nIf the service account is still needed, reactivate it by using it in a GCP service or by manually creating a new key:\n```\ngcloud iam service-accounts keys create KEY_FILE --iam-account={{email}}\n```\n\n>**Note**  \n>Before deleting a service account, ensure it's not being used by any resources or applications in your project. If you're unsure about the usage of a service account, consider disabling it temporarily instead of deleting it."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["serviceaccount#instance"]
}

resource "wiz_custom_control" "ccn_888b_op_acc_4_2" {
  description               = "This user is assigned permissions that together can be abused to achieve admin privileges in the environment. \n\nAn attacker that will gain access to the user account could use the permission combination and perform actions that will lead to administrative privileges (depending on the combination). More information for each combination can be found under the \"Lateral Movement Finding\" object in the Issue."
  enabled                   = true
  name                      = "User or service account assigned a permission combination that could lead to privilege escalation "
  project_id                = "*"
  query                     = "{\"relationships\":[{\"type\":[{\"type\":\"ALERTED_ON\"}],\"with\":{\"as\":\"scoped_entity\",\"select\":true,\"type\":[\"USER_ACCOUNT\",\"GROUP\",\"PREDEFINED_GROUP\",\"SERVICE_ACCOUNT\"],\"where\":{\"userDirectory\":{\"EQUALS\":[\"GCP\"]}}}}],\"select\":true,\"type\":[\"LATERAL_MOVEMENT_FINDING\"],\"where\":{\"permissionCombination\":{\"IS_SET\":true}}}"
  resolution_recommendation = "### Prevent unintended admin access\n* Use the “least privilege” principle when assigning permissions, meaning that each account is assigned the exact permissions that it needs to function properly. When assigning permissions, avoid wild-card permissions.\n* Revoke at least one of the permissions detailed in the \"Lateral Movement Finding\" object in the Issue.\n* To find unused permissions assigned to the principal, check the Excessive Permissions object on the Security Graph.\n* Minimize the attack surface of principals with sensitive permissions by remediating all Issues associated to them."
  scope_query               = "{\"type\":[\"USER_ACCOUNT\",\"GROUP\",\"PREDEFINED_GROUP\",\"SERVICE_ACCOUNT\"]}"
  security_sub_categories   = []
  severity                  = "MEDIUM"
}


