
resource "wiz_cloud_configuration_rule" "ccn_884a_opmon1r1" {
  description              = "This rule checks whether the Conditional Access Policy requires MFA for risky sign-ins.\nThis rule fails if the policy has all of the following:\n* `applications.includeApplications` contains `All`\n* `users.includeUsers` contains `All`\n* `builtInControls` contains `mfa` or `authenticationStrength.requirementsSatisfied` contains `mfa`\n* `signInRiskLevels` contains `high` or `medium`\n* `state` is `enabled`\n\n>**Note**  \nThis rule does not indicate a misconfiguration and is used as part of Control `wc-id-1233`."
  enabled                  = true
  function_as_control      = false
  name                     = "Conditional Access Policy requires MFA for risky sign-in"
  opa_policy               = "package wiz\n\nimport future.keywords.in\n\ndefault result = \"pass\"\n\nconditions := input.conditions\nriskLevels := {\"high\", \"medium\"}\n\nrequireMfaForRiskySignIn {\n\tlower(conditions.applications.includeApplications[_]) == \"all\"\n\tlower(conditions.users.includeUsers[_]) == \"all\"\n\tlower(conditions.signInRiskLevels[_]) in riskLevels\n\tlower(input.grantControls.builtInControls[_]) == \"mfa\"\n\tlower(input.state) == \"enabled\"\n}{\n\tlower(conditions.applications.includeApplications[_]) == \"all\"\n\tlower(conditions.users.includeUsers[_]) == \"all\"\n\tlower(conditions.signInRiskLevels[_]) in riskLevels\n\tlower(input.grantControls.authenticationStrength.requirementsSatisfied) == \"mfa\"\n\tlower(input.state) == \"enabled\"\n}\n\n# This rule fails if the Conditional Access Policy requires MFA for risky sign-in.\nresult = \"fail\" {\n\trequireMfaForRiskySignIn\n}\n\ncurrentConfiguration := sprintf(\"'%v' policy requires MFA for risky sign-in\", [input.displayName])"
  remediation_instructions = ">**Note**  \nThis rule does not indicate a misconfiguration and is used as part of a Control."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "INFORMATIONAL"
  target_native_types      = ["ConditionalAccessPolicy"]
}

# __generated__ by Terraform from "4e6ff53b-c48f-4559-96f7-f7652e848499"
resource "wiz_cloud_configuration_rule" "ccn_884a_opmon2r2" {
  description              = "This rule checks whether Azure AKS cluster monitoring has been configured.  This rule fails if the Azure AKS cluster does not have monitoring enabled through Azure Monitor Logs.  \nAzure Monitor Logs is a feature that allows users to gain comprehensive insights into the performance and health of their AKS clusters. By not enabling Azure Monitor Logs, users miss out on critical operational visibility required for troubleshooting and tuning purposes. Therefore, it is recommended to enable Azure Monitor Logs for AKS clusters for improved observability and management."
  enabled                  = true
  function_as_control      = false
  name                     = "AKS cluster logging to Azure monitoring should be configured"
  opa_policy               = null
  remediation_instructions = null
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = []
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.common as commonLib\nimport data.generic.terraform as terraLib\n\nWizPolicy[result] {\n\tdocument := input.document[i]\n\tresource := document.resource.azurerm_kubernetes_cluster[name]\n\n\tnot commonLib.valid_key(resource, \"oms_agent\")\n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"resourceName\": terraLib.get_resource_name(resource, name),\n\t\t\"searchKey\": sprintf(\"azurerm_kubernetes_cluster[%s]\", [name]),\n\t\t\"issueType\": \"MissingAttribute\",\n\t\t\"keyExpectedValue\": sprintf(\"azurerm_kubernetes_cluster[%s].omsAgent.log_analytics_workspace_id should be defined\", [name]),\n\t\t\"keyActualValue\": sprintf(\"azurerm_kubernetes_cluster[%s].omsAgent is not defined\", [name]),\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n\nWizPolicy[result] {\n\tdocument := input.document[i]\n\tresource := document.resource.azurerm_kubernetes_cluster[name]\n\tomsAgent := terraLib.getValueArrayOrObject(resource.oms_agent)\n\n\tnot commonLib.valid_key(omsAgent, \"log_analytics_workspace_id\")\n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"resourceName\": terraLib.get_resource_name(resource, name),\n\t\t\"searchKey\": sprintf(\"azurerm_kubernetes_cluster[%s]\", [name]),\n\t\t\"issueType\": \"MissingAttribute\",\n\t\t\"keyExpectedValue\": sprintf(\"azurerm_kubernetes_cluster[%s].omsAgent.log_analytics_workspace_id should be defined\", [name]),\n\t\t\"keyActualValue\": sprintf(\"azurerm_kubernetes_cluster[%s].omsAgent.log_analytics_workspace_id is not defined\", [name]),\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n"
    remediation_instructions = null
    type                     = "TERRAFORM"
  }
}

# __generated__ by Terraform from "87e4285b-0a91-4a46-839a-db2e10b2b563"
resource "wiz_cloud_configuration_rule" "ccn_884a_opexp8r2" {
  description              = "This rule checks if the Log Profile sends logs for all activities.  \nThis rule fails if the `logProfileResource.categories` does not contain all of the categories on the `allActivities` list.  \nLog Profiles are a legacy method for sending activity logs to Azure storage or Event Hubs, allowing monitoring events and handling incidents. Configuring your account Log Profile to collect logs for 'Write', 'Delete', and 'Action' event categories ensures that all the control and management activities performed on your subscription are exported.  \nIt is recommended to enable logs for all activities in order to create activity trails for investigation purposes if a security incident occurs or your network is compromised."
  enabled                  = true
  function_as_control      = false
  name                     = "Log Profile should send logs for all activities"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nallActivities := {\"delete\",\"write\",\"action\"}\n\ncontainsAllActivities(logProfileResource, activityName) {\n\tcategory := logProfileResource.properties.categories[cat]\n\tlower(category) == activityName\n}\n\nresult = \"fail\" {\n\tcount(input.LogProfileResources) < 1\n}{\n\tlogProfileResource := input.LogProfileResources[reource]\t\n\tactivityName := allActivities[act]\n\tnot containsAllActivities(logProfileResource, activityName)\n}\n\ncurrentConfiguration := sprintf(\"The Log Profile is empty or not configured to send logs for all activities\",[])\nexpectedConfiguration := \"The Log Profile should be configured to send logs for all activities\"\n"
  remediation_instructions = "Perform the following command to enable the Log Profile for all activities via Azure CLI:  \n```  \naz monitor log-profiles create \\\n  --categories [\"Delete\",\"Write\",\"Action\"] \\\n  --days <numberOfRetentionDays> \\\n  --enabled true \\\n  --location <location> \\\n  --locations <locations> \\\n  --name {{subscriptionName}} \\\n  --service-bus-rule-id \"/<serviceBusID>/resourceGroups/<resourceGroup>/providers/Microsoft.EventHub/namespaces/<namespace>/authorizationrules/RootManageSharedAccessKey\"\n```\n"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["Microsoft.Subscription"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.common as commonLib\nimport data.generic.terraform as terraLib\nimport future.keywords.every\n\nallActivities := {\"Delete\", \"Write\", \"Action\"}\n\ncontainsAllactivities(resource) {\n\tevery activity in allActivities {\n\t\tactivity in resource.categories\n\t}\n}\n\n\nWizPolicy[result] {\n\tdocument := input.document[i]\n\tresource := document.resource.azurerm_monitor_log_profile[name]\n\tnot containsAllactivities(resource)\n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"resourceName\": terraLib.get_resource_name(resource, name),\n\t\t\"searchKey\": sprintf(\"azurerm_monitor_log_profile[%s]\", [name]),\n\t\t\"issueType\": \"MissingAttribute\",\n\t\t\"keyExpectedValue\": sprintf(\"'azurerm_monitor_log_profile[%s]' is not configured to send logs for all activities\", [name]),\n\t\t\"keyActualValue\": sprintf(\"'azurerm_monitor_log_profile[%s]' should be configured to send logs for all activities\", [name]),\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n"
    remediation_instructions = "resource \"azurerm_monitor_log_profile\" \"example_log_profile\" {\n  categories = [\n    \"Action\",\n    \"Delete\",\n    \"Write\",\n  ]\n}"
    type                     = "TERRAFORM"
  }
}

# __generated__ by Terraform from "c50167b1-fffd-4b3e-9485-6329cfa1ab90"
resource "wiz_cloud_configuration_rule" "ccn_884a_mps4r1" {
  description              = "This rule checks if the Virtual Network is protected by Azure DDoS Protection Standard.    \nThis rule fails if `enableDdosProtection` is set to `false` or doesn't exist, or if `ddosProtectionPlan.id` is set to `false` or doesn't exist.  \nEnable Azure DDoS Protection Standard to protect your public IP resources in the virtual network from distributed denial of service (DDoS) attacks.  \nDDoS attacks exhaust an application's resources and make the application unavailable to legitimate users.  \nIt is recommended to enable DDoS protection with a DDoS protection plan on the Virtual Network (VNet)."
  enabled                  = true
  function_as_control      = false
  name                     = "Virtual Network DDoS Protection should be enabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nresult = \"fail\" {\n\tnot input.properties.enableDdosProtection\n}{\n\tnot input.properties.ddosProtectionPlan.id\n}\n\ncurrentConfiguration := sprintf(\"'enableDdosProtection': '%v'\", [input.properties.enableDdosProtection])\nexpectedConfiguration := \"'enableDdosProtection' should be 'true' and 'ddosProtectionPlan.id' should exist\""
  remediation_instructions = "Perform the following CLI commands to enable DDoS Protection on the Virtual Network via Azure CLI:    \n1. Use the following command to create a DDoS protection plan.    \n**Note:** A DDoS plan can be used for more than one Virtual Network, so if you already have a DDoS plan that you want to use, skip to the next step.  \n```  \naz network ddos-protection create \\\n    --resource-group {{resourceGroup}} \\\n    --name <DDosProtectionPlanName> \\\n    --vnets {{vnetName}}  \n```  \n2. Use the following command to enable the DDoS protection on the VNet.  \n```  \naz network vnet update \\\n    --resource-group {{resourceGroup}} \\\n    --name {{vnetName}} \\\n    --ddos-protection-plan <DDosProtectionPlanName> \\\n    --ddos-protection true  \n```  \nYou may validate that the VNet is now protected by using the following command:  \n```  \naz network ddos-protection show \\\n    --resource-group {{resourceGroup}} \\\n    --name <DDosProtectionPlanName>  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["Microsoft.Network/virtualNetworks"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.common as common_lib\nimport data.generic.terraform as terraLib\n\nWizPolicy[result] {\n\tdocument := input.document[i]\n\tresource := document.resource.azurerm_virtual_network[name]\n\n\tnot terraLib.validKey(resource, \"ddos_protection_plan\")\n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"resourceName\": terraLib.get_resource_name(resource, name),\n\t\t\"searchKey\": sprintf(\"azurerm_virtual_network[%s]\", [name]),\n\t\t\"issueType\": \"MissingAttribute\",\n\t\t\"keyExpectedValue\": sprintf(\"'azurerm_virtual_network[%s].ddos_protection_plan' should be defined and not null\", [name]),\n\t\t\"keyActualValue\": sprintf(\"'azurerm_virtual_network[%s].ddos_protection_plan' is undefined or null\", [name]),\n\t\t\"searchLine\": common_lib.build_search_line([\"resource\", \"azurerm_virtual_network\", name], []),\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n\nWizPolicy[result] {\n\tdocument := input.document[i]\n\tresource := document.resource.azurerm_virtual_network[name]\n\n\tterraLib.getValueArrayOrObject(resource.ddos_protection_plan).enable == false\n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"resourceName\": terraLib.get_resource_name(resource, name),\n\t\t\"searchKey\": sprintf(\"azurerm_virtual_network[%s].ddos_protection_plan.enable\", [name]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"'azurerm_virtual_network[%s].ddos_protection_plan.enable' should be set to true\", [name]),\n\t\t\"keyActualValue\": sprintf(\"'azurerm_virtual_network[%s].ddos_protection_plan.enable' is set to false\", [name]),\n\t\t\"searchLine\": common_lib.build_search_line([\"resource\", \"azurerm_virtual_network\", name, \"ddos_protection_plan\", \"enable\"], []),\n\t\t\"remediation\": json.marshal({\n\t\t\t\"before\": \"false\",\n\t\t\t\"after\": \"true\"\n\t\t}),\n\t\t\"remediationType\": \"update\",\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n"
    remediation_instructions = null
    type                     = "TERRAFORM"
  }
}

# __generated__ by Terraform from "fdb0115d-6c21-43e4-8c50-7c84b439890b"
resource "wiz_cloud_configuration_rule" "ccn_884a_opmon3r4" {
  description              = "This rule checks whether the Microsoft Defender for Cloud Defender plan is set to `On` for all supported services.  \nThis rule fails if any of the `Pricings.properties.pricingTier` fields are not set to `Standard`, unless it's a deprecated plan (see the rule logic to view the list of deprecated Defender plans).  \nMicrosoft Defender provides advanced security capabilities like threat intelligence, anomaly detection, and behavior analytics.  \nIt is recommended to enable Microsoft Defender for all Azure-supported services."
  enabled                  = true
  function_as_control      = false
  name                     = "Microsoft Defender for Cloud plans should be set to 'On' for all services"
  opa_policy               = "package wiz\n\nimport future.keywords.in\n\ndefault result = \"pass\"\n\ndefenderForCloudDisabledForSupportedServices[resourceName] {\n\tpricing := input.Pricings[price]\n\tresourceName := pricing.name\n\tdeprecatedServices := {\"ContainerRegistry\", \"KubernetesService\", \"Dns\"}\n\tnot resourceName in deprecatedServices\n\tlower(pricing.properties.pricingTier) != \"standard\"\n} \n\nresult = \"fail\" {\n\tcount(defenderForCloudDisabledForSupportedServices) > 0\n}\n\ncurrentConfiguration := sprintf(\"The following services are not on the Standard tier: '%v'\", [concat(\"', '\", defenderForCloudDisabledForSupportedServices)])\nexpectedConfiguration := \"All supported services should be set to the Standard tier\""
  remediation_instructions = "To enable Defender plans you need to set the pricing tier from Free to Standard for the service.  \nPerform the following command to enable Defender plans for each of the listed below Azure services via Azure CLI:\n```\naz security pricing create /\n\t--name <service> /\n\t--tier standard\n```\n{{uncompliantResources}}\n\n>**Note**  \nThis rule is configured to pass only Azure subscriptions that have enabled **all** Defender plans of the supported services."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["Microsoft.Subscription"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.common as common_lib\nimport data.generic.azureresourcemanager as arm_lib\n\nWizPolicy[result] {\n\tdoc := input.document[i]\n\n\t[path, value] = walk(doc)\n\n\tvalue.type == \"Microsoft.Security/pricings\"\n\t[val, val_type] := arm_lib.getDefaultValueFromParametersIfPresent(doc, value.properties.pricingTier)\n\tlower(val) != \"standard\"\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": value.name,\n\t\t\"searchKey\": sprintf(\"%s.name=%s.properties.pricingTier\", [common_lib.concat_path(path), value.name]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": \"'pricingTier' should be set to standard\",\n\t\t\"keyActualValue\": sprintf(\"'pricingTier' %s is set to %s\", [val_type, val]),\n\t\t\"searchLine\": common_lib.build_search_line(path, [\"properties\", \"pricingTier\"]),\n\t\t\"resourceTags\": object.get(value, \"tags\", {}),\n\t}\n}\n"
    remediation_instructions = null
    type                     = "AZURE_RESOURCE_MANAGER"
  }
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.terraform as terraLib\nimport data.generic.common as common_lib\n\nWizPolicy[result] {\n\tresource := input.document[i].resource.azurerm_security_center_subscription_pricing[name]\n\n\ttier := lower(resource.tier)\n\ttier == \"free\"\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": terraLib.get_resource_name(resource, name),\n\t\t\"searchKey\": sprintf(\"azurerm_security_center_subscription_pricing[%s].tier\", [name]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"'azurerm_security_center_subscription_pricing.%s.tier' is 'Standard'\", [name]),\n\t\t\"keyActualValue\": sprintf(\"'azurerm_security_center_subscription_pricing.%s.tier' is 'Free'\", [name]),\n\t\t\"searchLine\": common_lib.build_search_line([\"resource\",\"azurerm_security_center_subscription_pricing\",name, \"tier\"], []),\n\t\t\"remediation\": json.marshal({\n\t\t\t\"before\": sprintf(\"%s\",[resource.tier]),\n\t\t\t\"after\": \"Standard\"\n\t\t}),\n\t\t\"remediationType\": \"update\",\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n"
    remediation_instructions = null
    type                     = "TERRAFORM"
  }
}

# __generated__ by Terraform from "f60fd8ac-5373-4514-9727-4ca1938551ba"
resource "wiz_cloud_configuration_rule" "ccn_884a_opmon2r3" {
  description              = "Subscription Activity Logs are platform logs that provide insight into subscription-level events. \nThese logs contain information about operations on each resource in your subscription in addition to updates on Service Health events.\n\n>**Note**  \n>This rule should always pass on every Subscription since the logs are enabled by default and can't be disabled."
  enabled                  = true
  function_as_control      = false
  name                     = "Subscription activity logs should be enabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nis_subscription {\n    input.subscriptionId\n}\n\nresult = \"fail\" {\n    not is_subscription\n}\n\n#  Microsoft Entra ID (AAD) subscription logs are enabled by default and can't be disabled"
  remediation_instructions = null
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["Microsoft.Subscription"]
}

# __generated__ by Terraform from "f713df96-c6db-4eec-b55b-a69ee75e3b72"
resource "wiz_cloud_configuration_rule" "ccn_884a_mpcom2r1" {
  description              = "This rule checks if the Virtual Network contains a Peering that is disconnected.  \nThis rule fails if `peeringState` exists and is set to `Disconnected`.  \nVirtual network peering enables you to connect two Azure virtual networks so that the resources in these networks are directly connected. Typically, the disconnection happens when a peering configuration is deleted on one virtual network, and the other virtual network reports the peering status as disconnected."
  enabled                  = true
  function_as_control      = false
  name                     = "Virtual Network peering should be connected"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nresult = \"fail\"{\n\tlower(input.properties.virtualNetworkPeerings[_].properties.peeringState) == \"disconnected\"\n}\n\ncurrentConfiguration := \"'peeringState': 'Disconnected'\"\nexpectedConfiguration := \"If 'peeringState' exists it should be set to 'Connected'\""
  remediation_instructions = "Click [here](https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-troubleshoot-peering-issues) to view Azure's virtual network peering troubleshoot guide."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["Microsoft.Network/virtualNetworks"]
}

# __generated__ by Terraform from "56d4b85d-b01f-40ef-8ce4-2c12934e957c"
resource "wiz_cloud_configuration_rule" "ccn_884a_mpcom1r3" {
  description              = "This rule checks whether the Network Security Group UDP access from the internet is restricted.  \nThis rule fails if the Network Security Group allows inbound traffic from the internet using the UDP protocol.  \nRestricting access from the internet reduces susceptibility to security risks such as DDoS attacks and avoids data exposure.  \nYou should ensure UDP access is restricted and only allowed from specific sources."
  enabled                  = true
  function_as_control      = false
  name                     = "Network Security Group UDP Services should be restricted from the Internet"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nresult = \"fail\" {\n    some i\n    sg := input.properties.securityRules[i]\n    checkConfiguration(sg)\n}\n\ncheckConfiguration(sg) {\n    sg.properties.access == \"Allow\"\n    sg.properties.direction == \"Inbound\"\n\n    checkOpenToInternet(sg.properties.sourceAddressPrefix)\n    checkProtocol(sg.properties.protocol, \"UDP\")\n}\n\ncheckOpenToInternet(source_address_prefix) {\n    source_address_prefix == \"*\"\n}{\n    source_address_prefix == \"0.0.0.0/0\"\n}{\n    source_address_prefix == \"/0\"\n}{\n    source_address_prefix == \"Internet\"\n}{\n    source_address_prefix == \"Any\"\n}\n\ncheckProtocol(configProtocol, protocol) {\n    protocols = [protocol, \"*\"]\n    upper(configProtocol) == upper(protocols[_])\n}\n\ncurrentConfiguration := sprintf(\"Network Security Group UDP Services from the internet is not restricted\", [])\nexpectedConfiguration := sprintf(\"Network Security Group UDP Services should be restricted from the Internet\", [])\n"
  remediation_instructions = "Perform the following command to restrict the Network Security Group UDP access from the internet via Azure CLI:  \n```  \naz network nsg rule update --name <ruleName> --nsg-name {{nsgName}} --resource-group {{resourceGroupName}} --source-address-prefixes <source>  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["Microsoft.Network/networkSecurityGroups"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.terraform as terraLib\n\nWizPolicy[result] {\n\tresource := input.document[j].resource.azurerm_network_security_group[name]\n\tsecurityRule := input.document[i].resource.azurerm_network_security_rule[ruleName]\n\tterraLib.associatedResources(resource, securityRule, name, ruleName, \"name\", \"network_security_group_name\")\n\t\n\tupper(securityRule.access) == \"ALLOW\"\n\tupper(securityRule.direction) == \"INBOUND\"\n\tisRelevantProtocol(securityRule.protocol)\n\tisRelevantAddressPrefix(securityRule.source_address_prefix)\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": terraLib.get_resource_name(resource, name),\n\t\t\"searchKey\": sprintf(\"azurerm_network_security_rule[%s].protocol\", [ruleName]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"'azurerm_network_security_rule.%s.protocol' should be restricted\", [ruleName]),\n\t\t\"keyActualValue\": sprintf(\"'azurerm_network_security_rule.%s.protocol' is not restricted\", [ruleName]),\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n\nWizPolicy[result] {\n\tresource := terraLib.getArray(input.document[i].resource.azurerm_network_security_group[securityGroupName].security_rule)[rule]\n\tsecurityRuleName := resource.name\n\tupper(resource.access) == \"ALLOW\"\n\tupper(resource.direction) == \"INBOUND\"\n\tisRelevantProtocol(resource.protocol)\n\tisRelevantAddressPrefix(resource.source_address_prefix)\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": terraLib.get_resource_name(resource, securityGroupName),\n\t\t\"searchKey\": sprintf(\"azurerm_network_security_group[%s].security_rule[%s].protocol\", [securityGroupName, securityRuleName]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"'azurerm_network_security_group[%s].security_rule[%s].protocol' should be restricted\", [securityGroupName, securityRuleName]),\n\t\t\"keyActualValue\": sprintf(\"'azurerm_network_security_group[%s].security_rule[%s].protocol' is not restricted\", [securityGroupName, securityRuleName]),\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n\nisRelevantProtocol(protocol) = allow {\n\tupper(protocol) == \"UDP\"\n\tallow = true\n}{\n\tupper(protocol) == \"*\"\n\tallow = true\n}\n\nisRelevantAddressPrefix(prefix) = allow {\n\tprefix == \"*\"\n\tallow = true\n}\n\nelse = allow {\n\tprefix == \"0.0.0.0\"\n\tallow = true\n}\n\nelse = allow {\n\tendswith(prefix, \"/0\")\n\tallow = true\n}\n\nelse = allow {\n\tlower(prefix) == \"internet\"\n\tallow = true\n}\n\nelse = allow {\n\tlower(prefix) == \"any\"\n\tallow = true\n}\n"
    remediation_instructions = null
    type                     = "TERRAFORM"
  }
}

# __generated__ by Terraform from "260aa654-3850-4d91-88d4-9661986e230d"
resource "wiz_cloud_configuration_rule" "ccn_884a_acc6r4" {
  description              = "This rule checks whether the Conditional Access Policy requires MFA for all users.  \nThis rule fails if the policy has all of the following:\n* `applications.includeApplications` contains `All`\n* `users.includeUsers` contains `All`\n* `builtInControls` contains `mfa` or `authenticationStrength.requirementsSatisfied` contains `mfa`\n* `state` is `enabled`\n\n>**Note**  \nThis rule does not indicate a misconfiguration and is used as part of Control `wc-id-1232`."
  enabled                  = true
  function_as_control      = false
  name                     = "Conditional Access Policy requires MFA for all users"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nconditions := input.conditions\n\nrequireMfaForAllUsers {\n\tlower(conditions.applications.includeApplications[_]) == \"all\"\n\tlower(conditions.users.includeUsers[_]) == \"all\"\n\tlower(input.grantControls.builtInControls[_]) == \"mfa\"\n\tlower(input.state) == \"enabled\"\n}{\n\tlower(conditions.applications.includeApplications[_]) == \"all\"\n\tlower(conditions.users.includeUsers[_]) == \"all\"\n\tlower(input.grantControls.authenticationStrength.requirementsSatisfied) == \"mfa\"\n\tlower(input.state) == \"enabled\"\n}\n\n# This rule fails if the Conditional Access Policy requires MFA for all users.\nresult = \"fail\" {\n\trequireMfaForAllUsers\n}\n\ncurrentConfiguration := sprintf(\"'%v' policy requires MFA for all users\", [input.displayName])"
  remediation_instructions = ">**Note**  \nThis rule does not indicate a misconfiguration and is used as part of a control."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "INFORMATIONAL"
  target_native_types      = ["ConditionalAccessPolicy"]
}

# __generated__ by Terraform from "02555cd3-6bed-4498-97ce-9642145c1922"
resource "wiz_cloud_configuration_rule" "ccn_884a_mpinfo9r1" {
  description              = "This rule checks whether the private endpoint that connects to Recovery Services vaults for backup is configured with a Private DNS Zone.  \nThis rule fails if the `groupIds` field of the private links service connections is set to `AzureBackup`, if the resource type is set to `Microsoft.RecoveryServices`, if the sub-resource type is set to `vaults`, and if the `customDnsConfigs` field has an `fqdn` field.  \nPrivate DNS records allow private connections to private endpoints. Private endpoint connections allow secure communication by enabling private connectivity without a need for public IP addresses in the source or destination."
  enabled                  = true
  function_as_control      = false
  name                     = "A private endpoint that connects to Recovery Services vaults for backup should be configured with a Private DNS Zone"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nvalidResourceType := \"Microsoft.RecoveryServices\"\nvalidSubResourceType := \"vaults\"\nvalidGroupId := \"AzureBackup\"\nproperties := input.properties\n\nresourceAssessed {\n\tid := properties.privateLinkServiceConnections[connection].properties.privateLinkServiceId\n\tresourceType := split(id, \"/\")[6]\n\tsubResourceType := split(id, \"/\")[7]\n\tresourceType == validResourceType\n\tsubResourceType == validSubResourceType\n\tproperties.privateLinkServiceConnections[connection].properties.groupIds[i] == validGroupId\n}\n\nresult = \"skip\" {\n\tnot resourceAssessed\n} else = \"fail\" {\n\tproperties.customDnsConfigs[config].fqdn\n}\n\ncurrentConfiguration := sprintf(\"The Private endpoint should be configured with a Private DNS Zone\", [])\nexpectedConfiguration := sprintf(\"Private endpoint with the %s group id should be configured with a Private DNS Zone\", [validGroupId])"
  remediation_instructions = "Perform the following command to configure the private endpoint with a Private DNS Zone via Azure CLI:  \n```  \naz network private-dns zone create --name <privateDnsZone> --resource-group {{resourceGroup}}  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "HIGH"
  target_native_types      = ["Microsoft.Network/privateEndpoints"]
}

# __generated__ by Terraform from "b86ff7f6-1ab7-4fd4-b269-f94228a1e5b6"
resource "wiz_cloud_configuration_rule" "ccn_884a_opmon2r8" {
  description              = "This rule checks whether the Web App has HTTP logging enabled.\n\nHTTP logging, also known as web server logging, can be enabled via the App Service Logs, or by configuring a Diagnostic setting that sends and stores the HTTP logs.\n\nThis rule fails unless any one of the following occurs:\n\n* `properties.siteConfig.httpLoggingEnabled` is set to `true`\n* `DiagnosticLogsConfiguration.properties.httpLogs.enabled` is set to `true`\n* `DiagnosticSettingsResources.properties.logs.category = AppServiceHTTPLogs` has `enabled` set to `true`\n\nWhen HTTP logging is enabled, the web server logs HTTP request and response information, providing valuable insights into how your application is performing and interacting with clients.\nThese logs help in tracking and understanding details about incoming requests and outgoing responses, including request methods, URLs, status codes, headers, and more. This information can be crucial for identifying issues, such as misconfigured routes, failed requests, or unexpected behavior.\n\nIt is recommended to enable HTTP logging to effectively manage, troubleshoot, and optimize your web application as well as investigate the logs for any malicious activity.\n\n>**Note**  \n>This rule only assesses Web Apps. Other App Services are skipped."
  enabled                  = true
  function_as_control      = false
  name                     = "Web App HTTP logging should be enabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nisWebApp {\n\tsplit(lower(input.kind), \",\")[i] == \"app\"\n}\n\nhttpLogsEnabled {\n\tinput.DiagnosticLogsConfiguration.properties.httpLogs[_].enabled\n}{\n\tinput.properties.siteConfig.httpLoggingEnabled\n}{\n\tdiagnosticSettingsLog := input.DiagnosticSettingsResources[_].properties.logs[log]\n\tlower(diagnosticSettingsLog.category) == \"appservicehttplogs\"\n\tdiagnosticSettingsLog.enabled\n}\n\nresult = \"skip\" { # Skip if not web app\n\tnot isWebApp\n} else = \"fail\" {\n\tnot httpLogsEnabled\n}\n\ncurrentConfiguration := \"HTTP logging should be enabled\"\nexpectedConfiguration := \"HTTP logging is disabled\"\n"
  remediation_instructions = "Perform the following command to enable HTTP logging for the Web App via Azure PowerShell:  \n```\nSet-AzWebApp \\\n\t-ResourceGroupName {{ResourceGroup}} \\\n\t-Name {{WebAppName}} \\\n\t-RequestTracingEnabled $true\n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["Microsoft.Web/sites"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.terraform as terraLib\nimport data.generic.common as common_lib\n\nnotHTTPLogs(resource) {\n\tcount(terraLib.getValueArrayOrObject(resource.logs).http_logs) > 0\n}\n\nWizPolicy[result] {\n\tdocument := input.document[i]\n\tresourceType := {\"azurerm_linux_web_app\", \"azurerm_windows_web_app\"}\n\tresource := document.resource[resourceType[idx]][name]\n\n\tnot notHTTPLogs(resource)\n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"searchKey\": sprintf(\"%s[%s].http_logs\", [resourceType[idx], name]),\n\t\t\"keyExpectedValue\": sprintf(\"'logs.http_logs' should be defined\", [name]),\n\t\t\"keyActualValue\": sprintf(\"'logs.http_logs' is not defined\", [name]),\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n"
    remediation_instructions = null
    type                     = "TERRAFORM"
  }
}

# __generated__ by Terraform from "c09c1d63-0e61-43e8-bc23-0531da56e9f6"
resource "wiz_cloud_configuration_rule" "ccn_884a_opmon3r2" {
  description              = "This rule checks whether the Network Security Group flow logs are configured.  \nThis rule fails if `FlowLogs` is `null`.  \nNetwork Security Group flow logs are a feature of Network Watcher that allows you to view log information about ingress and egress IP traffic through a Network Security Group.  \nLogs help detect and prevent future occurrences of things such as hacking, system failures, outages, or corruption of information."
  enabled                  = true
  function_as_control      = false
  name                     = "Network Security Group flow logs should be configured"
  opa_policy               = "package wiz\n\ndefault result := \"pass\"\n\nresult := \"fail\" {\n\tis_null(input.FlowLogs)\n}\n\ncurrentConfiguration := \"FlowLogs': 'null'\"\nexpectedConfiguration := \"'FlowLogs' should be configured\""
  remediation_instructions = "Perform the following command to enable Network Security Group flow logs via Azure CLI:  \n```  \naz network watcher flow-log create --location {{region}} --name <name> --enabled true --nsg {{nsgName}} --resource-group {{resourceGroupName}} --retention 90 --storage-account <storageAccount> --traffic-analytics true --workspace <workspace>  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["Microsoft.Network/networkSecurityGroups"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.terraform as terraLib\nimport data.generic.common as common_lib\n\nflowLogsExistsAndRefersWatcher(document, networkWatcher, watcherName) {\n\tflowLogs := document.resource.azurerm_network_watcher_flow_log[flowLogName]\n\tterraLib.associatedResources(networkWatcher, flowLogs, watcherName, flowLogName, \"name\", \"network_watcher_name\")\n}\n\nWizPolicy[result] {\n\tdocument := input.document[i]\n\tnetworkWatcher := document.resource.azurerm_network_watcher[watcherName]\n\t\n\tnot flowLogsExistsAndRefersWatcher(document, networkWatcher, watcherName)\n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"searchKey\": sprintf(\"azurerm_network_watcher[%s]\",[watcherName]),\n\t\t\"keyExpectedValue\": sprintf(\"azurerm_network_watcher[%s] should be configured with flow logs.\",[watcherName]),\n\t\t\"keyActualValue\": sprintf(\"azurerm_network_watcher[%s] is not configured with flow logs.\",[watcherName]),\n\t\t\"resourceTags\": object.get(networkWatcher, \"tags\", {}),\n\t\t}\n}\n"
    remediation_instructions = null
    type                     = "TERRAFORM"
  }
}

# __generated__ by Terraform from "f88c0c51-12b6-4eeb-98bf-fc6a4fe97ecd"
resource "wiz_cloud_configuration_rule" "ccn_884a_opmon2r5" {
  description              = "This rule checks whether the Storage logging is enabled for `Table` service for read, write, and delete requests.  \nThis rule fails if the Storage Account is not configured to log at least one type of request (`Delete`, `Read`, or `Write`).  \nThis rule checks both storage logging types (Classic and Azure Monitor).  \nThis rule skips irrelevant storage account types.  \nThe Azure Queue Storage service stores messages that can be read by anyone with access to the storage account. \nStorage Logging stores server-side recording details in the storage account for both successful and failed requests. The logs hold the details of `Read`, `Write`, and `Delete` operations against the queues."
  enabled                  = true
  function_as_control      = true
  name                     = "Storage Account logging should be enabled for Table service for read, write, and delete requests"
  opa_policy               = "package wiz\n\nimport future.keywords.in\n\ndefault result = \"pass\"\n\nservice := \"Table\"\nrequestType := {\"Read\", \"Write\", \"Delete\"}\nserviceString := sprintf(\"StorageResourceProvider%vServiceProperties\", [service])\nclassicLogging := input[serviceString].Logging\nnewLoggingString := sprintf(\"%vDiagnosticSettingsResources\", [service])\nnewLogging := input[newLoggingString]\nreleventStorageAccountKind := {\"Storage\", \"StorageV2\"} \n\nclassicLoggingDisabled(request){\n\tnot classicLogging[request]\n}{\n\tis_null(input[serviceString])\n}\n\nnewLoggingEnabled(request){\n\tcontains(newLogging[serviceLogs].id,lower(service))\n\tcontains(newLogging[serviceLogs].properties.logs[log].category, request)\n\tnewLogging[serviceLogs].properties.logs[log].enabled\n}\n\nnewLoggingDisabled(request){\n\tnot newLoggingEnabled(request)\n}{\n\tnewLogging == []\t\n}{\n\tnot newLogging \n}\n\nresult = \"skip\" { # skipping irrelevant storage account types\n\tnot input.kind in releventStorageAccountKind\n} else = \"fail\" {\n\tclassicLoggingDisabled(requestType[request])\n\tnewLoggingDisabled(requestType[request])\n}\n\ncurrentConfiguration := sprintf(\"Logging is disabled for %v service for %v requests\", [service, concat(\", \", requestType)])\nexpectedConfiguration := sprintf(\"Logging should be enabled for %v service for %v requests\", [service, concat(\", \", requestType)])\n"
  remediation_instructions = "Perform the following command to create/update the Diagnostic Settings to enable Storage logging for Table service for read, write, and delete requests via Azure CLI:  \n\n#### Diagnostic Settings - Azure Monitor  \nA. If you do not yet have Diagnostic Settings, use the following command. Otherwise, skip this step and use the command in step **B** instead.\n```\naz monitor diagnostic-settings create \\\n\t--resource /subscriptions/{{subscriptionId}}/resourcegroups/{{resourceGroup}}/providers/microsoft.storage/storageaccounts/{{storageAccount}}/tableservices/default \\\n\t--logs '[{\"category\": \"StorageRead\",\"enabled\": true,\"retentionPolicy\": {\"days\": <set the retention you want>,\"enabled\": false}},{\"category\": \"StorageWrite\",\"enabled\": true,\"retentionPolicy\": {\"days\": <set the retention you want>,\"enabled\": false}},{\"category\": \"StorageDelete\",\"enabled\": true,\"retentionPolicy\": {\"days\": <set the retention you want>,\"enabled\": false}}]' \\\n\t--storage-account <Your Storage Account ID or name> || --workspace <Your Workspace ID or name> || --event-hub <Your Event Hub ID or name> || --event-hub-rule <Your Event Hub Rule ID>\n\t--name <set name for the diagnostic settings>\n```\n\nB. If you already have Diagnostic Settings, use the following command to update it:\n```\naz monitor diagnostic-settings update \\\n\t--resource /subscriptions/{{subscriptionId}}/resourcegroups/{{resourceGroup}}/providers/microsoft.storage/storageaccounts/{{storageAccount}}/tableservices/default \\\n\t--set logs='[{\"category\": \"StorageRead\",\"enabled\": true,\"retentionPolicy\": {\"days\": <set the retention you want>,\"enabled\": false}},{\"category\": \"StorageWrite\",\"enabled\": true,\"retentionPolicy\": {\"days\": <set the retention you want>,\"enabled\": false}},{\"category\": \"StorageDelete\", \"enabled\": true,\"retentionPolicy\": {\"days\": <set the retention you want>,\"enabled\": false}}]' \\\n\t--name <your diagnostic settings name>\n```\n\n#### Diagnostic Settings - Classic\nUse the following command if you prefer enabling Diagnostic Settings - Classic:\n```  \naz storage logging update \\\n\t--account-name {{storageAccount}} \\\n\t--account-key <your Storage Account Key> \\\n\t--services t \\\n\t--log rwd \\\n\t--retention <set the retention you want>  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["Microsoft.Storage/storageAccounts"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.terraform as terraLib\nimport future.keywords.in\n\n# This rule will fail even if Classic logging is enlabed (casuing a FP),\n# as Terraform currently only supports Classic logging for Queue service.\n\nserviceType := \"table\"\nloggingTypes := [\"storagedelete\", \"storageread\", \"storagewrite\"]\n\nassociatedToDs(document, resource, name) {\n\tdiagnosticSetting := document.resource.azurerm_monitor_diagnostic_setting[dsName]\n\tcontains(lower(diagnosticSetting.target_resource_id), serviceType)\n\tterraLib.associatedResources(resource, diagnosticSetting, name, dsName, null, \"target_resource_id\")\n}\n\nallLoggingTypesEnabled(diagnosticSetting) {\n\tenabledLogs := diagnosticSetting.enabled_log \n\tlower(enabledLogs[_].category) == loggingTypes[0]\n\tlower(enabledLogs[_].category) == loggingTypes[1]\n\tlower(enabledLogs[_].category) == loggingTypes[2]\n}{\n\t# support for AzureRM versions lower than 4\n\tenabledLogs := diagnosticSetting.log \n\tlower(enabledLogs[i].category) == loggingTypes[0]\n\tenabledLogs[i].enabled == false\n\tlower(enabledLogs[j].category) == loggingTypes[1]\n\tenabledLogs[j].enabled == false\n\tlower(enabledLogs[k].category) == loggingTypes[2]\n\tenabledLogs[k].enabled == false\n}\n\n# This will match 'azurerm_storage_account' that is not associated to a\n# 'azurerm_monitor_diagnostic_setting' resource\nWizPolicy[result] {\n\tdocument := input.document[i]\n\tresource := document.resource.azurerm_storage_account[name]\n\n\tnot associatedToDs(document, resource, name)\n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"resourceName\": terraLib.get_resource_name(resource, name),\n\t\t\"searchKey\": sprintf(\"azurerm_storage_account[%s]\", [name]),\n\t\t\"keyExpectedValue\": sprintf(\"'azurerm_storage_account[%s]' is not associated to a 'azurerm_monitor_diagnostic_setting' resource for '%sServices' logging\", [name, serviceType]),\n\t\t\"keyActualValue\": sprintf(\"'azurerm_storage_account[%s]' should be associated to a 'azurerm_monitor_diagnostic_setting' resource for '%sServices' logging\", [name, serviceType]),\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n\n# This will match 'azurerm_storage_account' that is associated to a\n# 'azurerm_monitor_diagnostic_setting' resource that does not have all logging types enabled\nWizPolicy[result] {\n\tdocument := input.document[i]\n\tresource := document.resource.azurerm_storage_account[name]\n\tdiagnosticSetting := document.resource.azurerm_monitor_diagnostic_setting[dsName]\n\n\tterraLib.associatedResources(resource, diagnosticSetting, name, dsName, null, \"target_resource_id\")\n\tcontains(lower(diagnosticSetting.target_resource_id), serviceType)\n\tnot allLoggingTypesEnabled(diagnosticSetting)\n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"resourceName\": terraLib.get_resource_name(resource, name),\n\t\t\"searchKey\": sprintf(\"azurerm_monitor_diagnostic_setting[%s].enabled_log\", [dsName]),\n\t\t\"keyExpectedValue\": sprintf(\"'azurerm_monitor_diagnostic_setting[%s]' should enable %s logging for 'StorageRead', 'StorageWrite', and 'StorageDelete'\", [dsName, serviceType]),\n\t\t\"keyActualValue\": sprintf(\"'azurerm_monitor_diagnostic_setting[%s]' does not enable %s logging for Read, Write and/or Delete\", [dsName, serviceType]),\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n"
    remediation_instructions = null
    type                     = "TERRAFORM"
  }
}

# __generated__ by Terraform from "06537292-130c-41d6-a3f4-b3d2298dd035"
resource "wiz_cloud_configuration_rule" "ccn_884a_acc2r4" {
  description              = "This rule checks if there are any Access Reviews, which indicates PIM is in use"
  enabled                  = true
  function_as_control      = false
  name                     = " Microsoft Entra Privileged Identity Management (PIM) is recommended"
  opa_policy               = "package wiz\n\n# Default result is fail, as we're checking for the presence of PIM\ndefault result = \"fail\"\n\n# Check if there are any Access Reviews, which indicates PIM is in use\nresult = \"pass\" {\n    count(input.AccessReviews) > 0\n}\n\n# If AccessReviews is empty, PIM might not be configured\ncurrentConfiguration := sprintf(\"No Access Reviews found, which suggests Privileged Identity Management (PIM) might not be in use\", [])\nexpectedConfiguration := \"Microsoft Entra Privileged Identity Management (PIM) should be configured and used for managing privileged access\"\n\n# Additional context\nrecommendation := \"Enable and configure Microsoft Entra Privileged Identity Management (PIM) to enhance security by providing just-in-time privileged access management\""
  remediation_instructions = null
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["Microsoft.AzureActiveDirectory/tenants"]
}

# __generated__ by Terraform from "46785512-f9c2-4abd-8466-cc0e38f079eb"
resource "wiz_cloud_configuration_rule" "ccn_884a_opmon3r3" {
  description              = "This rule checks whether the Network Security Group flow logs are enabled.  \nThis rule fails if the `enabled` field is not set to `true`.  \nNetwork Security Group flow logs are a feature of Network Watcher that allows you to view log information about ingress and egress IP traffic through a Network Security Group. \nLogs help detect and prevent future occurrences of things such as hacking, system failures, outages, or corruption of information."
  enabled                  = true
  function_as_control      = false
  name                     = "Network Security Group flow logs should be enabled"
  opa_policy               = "package wiz\n\ndefault result = \"fail\"\n\nresult = \"pass\" {\n\tinput.FlowLogs[_].properties.enabled == true\n}\n\ncurrentConfiguration := sprintf(\"'FlowLogs.properties.enabled' is not set to 'true'\", [])\nexpectedConfiguration := sprintf(\"'FlowLogs.properties.enabled' should be set to 'true\", [])"
  remediation_instructions = "Perform the following command to create a flow log on a Network Security Group with traffic analytics enabled via Azure CLI:  \n```  \naz network watcher flow-log create --location {{region}} --name <name> --enabled true --nsg {{nsgName}} --resource-group {{resourceGroupName}} --retention 90 --storage-account <storageAccount> --traffic-analytics true --workspace <workspace>  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["Microsoft.Network/networkSecurityGroups"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.terraform as terraLib\nimport data.generic.common as common_lib\n\nWizPolicy[result] {\n\tnetwork := input.document[i].resource.azurerm_network_watcher_flow_log[name]\n\tnetwork.enabled == false\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": terraLib.get_resource_name(network, name),\n\t\t\"searchKey\": sprintf(\"azurerm_network_watcher_flow_log[%s].enable\", [name]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": \"azurerm_network_watcher_flow_log.enabled should be true\",\n\t\t\"keyActualValue\": \"azurerm_network_watcher_flow_log.enabled is false\",\n\t\t\"searchLine\": common_lib.build_search_line([\"resource\", \"azurerm_network_watcher_flow_log\", name, \"enabled\"], []),\n\t\t\"remediation\": json.marshal({\n\t\t\t\"before\": \"false\",\n\t\t\t\"after\": \"true\"\n\t\t}),\n\t\t\"remediationType\": \"update\",\n\t\t\"resourceTags\": object.get(network, \"tags\", {}),\n\t}\n}\n"
    remediation_instructions = "resource \"azurerm_network_watcher_flow_log\" \"example_flow_log\" {\n  enabled = true\n}"
    type                     = "TERRAFORM"
  }
}

# __generated__ by Terraform from "c31c0c26-dc24-41e2-b360-2f63031eb6c8"
resource "wiz_cloud_configuration_rule" "ccn_884a_mpcom1r2" {
  description              = "This rule checks whether the Network Security Group allows SSH access (TCP - port 22).  \nThis rule fails if the Network Security Group allows inbound access from 0.0.0.0/0 over TCP port 22.  \nAllowing unrestricted inbound access can increase the risk of malicious activities such as brute-force and denial of service attacks.  \nYou should ensure access is restricted and only allowed from specific sources, especially over protocols with high risk such as SSH."
  enabled                  = true
  function_as_control      = false
  name                     = "Network Security Group should restrict SSH access (TCP - port 22)"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\napplicationEndpoint := {\"0.0.0.0/0\", \"any\", \"*\", \"::/0\", \"internet\"}\n\nanyPort := \"*\"\n\nrestrictProtocols := {\n\t\"sshTcp\": {\n\t\t\"protocols\": {\"tcp\", \"-1\", \"6\", \"*\"},\n\t\t\"ports\": {22}\n\t}\n}\n\nportRange(portRange, port) {\n\tportRange == anyPort\n}{\n\tport == to_number(portRange)\n}{\n\tPortRangeToFrom := split(portRange, \"-\")\n\tto_number(PortRangeToFrom[0]) <= port\n\tto_number(PortRangeToFrom[1]) >= port\n}\n\nallPorts(permission, restrictPort) {\n\tportRange(permission.destinationPortRange, restrictPort)\n}{\n\tportRange(permission.destinationPortRanges[range], restrictPort)\n}\n\nallIps(permission) {\n\tapplicationEndpoint[lower(permission.sourceAddressPrefix)]\n}{\n\tapplicationEndpoint[lower(permission.sourceAddressPrefixes[prefix])]\n}\n\nlistRulesPriority(protocols, port, effect) = priorities { \n\tpriorities := [\n\t\tpriority | permission := input.properties.securityRules[Permissions].properties\n\t\tallIps(permission)\n\t\tlower(permission.direction) == \"inbound\"\n\t\tpermission.access == effect\n\t\tprotocols[protocol] == lower(permission.protocol)\n\t\tallPorts(permission, port)\n\t\tpriority := permission.priority\n\t]\n}\n\nresult = \"fail\" {\n\tmin(listRulesPriority(restrictProtocols[i].protocols, restrictProtocols[i].ports[_], \"Allow\")) < min(listRulesPriority(restrictProtocols[i].protocols, restrictProtocols[i].ports[_], \"Deny\"))\n}{\n\tcount(listRulesPriority(restrictProtocols[i].protocols, restrictProtocols[i].ports[_], \"Allow\")) > 0\n\tcount(listRulesPriority(restrictProtocols[i].protocols, restrictProtocols[i].ports[_], \"Deny\")) == 0\n}\n\ncurrentConfiguration := sprintf(\"Security Group allows unrestricted access\", [])\nexpectedConfiguration := sprintf(\"Security Group should not allow unrestricted access\", [])\n"
  remediation_instructions = "Perform the following command to restrict the Network Security Group SSH access from the internet via Azure CLI:  \n```  \naz network nsg rule update --name <ruleName> --nsg-name {{nsgName}} --resource-group {{resourceGroupName}} --source-address-prefixes <source>  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["Microsoft.Network/networkSecurityGroups"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.azureresourcemanager as arm_lib\nimport data.generic.common as common_lib\n\nWizPolicy[result] {\n\tdoc := input.document[i]\n\t[path, value] = walk(doc)\n\n\tvalue.type == \"Microsoft.Network/networkSecurityGroups\"\n\n\tproperties := value.properties.securityRules[x].properties\n\n\tproperties.access == \"Allow\"\n\tproperties.protocol == \"Tcp\"\n\tproperties.direction == \"Inbound\"\n\tarm_lib.contains_port(properties, 22)\n\tarm_lib.source_address_prefix_is_open(properties)\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": value.name,\n\t\t\"searchKey\": sprintf(\"%s.name={{%s}}.properties.securityRules\", [common_lib.concat_path(path), value.name]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"resource with type '%s' restricts access to SSH\", [value.type]),\n\t\t\"keyActualValue\": sprintf(\"resource with type '%s' does not restrict access to SSH\", [value.type]),\n\t\t\"searchLine\": common_lib.build_search_line(path, [\"properties\", \"securityRules\", x, \"properties\"]),\n\t\t\"resourceTags\": object.get(value, \"tags\", {}),\n\t}\n}\n\nWizPolicy[result] {\n\tdoc := input.document[i]\n\t[path, value] = walk(doc)\n\n\ttypeInfo := arm_lib.get_sg_info(value)\n\n\tproperties := typeInfo.properties\n\n\tproperties.access == \"Allow\"\n\tproperties.protocol == \"Tcp\"\n\tproperties.direction == \"Inbound\"\n\tarm_lib.contains_port(properties, 22)\n\tarm_lib.source_address_prefix_is_open(properties)\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": value.name,\n\t\t\"searchKey\": sprintf(\"%s\", [typeInfo.path]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"resource with type '%s' restricts access to SSH\", [typeInfo.type]),\n\t\t\"keyActualValue\": sprintf(\"resource with type '%s' does not restrict access to SSH\", [typeInfo.type]),\n\t\t\"searchLine\": common_lib.build_search_line(path, typeInfo.sl),\n\t\t\"resourceTags\": object.get(value, \"tags\", {}),\n\t}\n}\n"
    remediation_instructions = null
    type                     = "AZURE_RESOURCE_MANAGER"
  }
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.terraform as terraLib\n\nWizPolicy[result] {\n\tresource := input.document[j].resource.azurerm_network_security_group[name]\n\tsecurityRule := input.document[i].resource.azurerm_network_security_rule[ruleName]\n\tterraLib.associatedResources(resource, securityRule, name, ruleName, \"name\", \"network_security_group_name\")\n\t\n\tupper(securityRule.access) == \"ALLOW\"\n\tupper(securityRule.direction) == \"INBOUND\"\n\tisRelevantProtocol(securityRule.protocol)\n\tisRelevantPort(securityRule.destination_port_range)\n\tisRelevantAddressPrefix(securityRule.source_address_prefix)\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": terraLib.get_resource_name(resource, name),\n\t\t\"resourceType\": \"azurerm_network_security_group\",\n\t\t\"searchKey\": sprintf(\"azurerm_network_security_rule[%s].destination_port_range\", [ruleName]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"'azurerm_network_security_rule.%s.destination_port_range' cannot be 22\", [ruleName]),\n\t\t\"keyActualValue\": sprintf(\"'azurerm_network_security_rule.%s.destination_port_range' might be 22\", [ruleName]),\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n\nWizPolicy[result] {\n\tresource := terraLib.getArray(input.document[i].resource.azurerm_network_security_group[securityGroupName].security_rule)[rule]\n\tsecurityRuleName := resource.name\n\tupper(resource.access) == \"ALLOW\"\n\tupper(resource.direction) == \"INBOUND\"\n\tisRelevantProtocol(resource.protocol)\n\tisRelevantPort(resource.destination_port_range)\n\tisRelevantAddressPrefix(resource.source_address_prefix)\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": terraLib.get_resource_name(resource, securityGroupName),\n\t\t\"searchKey\": sprintf(\"azurerm_network_security_group[%s].security_rule[%s].destination_port_range\", [securityGroupName, securityRuleName]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"'azurerm_network_security_group[%s].security_rule[%s].destination_port_range' should not be 22\", [securityGroupName, securityRuleName]),\n\t\t\"keyActualValue\": sprintf(\"'azurerm_network_security_group[%s].security_rule[%s].destination_port_range' might be 22\", [securityGroupName, securityRuleName]),\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n\nisRelevantProtocol(protocol) = allow {\n\tupper(protocol) != \"UDP\"\n\tupper(protocol) != \"ICMP\"\n\tallow = true\n}\n\nisRelevantPort(port) = allow {\n\tregex.match(\"(^|\\\\s|,)22(-|,|$|\\\\s)\", port)\n\tallow = true\n}\n\nelse = allow {\n\tports = split(port, \",\")\n\tsublist = split(ports[var], \"-\")\n\tto_number(trim(sublist[0], \" \")) <= 22\n\tto_number(trim(sublist[1], \" \")) >= 22\n\tallow = true\n}\n\nisRelevantAddressPrefix(prefix) = allow {\n\tprefix == \"*\"\n\tallow = true\n}\n\nelse = allow {\n\tprefix == \"0.0.0.0\"\n\tallow = true\n}\n\nelse = allow {\n\tendswith(prefix, \"/0\")\n\tallow = true\n}\n\nelse = allow {\n\tprefix == \"internet\"\n\tallow = true\n}\n\nelse = allow {\n\tprefix == \"any\"\n\tallow = true\n}\n"
    remediation_instructions = null
    type                     = "TERRAFORM"
  }
}

# __generated__ by Terraform from "3e406e65-c654-4e2a-ba59-0786738ab6bf"
resource "wiz_cloud_configuration_rule" "ccn_884a_acc6r3" {
  description              = "This rule checks whether the Conditional Access Policy requires MFA for administrators.  \nThis rule fails if the policy has all of the following:\n* `users.includeRoles` contains all the Microsoft Entra ID (AAD) administrator role IDs (as listed in the Rego code) OR if `users.includeUsers` contains `All`\n* `applications.includeApplications` contains `All`\n* `builtInControls` contains `mfa` or `authenticationStrength.requirementsSatisfied` contains `mfa`\n* `state` is `enabled`\n\n>**Note**  \n>* This rule does not indicate a misconfiguration and is used as part of Control `wc-id-1235`.\n>* The full list of Microsoft Entra ID built-in roles and their IDs can be found [here](https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference)."
  enabled                  = true
  function_as_control      = false
  name                     = "Conditional Access Policy requires MFA for administrators"
  opa_policy               = "package wiz\n\ndefault result := \"pass\"\n\nconditions := input.conditions\nincludedRoles := conditions.users.includeRoles\n\n# The full list of Microsoft Entra ID (AAD) built-in roles and their IDs can be found here:\n# https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference\nadminIds := {\n\t\"9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3\",\n\t\"fdd7a751-b60b-444a-984c-02652fe8fa1c\",\n\t\"c4e39bd9-1100-46d3-8c65-fb160da0071f\",\n\t\"b0f54661-2d74-4c50-afa3-1ec803f12efe\",\n\t\"158c047a-c907-4556-b7ef-446551a6b5f7\",\n\t\"b1be1c3e-b65d-4f19-8427-f6fa0d97feb9\",\n\t\"29232cdf-9323-42fd-ade2-1d097af3e4de\",\n\t\"729827e3-9c14-49f7-bb1b-9608f156bbb8\",\n\t\"966707d0-3269-4727-9be2-8c3a10f19b9d\",\n\t\"7be44c8a-adaf-4e2a-84d6-ab2649e08a13\",\n\t\"e8611ab8-c189-46e8-94e1-60213ab1f814\",\n\t\"194ae4cb-b126-40b2-bd5b-6091b380977d\",\n\t\"f28a1f50-f6e7-4571-818b-6a12f2af6b6c\",\n\t\"fe930be7-5e62-47db-91af-98c3a49a38b1\"\n}\n\nallAdminRoleIds[ids] {\n\tadminIds[includedRoles[roleId]]\n\tids := includedRoles[roleId]\n}\n\nrequireMfaForAdmins {\n\tcount(allAdminRoleIds) >= 14\n\tlower(conditions.applications.includeApplications[_]) == \"all\"\n\tlower(input.grantControls.builtInControls[_]) == \"mfa\"\n\tlower(input.state) == \"enabled\"\n}{\n\tlower(conditions.users.includeUsers[_]) == \"all\"\n\tlower(conditions.applications.includeApplications[_]) == \"all\"\n\tlower(input.grantControls.builtInControls[_]) == \"mfa\"\n\tlower(input.state) == \"enabled\"\n}{\n\tcount(allAdminRoleIds) >= 14\n\tlower(conditions.applications.includeApplications[_]) == \"all\"\n\tlower(input.grantControls.authenticationStrength.requirementsSatisfied) == \"mfa\"\n\tlower(input.state) == \"enabled\"\n}{\n\tlower(conditions.users.includeUsers[_]) == \"all\"\n\tlower(conditions.applications.includeApplications[_]) == \"all\"\n\tlower(input.grantControls.authenticationStrength.requirementsSatisfied) == \"mfa\"\n\tlower(input.state) == \"enabled\"\n}\n\n# This rule fails if the Conditional Access Policy requires MFA for administrators.\nresult := \"fail\" {\n\trequireMfaForAdmins\n}\n\ncurrentConfiguration := sprintf(\"'%v' policy requires MFA for admins\", [input.displayName])"
  remediation_instructions = ">**Note**  \nThis rule does not indicate a misconfiguration and is used as part of a Control."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "INFORMATIONAL"
  target_native_types      = ["ConditionalAccessPolicy"]
}

# __generated__ by Terraform from "b468ce14-a0a2-4e26-9766-e0ca0807e571"
resource "wiz_cloud_configuration_rule" "ccn_884a_acc6r1" {
  description              = "This rule checks if the Microsoft Entra ID (AAD) User is registered for MFA.  \nThis rule skips users where `accountEnabled` is `false`, and fails if `isMfaRegistered` is set to `false`.  \nMulti-factor authentication (MFA) adds an extra layer of protection on top of your user name and password. MFA provides increased security for your Azure account settings and resources.  \nIt is recommended to enforce Microsoft Entra ID user MFA via conditional access policies.\n>**Note**  \n>See [Control](https://app.wiz.io/issues#~(filters~(status~(equals~(~'OPEN~'IN_PROGRESS))~sourceRule~(equals~(~'wc-id-1232)))~groupBy~'none)) `wc-id-1232` to check which Azure Tenants don't have an active conditional access policy that requires MFA for all users.\n"
  enabled                  = true
  function_as_control      = true
  name                     = "Microsoft Entra ID (AAD) user should have MFA enabled"
  opa_policy               = "package wiz\n\ndefault result := \"pass\"\n\nhasMfa := input.isMfaRegistered\n\nresult := \"skip\"{\n\tinput.accountEnabled == false\n} else := \"fail\" {\n\thasMfa == false\n}\n\ncurrentConfiguration := sprintf(\"'isMfaRegistered: %v'\", [hasMfa])\nexpectedConfiguration := sprintf(\"'isMfaRegistered' should be 'true'\", [])\n"
  remediation_instructions = "It is best practice to enable Microsoft Entra User MFA by creating a Conditional Access policy that enforces it. See [Azure's guide](https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-azure-mfa) on how to properly configure this on your Tenant.\n\nIf you prefer to enable per-user Microsoft Entra MFA, click [here](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userstates)."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["Microsoft.AzureActiveDirectory/User"]
}

# __generated__ by Terraform from "90d46890-b6ff-4c72-8b48-be8a6580241c"
resource "wiz_cloud_configuration_rule" "ccn_884a_opmon2r6" {
  description              = "This rule checks whether the Storage logging is enabled for `Blob` service for read, write, and delete requests.  \nThis rule fails if the Storage Account is not configured to log at least one type of request (`Delete`, `Read`, or `Write`).  \nThis rule checks both storage logging types (Classic and Azure Monitor).  \nThis rule skips irrelevant storage account types.  \nThe Azure Queue Storage service stores messages that can be read by anyone with access to the storage account. \nStorage Logging stores server-side recording details in the storage account for both successful and failed requests. The logs hold the details of `Read`, `Write`, and `Delete` operations against the queues."
  enabled                  = true
  function_as_control      = false
  name                     = "Storage Account logging should be enabled for Blob service for read, write, and delete requests"
  opa_policy               = "package wiz\n\nimport future.keywords.in\n\ndefault result = \"pass\"\n\nservice := \"Blob\"\nrequestType := {\"Read\", \"Write\", \"Delete\"}\nserviceString := sprintf(\"StorageResourceProvider%vServiceProperties\", [service])\nclassicLogging := input[serviceString].Logging\nnewLoggingString := sprintf(\"%vDiagnosticSettingsResources\", [service])\nnewLogging := input[newLoggingString]\nreleventStorageAccountKind := {\"Storage\", \"StorageV2\"} \n\nclassicLoggingDisabled(request){\n\tnot classicLogging[request]\n}{\n\tis_null(input[serviceString])\n}\n\nnewLoggingEnabled(request){\n\tcontains(newLogging[serviceLogs].id,lower(service))\n\tcontains(newLogging[serviceLogs].properties.logs[log].category, request)\n\tnewLogging[serviceLogs].properties.logs[log].enabled\n}\n\nnewLoggingDisabled(request){\n\tnot newLoggingEnabled(request)\n}{\n\tnewLogging == []\t\n}{\n\tnot newLogging \n}\n\nresult = \"skip\" { # skipping irrelevant storage account types\n\tnot input.kind in releventStorageAccountKind\n} else = \"skip\" {\n\tis_null(input.AccountStorageServicesBlobServiceProperties)\n} else = \"fail\" {\n\tclassicLoggingDisabled(requestType[request])\n\tnewLoggingDisabled(requestType[request])\n}\n\ncurrentConfiguration := sprintf(\"Logging is disabled for %v service for %v requests\", [service, concat(\", \", requestType)])\nexpectedConfiguration := sprintf(\"Logging should be enabled for %v service for %v requests\", [service, concat(\", \", requestType)])\n"
  remediation_instructions = "Perform the following command to create/update the Diagnostic Settings to enable Storage logging for Blob service for read, write, and delete requests via Azure CLI:\n\n#### Diagnostic Settings - Azure Monitor\nA. If you do not yet have Diagnostic Settings, use the following command. Otherwise, skip this step and use the command in step **B** instead.\n```\naz monitor diagnostic-settings create \\\n\t--resource /subscriptions/{{subscriptionId}}/resourcegroups/{{resourceGroup}}/providers/microsoft.storage/storageaccounts/{{storageAccount}}/blobservices/default \\\n\t--logs '[{\"category\": \"StorageRead\",\"enabled\": true,\"retentionPolicy\": {\"days\": <set the retention you want>,\"enabled\": false}},{\"category\": \"StorageWrite\",\"enabled\": true,\"retentionPolicy\": {\"days\": <set the retention you want>,\"enabled\": false}},{\"category\": \"StorageDelete\",\"enabled\": true,\"retentionPolicy\": {\"days\": <set the retention you want>,\"enabled\": false}}]' \\\n\t--storage-account <Your Storage Account ID or name> || --workspace <Your Workspace ID or name> || --event-hub <Your Event Hub ID or name> || --event-hub-rule <Your Event Hub Rule ID>\n\t--name <set name for the diagnostic settings>\n```\n\nB. If you already have Diagnostic Settings, use the following command to update it:\n```\naz monitor diagnostic-settings update \\\n\t--resource /subscriptions/{{subscriptionId}}/resourcegroups/{{resourceGroup}}/providers/microsoft.storage/storageaccounts/{{storageAccount}}/blobservices/default \\\n\t--set logs='[{\"category\": \"StorageRead\",\"enabled\": true,\"retentionPolicy\": {\"days\": <set the retention you want>,\"enabled\": false}},{\"category\": \"StorageWrite\",\"enabled\": true,\"retentionPolicy\": {\"days\": <set the retention you want>,\"enabled\": false}},{\"category\": \"StorageDelete\", \"enabled\": true,\"retentionPolicy\": {\"days\": <set the retention you want>,\"enabled\": false}}]' \\\n\t--name <your diagnostic settings name>\n```\n\n#### Diagnostic Settings - Classic\nUse the following command if you prefer enabling Diagnostic Settings - Classic:\n```  \naz storage logging update \\\n\t--account-name {{storageAccount}} \\\n\t--account-key <your Storage Account Key> \\\n\t--services b \\\n\t--log rwd \\\n\t--retention <set the retention you want>  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["Microsoft.Storage/storageAccounts"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.terraform as terraLib\nimport future.keywords.in\n\n# This rule will fail even if Classic logging is enlabed (casuing a FP),\n# as Terraform currently only supports Classic logging for Queue service.\n\nserviceType := \"blob\"\nloggingTypes := [\"storagedelete\", \"storageread\", \"storagewrite\"]\n\nassociatedToDs(document, resource, name) {\n\tdiagnosticSetting := document.resource.azurerm_monitor_diagnostic_setting[dsName]\n\tcontains(lower(diagnosticSetting.target_resource_id), serviceType)\n\tterraLib.associatedResources(resource, diagnosticSetting, name, dsName, null, \"target_resource_id\")\n}\n\nallLoggingTypesEnabled(diagnosticSetting) {\n\tenabledLogs := diagnosticSetting.enabled_log \n\tlower(enabledLogs[_].category) == loggingTypes[0]\n\tlower(enabledLogs[_].category) == loggingTypes[1]\n\tlower(enabledLogs[_].category) == loggingTypes[2]\n}{\n\t# support for AzureRM versions lower than 4\n\tenabledLogs := diagnosticSetting.log \n\tlower(enabledLogs[i].category) == loggingTypes[0]\n\tenabledLogs[i].enabled == false\n\tlower(enabledLogs[j].category) == loggingTypes[1]\n\tenabledLogs[j].enabled == false\n\tlower(enabledLogs[k].category) == loggingTypes[2]\n\tenabledLogs[k].enabled == false\n}\n\n# This will match 'azurerm_storage_account' that is not associated to a\n# 'azurerm_monitor_diagnostic_setting' resource\nWizPolicy[result] {\n\tdocument := input.document[i]\n\tresource := document.resource.azurerm_storage_account[name]\n\n\tnot associatedToDs(document, resource, name)\n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"searchKey\": sprintf(\"azurerm_storage_account[%s]\", [name]),\n\t\t\"keyExpectedValue\": sprintf(\"'azurerm_storage_account[%s]' is not associated to a 'azurerm_monitor_diagnostic_setting' resource for '%sServices' logging\", [name, serviceType]),\n\t\t\"keyActualValue\": sprintf(\"'azurerm_storage_account[%s]' should be associated to a 'azurerm_monitor_diagnostic_setting' resource for '%sServices' logging\", [name, serviceType]),\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n\n# This will match 'azurerm_storage_account' that is associated to a\n# 'azurerm_monitor_diagnostic_setting' resource that does not have all logging types enabled\nWizPolicy[result] {\n\tdocument := input.document[i]\n\tresource := document.resource.azurerm_storage_account[name]\n\tdiagnosticSetting := document.resource.azurerm_monitor_diagnostic_setting[dsName]\n\n\tterraLib.associatedResources(resource, diagnosticSetting, name, dsName, null, \"target_resource_id\")\n\tcontains(lower(diagnosticSetting.target_resource_id), serviceType)\n\tnot allLoggingTypesEnabled(diagnosticSetting)\n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"searchKey\": sprintf(\"azurerm_monitor_diagnostic_setting[%s].enabled_log\", [dsName]),\n\t\t\"keyExpectedValue\": sprintf(\"'azurerm_monitor_diagnostic_setting[%s]' should enable %s logging for 'StorageRead', 'StorageWrite', and 'StorageDelete'\", [dsName, serviceType]),\n\t\t\"keyActualValue\": sprintf(\"'azurerm_monitor_diagnostic_setting[%s]' does not enable %s logging for Read, Write and/or Delete\", [dsName, serviceType]),\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n"
    remediation_instructions = null
    type                     = "TERRAFORM"
  }
}

# __generated__ by Terraform from "6c340237-554b-4a57-8e55-c0cf7f10a5d2"
resource "wiz_cloud_configuration_rule" "ccn_884a_mpinfo9r3" {
  description              = "This rule checks whether the Azure Backup Vault soft delete option is enabled.  \nThis rule fails if the field `SoftDeleteSettings.state` is not set to `on` or `alwayson`.  \nSoft delete provides a layer of defense against accidental or intentional data deletion, by retaining deleted data for a specified period of time. This feature is especially critical in the event of a cyberattack, where hackers may attempt to delete or corrupt data to cause damage or demand a ransom.  \nSoft delete ensures that important data is not lost forever and can be easily recovered, reducing the impact of such attacks."
  enabled                  = true
  function_as_control      = false
  name                     = "Backup Vault soft delete should be enabled"
  opa_policy               = "package wiz\n\nimport future.keywords.in\n\ndefault result = \"pass\"\n\nresult = \"fail\" {\n \tnot lower(input.Properties.SecuritySettings.SoftDeleteSettings.State) in [\"on\", \"alwayson\"]\n}\n\ncurrentConfiguration := \"Backup Vault soft delete is disabled\"\nexpectedConfiguration := \"Backup Vault soft delete should be enabled\""
  remediation_instructions = "Perform the following command to enable the soft delete option on the Backup Vault via Azure CLI:  \n```\naz dataprotection backup-vault update --ids {{id}} --soft-delete-state On \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["Microsoft.DataProtection/backupVaults"]
}

# __generated__ by Terraform from "6aaac733-2795-49e4-8aef-6485c30272e0"
resource "wiz_cloud_configuration_rule" "ccn_884a_opexp11r1" {
  description              = "This rule checks whether the Key Vault is using Role-Based Access Control (RBAC) for authorization.  \nThis rule fails if the `enableRbacAuthorization` property is not set to `true`.  \nAzure Key Vault supports two types of authorization: Azure Active Directory (Azure AD) RBAC and Key Vault access policies. Azure AD RBAC is the recommended authorization method as it provides superior security and ease of use over access policies.  \nUsing RBAC allows for more granular control over access to secrets, keys, and certificates stored in a key vault. It also integrates better with other Azure services and provides a consistent authorization model across Azure resources.  \nIt is recommended to use RBAC authorization for your Key Vaults to improve security and simplify access management."
  enabled                  = true
  function_as_control      = false
  name                     = "Key Vault should not use a legacy authorization method"
  opa_policy               = "package wiz\n\ndefault result := \"pass\"\n\nresult := \"fail\" {\n\tnot input.properties.enableRbacAuthorization\n}\n\ncurrentConfiguration := \"'enableRbacAuthorization': false\"\nexpectedConfiguration := \"'enableRbacAuthorization' should be set to true\""
  remediation_instructions = "Perform the following command to enable RBAC authorization for the Key Vault via Azure CLI:\n\n```\naz keyvault update \\\n    --name {{name}} \\\n    --resource-group {{resourceGroup}} \\\n    --enable-rbac-authorization true\n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["Microsoft.KeyVault/vaults"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.common as common_lib\nimport data.generic.terraform as terraLib\n\nWizPolicy[result] {\n\tresource := input.document[i].resource.azurerm_key_vault[name]\n\tnot common_lib.valid_key(resource, \"enable_rbac_authorization\")\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": terraLib.get_resource_name(resource, name),\n\t\t\"searchKey\": sprintf(\"azurerm_key_vault[%s]\", [name]),\n\t\t\"issueType\": \"MissingAttribute\",\n\t\t\"keyExpectedValue\": sprintf(\"'azurerm_key_vault[%s].enable_rbac_authorization' should be set to true\", [name]),\n\t\t\"keyActualValue\": sprintf(\"'azurerm_key_vault[%s].enable_rbac_authorization' is undefined\", [name]),\n\t\t\"remediation\": \"enable_rbac_authorization = true\",\n\t\t\"remediationType\": \"addition\",\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n\nWizPolicy[result] {\n\tresource := input.document[i].resource.azurerm_key_vault[name]\n\tresource.enable_rbac_authorization == false\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": terraLib.get_resource_name(resource, name),\n\t\t\"searchKey\": sprintf(\"azurerm_key_vault[%s].enable_rbac_authorization\", [name]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"'azurerm_key_vault[%s].enable_rbac_authorization' should be set to true\", [name]),\n\t\t\"keyActualValue\": sprintf(\"'azurerm_key_vault[%s].enable_rbac_authorization' is set to false\", [name]),\n\t\t\"remediation\": json.marshal({\n\t\t\t\"before\": \"false\",\n\t\t\t\"after\": \"true\"\n\t\t}),\n\t\t\"remediationType\": \"update\",\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n"
    remediation_instructions = "resource \"azurerm_key_vault\" \"example_keyvault\" {\n  enable_rbac_authorization = true\n}"
    type                     = "TERRAFORM"
  }
}

# __generated__ by Terraform from "112aa076-4e69-4e8e-9e2a-4c307057961f"
resource "wiz_cloud_configuration_rule" "ccn_884a_acc5r1" {
  description              = "This rule checks if the Microsoft Entra ID (AAD) guest User is registered for MFA.  \nThis rule skips no guest users and fails if `isMfaRegistered` is set to `false`.  \nMulti-factor authentication (MFA) adds an extra layer of protection on top of your user name and password. MFA provides increased security for your Azure account settings and resources.  \nIt is recommended to enforce Microsoft Entra ID user MFA via conditional access policies.\n>**Note**  \n>See [Control](https://app.wiz.io/issues#~(filters~(status~(equals~(~'OPEN~'IN_PROGRESS))~sourceRule~(equals~(~'wc-id-1232)))~groupBy~'none)) `wc-id-1232` to check which Azure Tenants don't have an active conditional access policy that requires MFA for all users.\n"
  enabled                  = true
  function_as_control      = true
  name                     = "Microsoft Entra ID (AAD) guest user should have MFA enabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nresult = \"skip\" {\n    lower(input.userType) != \"guest\"\n} else = \"fail\" {\n    not input.isMfaRegistered\n}\n\ncurrentConfiguration := sprintf(\"User '%s' is a %s guest user with MFA %s\", [input.userPrincipalName, lower(input.userType), input.isMfaRegistered])\nexpectedConfiguration := \"Guest users should have MFA enabled\""
  remediation_instructions = "It is best practice to enable Microsoft Entra User MFA by creating a Conditional Access policy that enforces it. See [Azure's guide](https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-azure-mfa) on how to properly configure this on your Tenant.\n\nIf you prefer to enable per-user Microsoft Entra MFA, click [here](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userstates)."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["Microsoft.AzureActiveDirectory/User"]
}

# __generated__ by Terraform from "a505e96c-46d6-413d-bca3-d9fe4e07875c"
resource "wiz_cloud_configuration_rule" "ccn_884a_opmon2r7" {
  description              = "This rule checks whether the Storage logging is enabled for `Queue` service for read, write, and delete requests.  \nThis rule fails if the Storage Account is not configured to log at least one type of request (`Delete`, `Read`, or `Write`).  \nThis rule checks both storage logging types (Classic and Azure Monitor).  \nThis rule skips irrelevant storage account types.  \nThe Azure Queue Storage service stores messages that can be read by anyone with access to the storage account. \nStorage Logging stores server-side recording details in the storage account for both successful and failed requests. The logs hold the details of `Read`, `Write`, and `Delete` operations against the queues."
  enabled                  = true
  function_as_control      = false
  name                     = "Storage Account logging should be enabled for Queue service for read, write, and delete requests"
  opa_policy               = "package wiz\n\nimport future.keywords.in\n\ndefault result = \"pass\"\n\nservice := \"Queue\"\nrequestType := {\"Read\", \"Write\", \"Delete\"}\nserviceString := sprintf(\"StorageResourceProvider%vServiceProperties\", [service])\nclassicLogging := input[serviceString].Logging\nnewLoggingString := sprintf(\"%vDiagnosticSettingsResources\", [service])\nnewLogging := input[newLoggingString]\nreleventStorageAccountKind := {\"Storage\", \"StorageV2\"} \n\nclassicLoggingDisabled(request){\n\tnot classicLogging[request]\n}{\n\tis_null(input[serviceString])\n}\n\nnewLoggingEnabled(request){\n\tcontains(newLogging[serviceLogs].id,lower(service))\n\tcontains(newLogging[serviceLogs].properties.logs[log].category, request)\n\tnewLogging[serviceLogs].properties.logs[log].enabled\n}\n\nnewLoggingDisabled(request){\n\tnot newLoggingEnabled(request)\n}{\n\tnewLogging == []\t\n}{\n\tnot newLogging \n}\n\nresult = \"skip\" { # skipping irrelevant storage account types\n\tnot input.kind in releventStorageAccountKind\n} else = \"skip\" {\n\tis_null(input.AccountStorageServicesQueueServiceProperties)\n} else = \"fail\" {\n\tclassicLoggingDisabled(requestType[request])\n\tnewLoggingDisabled(requestType[request])\n}\n\ncurrentConfiguration := sprintf(\"Logging is disabled for %v service for %v requests\", [service, concat(\", \", requestType)])\nexpectedConfiguration := sprintf(\"Logging should be enabled for %v service for %v requests\", [service, concat(\", \", requestType)])\n"
  remediation_instructions = "Perform the following command to create/update the Diagnostic Settings to enable Storage logging for Blob service for read, write, and delete requests via Azure CLI:\n\n#### Diagnostic Settings - Azure Monitor  \nA. If you do not yet have Diagnostic Settings, use the following command. Otherwise, skip this step and use the command in step **B** instead.\n```\naz monitor diagnostic-settings create \\\n\t--resource /subscriptions/{{subscriptionId}}/resourcegroups/{{resourceGroup}}/providers/microsoft.storage/storageaccounts/{{storageAccount}}/queueservices/default \\\n\t--logs '[{\"category\": \"StorageRead\",\"enabled\": true,\"retentionPolicy\": {\"days\": <set the retention you want>,\"enabled\": false}},{\"category\": \"StorageWrite\",\"enabled\": true,\"retentionPolicy\": {\"days\": <set the retention you want>,\"enabled\": false}},{\"category\": \"StorageDelete\",\"enabled\": true,\"retentionPolicy\": {\"days\": <set the retention you want>,\"enabled\": false}}]' \\\n\t--storage-account <Your Storage Account ID or name> || --workspace <Your Workspace ID or name> || --event-hub <Your Event Hub ID or name> || --event-hub-rule <Your Event Hub Rule ID>\n\t--name <set name for the diagnostic settings>\n```\n\nB. If you already have Diagnostic Settings, use the following command to update it:\n```\naz monitor diagnostic-settings update \\\n\t--resource /subscriptions/{{subscriptionId}}/resourcegroups/{{resourceGroup}}/providers/microsoft.storage/storageaccounts/{{storageAccount}}/queueservices/default \\\n\t--set logs='[{\"category\": \"StorageRead\",\"enabled\": true,\"retentionPolicy\": {\"days\": <set the retention you want>,\"enabled\": false}},{\"category\": \"StorageWrite\",\"enabled\": true,\"retentionPolicy\": {\"days\": <set the retention you want>,\"enabled\": false}},{\"category\": \"StorageDelete\", \"enabled\": true,\"retentionPolicy\": {\"days\": <set the retention you want>,\"enabled\": false}}]' \\\n\t--name <your diagnostic settings name>\n```\n\n#### Diagnostic Settings - Classic\nUse the following command if you prefer enabling Diagnostic Settings - Classic:\n```  \naz storage logging update \\\n\t--account-name {{storageAccount}} \\\n\t--account-key <your Storage Account Key> \\\n\t--services q \\\n\t--log rwd \\\n\t--retention <set the retention you want>  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["Microsoft.Storage/storageAccounts"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.common as common_lib\n\nWizPolicy[result] {\n\tcats := [\"StorageRead\", \"StorageWrite\", \"StorageDelete\"]\n\n\tdoc := input.document[i]\n\t[path, value] = walk(doc)\n\n\tvalue.type == \"Microsoft.Storage/storageAccounts/queueServices/providers/diagnosticsettings\"\n\n\tvalSlice := [x | x := {sprintf(\"%s\", [value.properties.logs[n].category]): value.properties.logs[n].enabled}]\n\n\tunionObject := {k: v |\n\t\tsome i, k\n\t\tv := valSlice[i][k]\n\t}\n\n\tissue := actual_issue(unionObject, cats[l])\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": value.name,\n\t\t\"searchKey\": sprintf(\"%s.name=%s.properties.logs.%s\", [common_lib.concat_path(path), value.name, cats[l]]),\n\t\t\"issueType\": issue.type,\n\t\t\"keyExpectedValue\": sprintf(\"'diagnosticsettings.properties.logs.%s' should be defined and enabled\", [cats[l]]),\n\t\t\"keyActualValue\": sprintf(\"'diagnosticsettings.properties.logs.%s' is %s\", [issue.msg]),\n\t\t\"searchLine\": common_lib.build_search_line(path, [\"properties\", \"logs\", cats[l]]),\n\t\t\"resourceTags\": object.get(value, \"tags\", {}),\n\t}\n}\n\nactual_issue(obj, key) = issue {\n\tnot common_lib.valid_key(obj, key)\n\tissue := {\"msg\": \"missing\", \"type\": \"MissingAttribute\"}\n} else = issue {\n\tobj[key] == false\n\tissue := {\"msg\": \"false\", \"type\": \"IncorrectValue\"}\n}\n"
    remediation_instructions = null
    type                     = "AZURE_RESOURCE_MANAGER"
  }
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.terraform as terraLib\nimport future.keywords.in\n\nserviceType := \"queue\"\nloggingTypes := [\"storagedelete\", \"storageread\", \"storagewrite\"]\nisTrue := {true, \"true\"}\nisFalse := {false, \"false\"}\n\nassociatedToDs(document, resource, name) {\n\tdiagnosticSetting := document.resource.azurerm_monitor_diagnostic_setting[dsName]\n\tcontains(lower(diagnosticSetting.target_resource_id), serviceType)\n\tterraLib.associatedResources(resource, diagnosticSetting, name, dsName, null, \"target_resource_id\")\n}\n\nallLoggingTypesEnabled(diagnosticSetting) {\n\tenabledLogs := diagnosticSetting.enabled_log \n\tlower(enabledLogs[_].category) == loggingTypes[0]\n\tlower(enabledLogs[_].category) == loggingTypes[1]\n\tlower(enabledLogs[_].category) == loggingTypes[2]\n}{\n\t# support for AzureRM versions lower than 4\n\tenabledLogs := diagnosticSetting.log \n\tlower(enabledLogs[i].category) == loggingTypes[0]\n\tenabledLogs[i].enabled in isFalse\n\tlower(enabledLogs[j].category) == loggingTypes[1]\n\tenabledLogs[j].enabled in isFalse\n\tlower(enabledLogs[k].category) == loggingTypes[2]\n\tenabledLogs[k].enabled in isFalse\n}\n\n# checks if classic logging is enabled (terraform only suports classic logging for Queue).\n# if classic logging is properly configured, the rule will not fail.\nClassicLoggingEnabledForAllTypes(resource) {\n\tqueueProperties := terraLib.getValueArrayOrObject(resource.queue_properties)\n\tlogging := terraLib.getValueArrayOrObject(queueProperties.logging)\n\tlogging.delete in isTrue\n\tlogging.read in isTrue\n\tlogging.write in isTrue\n}\n\n# This will match 'azurerm_storage_account' that is not associated to a\n# 'azurerm_monitor_diagnostic_setting' resource\nWizPolicy[result] {\n\tdocument := input.document[i]\n\tresource := document.resource.azurerm_storage_account[name]\n    \n\tnot ClassicLoggingEnabledForAllTypes(resource)\n\tnot associatedToDs(document, resource, name)\n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"searchKey\": sprintf(\"azurerm_storage_account[%s]\", [name]),\n\t\t\"keyExpectedValue\": sprintf(\"'azurerm_storage_account[%s]' is not associated to a 'azurerm_monitor_diagnostic_setting' resource for '%sServices' logging\", [name, serviceType]),\n\t\t\"keyActualValue\": sprintf(\"'azurerm_storage_account[%s]' should be associated to a 'azurerm_monitor_diagnostic_setting' resource for '%sServices' logging\", [name, serviceType]),\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n\n# This will match 'azurerm_storage_account' that is associated to a\n# 'azurerm_monitor_diagnostic_setting' resource that does not have all logging types enabled\nWizPolicy[result] {\n\tdocument := input.document[i]\n\tresource := document.resource.azurerm_storage_account[name]\n\tdiagnosticSetting := document.resource.azurerm_monitor_diagnostic_setting[dsName]\n\t\n\tnot ClassicLoggingEnabledForAllTypes(resource)\n\tterraLib.associatedResources(resource, diagnosticSetting, name, dsName, null, \"target_resource_id\")\n\tcontains(lower(diagnosticSetting.target_resource_id), serviceType)\n\tnot allLoggingTypesEnabled(diagnosticSetting)\n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"searchKey\": sprintf(\"azurerm_monitor_diagnostic_setting[%s].enabled_log\", [dsName]),\n\t\t\"keyExpectedValue\": sprintf(\"'azurerm_monitor_diagnostic_setting[%s]' should enable %s logging for 'StorageRead', 'StorageWrite', and 'StorageDelete'\", [dsName, serviceType]),\n\t\t\"keyActualValue\": sprintf(\"'azurerm_monitor_diagnostic_setting[%s]' does not enable %s logging for Read, Write and/or Delete\", [dsName, serviceType]),\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n"
    remediation_instructions = null
    type                     = "TERRAFORM"
  }
}

# __generated__ by Terraform from "2ce49437-0647-4c45-8f46-a76d0aa149eb"
resource "wiz_cloud_configuration_rule" "ccn_884a_opmon3r1" {
  description              = "This rule checks whether Azure Network Watcher is disabled.  \nThis rule fails if `NetworkWatchers` is set to null.  \n>**Note**  \nThis rule is informational. It is used for the control `wc-id-1131`, and does not indicate a misconfiguration."
  enabled                  = true
  function_as_control      = false
  name                     = "Network Watcher is disabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nresult = \"fail\" {\n\tinput.NetworkWatchers == null\n}\n\ncurrentConfiguration := \"This region has network watcher disabled\"\nexpectedConfiguration := \"\"\n"
  remediation_instructions = null
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["Microsoft.Location"]
  tags {
    key   = "dbaker-api-test"
    value = "20240614"
  }
  tags {
    key   = "owner"
    value = "test123"
  }
  tags {
    key   = "test"
    value = "owner"
  }
  tags {
    key   = "test2"
    value = "owner2"
  }
}

# __generated__ by Terraform from "c1d810fa-3fc1-4ebb-8d0e-9d75110f0d21"
resource "wiz_cloud_configuration_rule" "ccn_884a_opmon2r9" {
  description              = "This rule checks whether Cosmos DB has control plane requests logging enabled.  \nThis rule fails if there are no diagnostic settings configured for the Cosmos DB account, or if control plane requests logging is not enabled.  \nEnabling logging for control plane requests in Cosmos DB is crucial for monitoring and auditing administrative operations. It helps in tracking changes and ensuring the security and compliance of your Cosmos DB environment.  \nIt is recommended to enable control plane requests logging to maintain a secure and compliant database environment."
  enabled                  = true
  function_as_control      = false
  name                     = "Cosmos DB control plane requests logging should be enabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nhasDiagnosticSettings {\n\tcount(input.DiagnosticSettingsResources) > 0\n}\n\nhasControlPlaneRequests(DiagnosticSettingsResources) {\n\tDiagnosticSettingsResources[i].properties.logs[j].category == \"ControlPlaneRequests\"\n}\n\nresult = \"fail\" { # checks if there are no diagnostic settings at all\n\tnot hasDiagnosticSettings\n}{ # checks if there are diagnostic settings, but without a 'ControlPlaneRequests' category\n    \tDiagnosticSettingsResources := input.DiagnosticSettingsResources\n    \tnot hasControlPlaneRequests(DiagnosticSettingsResources)\n}{ # checks if there are diagnostic settings with a 'ControlPlaneRequests' category, but not enabled\n\tinput.DiagnosticSettingsResources[i].properties.logs[j].category == \"ControlPlaneRequests\"\n\tnot input.DiagnosticSettingsResources[i].properties.logs[j].enabled == true\n}\n\ncurrentConfiguration := \"Cosmos DB does not have control plane requests logging enabled\"\nexpectedConfiguration := \"Cosmos DB should have control plane requests logging enabled\"\n"
  remediation_instructions = "Perform the following commands to enable control plane requests logging for Cosmos DB via Azure CLI. You must choose a destination for your logs:\n\n1. Create a diagnostic setting for Cosmos DB to send logs to a Log Analytics workspace:\n```\naz monitor diagnostic-settings create \\\n  --name <diagnosticSettingName> \\\n  --resource {{cosmosDbAccountId}} \\\n  --workspace <logAnalyticsWorkspaceId> \\\n  --logs '[{\"category\": \"ControlPlaneRequests\", \"enabled\": true}]'\n```\n\n2. If you want to send logs to an Event Hub, use the following command instead:\n```\naz monitor diagnostic-settings create \\\n  --name <diagnosticSettingName> \\\n  --resource {{cosmosDbAccountId}} \\\n  --event-hub <eventHubName> \\\n  --event-hub-rule <eventHubAuthorizationRuleId> \\\n  --logs '[{\"category\": \"ControlPlaneRequests\", \"enabled\": true}]'\n```\n\n3. To send logs to a storage account, use this command:\n```\naz monitor diagnostic-settings create \\\n  --name <diagnosticSettingName> \\\n  --resource {{cosmosDbAccountId}} \\\n  --storage-account <storageAccountId> \\\n  --logs '[{\"category\": \"ControlPlaneRequests\", \"enabled\": true}]'\n```\n\n>**Note**\n>The diagnostic setting name is user-defined and should be unique within the Azure subscription. The Log Analytics workspace ID, Event Hub name, Event Hub authorization rule ID, and storage account ID are specific to your Azure environment and should be retrieved from the Azure portal or via corresponding Azure CLI commands."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["Microsoft.DocumentDB/databaseAccounts"]
}

# __generated__ by Terraform from "86c7c850-05c4-4f83-9de8-4c1199a0ba04"
resource "wiz_cloud_configuration_rule" "ccn_884a_acc2r2" {
  description              = "This rule checks whether the Conditional Access Policy blocks access by location.  \nThis rule fails if the policy has all of the following:  \n* `applications.includeApplications` contains `All`  \n* `users.includeUsers` contains `All`  \n* `locations.includeLocations` is not empty  \n* `grantControls.builtInControls` contains `block`  \n* `state` is `enabled`  \n\n>**Note**  \nThis rule does not indicate a misconfiguration and is used as part of Control `wc-id-1238`."
  enabled                  = true
  function_as_control      = false
  name                     = "Conditional Access Policy blocks access by location"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nconditions := input.conditions\n\nblocksAccessByLocation {\n\tlower(conditions.applications.includeApplications[_]) == \"all\"\n\tlower(conditions.users.includeUsers[_]) == \"all\"\n\tlower(input.grantControls.builtInControls[_]) == \"block\"\n\tcount(conditions.locations.includeLocations[_]) > 0\n\tlower(input.state) == \"enabled\"\n}\n\n# This rule fails if the Conditional Access Policy blocks access by location.\nresult = \"fail\" {\n\tblocksAccessByLocation\n}\n\ncurrentConfiguration := sprintf(\"'%v' policy blocks access by location\", [input.displayName])"
  remediation_instructions = ">**Note**  \nThis rule does not indicate a misconfiguration and is used as part of a Control."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "INFORMATIONAL"
  target_native_types      = ["ConditionalAccessPolicy"]
}

# __generated__ by Terraform from "57c9d6a2-aa2d-4372-8396-9997cc31371b"
resource "wiz_cloud_configuration_rule" "ccn_884a_opmon2r10" {
  description              = "This rule checks if Audit Event logging for Key Vault instances is enabled.  \nThis rule fails when a Key Vault's `DiagnosticSettingsResources` does not contain a diagnostic setting that sends logs to a Storage Account where `properties.logs.category = AuditEvent` and `properties.logs.enabled = true` and `properties.logs.retentionPolicy.days` is at least **180** days.  \nMonitoring how and when your Azure Key Vaults are accessed, and by whom, enables an audit trail of interactions with private information, encryption keys, and certificates managed by the Azure Key Vault service. \nIt is recommended to enable AuditEvent logging for key vault instances for at least 180 days (the maximum amount of retention days is 365) to ensure interactions with key vaults are logged and available.  \n>**Note**  \nAudit Event retention is only relevant when archiving logs to a **Storage Account**."
  enabled                  = true
  function_as_control      = false
  name                     = "Key Vault audit event logging should be enabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nretentionMoreThan180(retentionPolicy) {\n\tretentionPolicy.enabled\n    \tretentionPolicy.days >= 180\n}{\n\tretentionPolicy.enabled\n    \tretentionPolicy.days == 0\n}{\n\tnot retentionPolicy.enabled\n}\n\nauditLog(dsResource) = auditLogObject {\n\tlower(dsResource.properties.logs[log].category) == \"auditevent\"\n    \tauditLogObject := dsResource.properties.logs[log]\n}\n\nauditLogsEnabled(dsResource) {\n\tdsResource.properties.storageAccountId\n    \tauditLogObject := auditLog(dsResource)\n\tauditLogObject.enabled\n    \tretentionMoreThan180(auditLogObject.retentionPolicy)\n}\n\nresult = \"fail\" {\n\tdsResource := input.DiagnosticSettingsResources[resource]\n\tnot auditLogsEnabled(dsResource)\n}\n\ncurrentConfiguration := \"AuditEvent not logging to a storage account, or retention is less than 180 days\"\nexpectedConfiguration := \"Key Vault should keep AuditEvent logs for at least 180 days and send them to a storage account\"\n"
  remediation_instructions = "Perform the following command to enable Key Vault Audit Event logging via Azure CLI:  \n```  \naz monitor diagnostic-settings create \\\n\t--storage-account <StorageAccountID> \\\n\t--resource {{keyVaultId}} \\\n\t--name <DiagnosticSettingsName> \\\n\t--logs '[{\"category\": \"AuditEvent\",\"enabled\": true}]'  \n\t[--metrics '[{\"category\": \"AllMetrics\",\"enabled\": true}]'] #Include if you want to log platform metrics as well.  \n```  \nOnce you enable logging, a new container called `insights-logs-auditevent` is automatically created for your specified storage account. You can use this same storage account for collecting logs for multiple key vaults."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["Microsoft.KeyVault/vaults"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.terraform as terraLib\n\nassociatedToDs(document, resource, name) {\n\tdsResource := document.resource.azurerm_monitor_diagnostic_setting[dsName]\n\tterraLib.associatedResources(resource, dsResource, name, dsName, null, \"target_resource_id\")\n}\n\nWizPolicy[result] {\n\tdocument := input.document[i]\n\tresource := document.resource.azurerm_key_vault[name]\n    \n\tnot associatedToDs(document, resource, name)\n\n\tresult := {\n\t\t\"documentId\": document.id,\n\t\t\"resourceName\": terraLib.get_resource_name(resource, name),\n\t\t\"searchKey\": sprintf(\"azurerm_key_vault[%s]\", [name]),\n\t\t\"issueType\": \"MissingAttribute\",\n\t\t\"keyExpectedValue\": sprintf(\"'azurerm_key_vault[%s]' should be associated with 'azurerm_monitor_diagnostic_setting'\", [name]),\n\t\t\"keyActualValue\": sprintf(\"'azurerm_key_vault[%s]' is not associated with 'azurerm_monitor_diagnostic_setting'\", [name]),\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n\n"
    remediation_instructions = null
    type                     = "TERRAFORM"
  }
}

# __generated__ by Terraform from "e2db3116-0b07-4b19-ade8-8edfc516451c"
resource "wiz_cloud_configuration_rule" "ccn_884a_opmon1r2" {
  description              = "This rule checks whether the Conditional Access Policy requires MFA for all users.  \nThis rule fails if the policy has all of the following:\n* `applications.includeApplications` contains `All`\n* `users.includeUsers` contains `All`\n* `userRiskLevels` contains `high`\n* `builtInControls` contains `passwordChange`\n* `state` is `enabled`\n\n>**Note**  \nThis rule does not indicate a misconfiguration and is used as part of Control `wc-id-1236`."
  enabled                  = true
  function_as_control      = false
  name                     = "Conditional Access Policy requires a password change for risky users"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nconditions := input.conditions\n\nrequirePasswordChangeForRiskyUsers {\n\tlower(conditions.applications.includeApplications[_]) == \"all\"\n\tlower(conditions.users.includeUsers[_]) == \"all\"\n\tlower(conditions.userRiskLevels[_]) == \"high\"\n\tlower(input.grantControls.builtInControls[_]) == \"passwordchange\"\n\tlower(input.state) == \"enabled\"\n}\n\n# This rule fails if the Conditional Access Policy requires password change for risky users.\nresult = \"fail\" {\n\trequirePasswordChangeForRiskyUsers\n}\n\ncurrentConfiguration := sprintf(\"'%v' policy requires password change for risky users\", [input.displayName])"
  remediation_instructions = ">**Note**  \nThis rule does not indicate a misconfiguration and is used as part of a Control."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "INFORMATIONAL"
  target_native_types      = ["ConditionalAccessPolicy"]
}

# __generated__ by Terraform from "e8e11135-8bec-46fd-b456-877770775772"
resource "wiz_cloud_configuration_rule" "ccn_884a_mpinfo2r1" {
  description              = "Azure VM should be tagged with owner details for governance purposes"
  enabled                  = true
  function_as_control      = true
  name                     = "Azure VM should have an owner tag"
  opa_policy               = "package wiz\n\ndefault result = \"fail\"\n\nresult = \"pass\"{\n    input.tags.Owner != null\n    }\n\n"
  remediation_instructions = null
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["Microsoft.Compute/virtualMachines"]
}

# __generated__ by Terraform from "d972282d-f09b-46e7-b8d8-1d8d48daca5a"
resource "wiz_cloud_configuration_rule" "ccn_884a_mpcom1r1" {
  description              = "This rule checks whether the Network Security Group allows RDP access (TCP - port 3389).  \nThis rule fails if the Network Security Group allows inbound access from 0.0.0.0/0 over TCP port 3389.  \nAllowing unrestricted inbound access can increase the risk of malicious activities such as brute-force and denial of service attacks.  \nYou should ensure access is restricted and only allowed from specific sources, especially over protocols with high risk such as RDP."
  enabled                  = true
  function_as_control      = false
  name                     = "Network Security Group should restrict RDP access (TCP - port 3389)"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\napplicationEndpoint := {\"0.0.0.0/0\", \"any\", \"*\", \"::/0\", \"internet\"}\n\nanyPort := \"*\"\n\nrestrictProtocols := {\n\t\"rdpTcp\": {\n\t\t\"protocols\": {\"tcp\", \"-1\", \"6\", \"*\"},\n\t    \t\"ports\": {3389}\n\t}\n}\n\nportRange(portRange, port) {\n\tportRange == anyPort\n}{\n\tport == to_number(portRange)\n}{\n\tPortRangeToFrom := split(portRange, \"-\")\n\tto_number(PortRangeToFrom[0]) <= port\n\tto_number(PortRangeToFrom[1]) >= port\n}\n\nallPorts(permission, restrictPort) {\n\tportRange(permission.destinationPortRange, restrictPort)\n}{\n\tportRange(permission.destinationPortRanges[range], restrictPort)\n}\n\nallIps(permission) {\n\tapplicationEndpoint[lower(permission.sourceAddressPrefix)]\n}{\n\tapplicationEndpoint[lower(permission.sourceAddressPrefixes[prefix])]\n}\n\nlistRulesPriority(protocols, port, effect) = priorities { \n\tpriorities := [\n\t\tpriority | permission := input.properties.securityRules[Permissions].properties\n\t\tallIps(permission)\n\t\tlower(permission.direction) == \"inbound\"\n\t\tpermission.access == effect\n\t\tprotocols[protocol] == lower(permission.protocol)\n\t\tallPorts(permission, port)\n\t\tpriority := permission.priority\n\t]\n}\n\nresult = \"fail\" {\n\tmin(listRulesPriority(restrictProtocols[i].protocols, restrictProtocols[i].ports[_], \"Allow\")) < min(listRulesPriority(restrictProtocols[i].protocols, restrictProtocols[i].ports[_], \"Deny\"))\n}{\n\tcount(listRulesPriority(restrictProtocols[i].protocols, restrictProtocols[i].ports[_], \"Allow\")) > 0\n\tcount(listRulesPriority(restrictProtocols[i].protocols, restrictProtocols[i].ports[_], \"Deny\")) == 0\n}\n\ncurrentConfiguration := sprintf(\"Security Group allows unrestricted access\", [])\nexpectedConfiguration := sprintf(\"Security Group should not allow unrestricted access\", [])\n"
  remediation_instructions = "Perform the following command to restrict the Network Security Group RDP access from the internet via Azure CLI:  \n```  \naz network nsg rule update --name <ruleName> --nsg-name {{nsgName}} --resource-group {{resourceGroupName}} --source-address-prefixes <source>  \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "HIGH"
  target_native_types      = ["Microsoft.Network/networkSecurityGroups"]
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.azureresourcemanager as arm_lib\nimport data.generic.common as common_lib\n\nWizPolicy[result] {\n\tdoc := input.document[i]\n\t[path, value] = walk(doc)\n\n\tvalue.type == \"Microsoft.Network/networkSecurityGroups\"\n\n\tproperties := value.properties.securityRules[x].properties\n\n\tproperties.access == \"Allow\"\n\tproperties.protocol == \"Tcp\"\n\tproperties.direction == \"Inbound\"\n\tarm_lib.contains_port(properties, 3389)\n\tarm_lib.source_address_prefix_is_open(properties)\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": value.name,\n\t\t\"searchKey\": sprintf(\"%s.name={{%s}}.properties.securityRules\", [common_lib.concat_path(path), value.name]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"resource with type '%s' should restrict access to RDP\", [value.type]),\n\t\t\"keyActualValue\": sprintf(\"resource with type '%s' does not restrict access to RDP\", [value.type]),\n\t\t\"searchLine\": common_lib.build_search_line(path, [\"properties\", \"securityRules\", x, \"properties\"]),\n\t\t\"resourceTags\": object.get(value, \"tags\", {}),\n\t}\n}\n\nWizPolicy[result] {\n\tdoc := input.document[i]\n\t[path, value] = walk(doc)\n\n\ttypeInfo := arm_lib.get_sg_info(value)\n\n\tproperties := typeInfo.properties\n\n\tproperties.access == \"Allow\"\n\tproperties.protocol == \"Tcp\"\n\tproperties.direction == \"Inbound\"\n\tarm_lib.contains_port(properties, 3389)\n\tarm_lib.source_address_prefix_is_open(properties)\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": value.name,\n\t\t\"searchKey\": sprintf(\"%s\", [typeInfo.path]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"resource with type '%s' should restrict access to RDP\", [typeInfo.type]),\n\t\t\"keyActualValue\": sprintf(\"resource with type '%s' does not restrict access to RDP\", [typeInfo.type]),\n\t\t\"searchLine\": common_lib.build_search_line(path, typeInfo.sl),\n\t\t\"resourceTags\": object.get(value, \"tags\", {}),\n\t}\n}\n"
    remediation_instructions = null
    type                     = "AZURE_RESOURCE_MANAGER"
  }
  iac_matchers {
    rego_code                = "package wiz\n\nimport data.generic.terraform as terraLib\n\nWizPolicy[result] {\n\tresource := input.document[j].resource.azurerm_network_security_group[name]\n\tsecurityRule := input.document[i].resource.azurerm_network_security_rule[ruleName]\n\tterraLib.associatedResources(resource, securityRule, name, ruleName, \"name\", \"network_security_group_name\")\n\t\n\tupper(securityRule.access) == \"ALLOW\"\n\tupper(securityRule.direction) == \"INBOUND\"\n\tisRelevantProtocol(securityRule.protocol)\n\tisRelevantPort(securityRule.destination_port_range)\n\tisRelevantAddressPrefix(securityRule.source_address_prefix)\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": terraLib.get_resource_name(resource, name),\n\t\t\"resourceType\": \"azurerm_network_security_group\",\n\t\t\"searchKey\": sprintf(\"azurerm_network_security_rule[%s].destination_port_range\", [ruleName]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"'azurerm_network_security_rule.%s.destination_port_range' cannot be 3389\", [ruleName]),\n\t\t\"keyActualValue\": sprintf(\"'azurerm_network_security_rule.%s.destination_port_range' might be 3389\", [ruleName]),\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n\nWizPolicy[result] {\n\tresource := terraLib.getArray(input.document[i].resource.azurerm_network_security_group[securityGroupName].security_rule)[rule]\n\tsecurityRuleName := resource.name\n\tupper(resource.access) == \"ALLOW\"\n\tupper(resource.direction) == \"INBOUND\"\n\tisRelevantProtocol(resource.protocol)\n\tisRelevantPort(resource.destination_port_range)\n\tisRelevantAddressPrefix(resource.source_address_prefix)\n\n\tresult := {\n\t\t\"documentId\": input.document[i].id,\n\t\t\"resourceName\": terraLib.get_resource_name(resource, securityGroupName),\n\t\t\"searchKey\": sprintf(\"azurerm_network_security_group[%s].security_rule[%s].destination_port_range\", [securityGroupName, securityRuleName]),\n\t\t\"issueType\": \"IncorrectValue\",\n\t\t\"keyExpectedValue\": sprintf(\"'azurerm_network_security_group[%s].security_rule[%s].destination_port_range' should not be 3389\", [securityGroupName, securityRuleName]),\n\t\t\"keyActualValue\": sprintf(\"'azurerm_network_security_group[%s].security_rule[%s].destination_port_range' might be 3389\", [securityGroupName, securityRuleName]),\n\t\t\"resourceTags\": object.get(resource, \"tags\", {}),\n\t}\n}\n\nisRelevantProtocol(protocol) = allow {\n\tupper(protocol) != \"UDP\"\n\tupper(protocol) != \"ICMP\"\n\tallow = true\n}\n\nisRelevantPort(port) = allow {\n\tregex.match(\"(^|\\\\s|,)3389(-|,|$|\\\\s)\", port)\n\tallow = true\n}\n\nelse = allow {\n\tports = split(port, \",\")\n\tsublist = split(ports[var], \"-\")\n\tto_number(trim(sublist[0], \" \")) <= 3389\n\tto_number(trim(sublist[1], \" \")) >= 3389\n\tallow = true\n}\n\nisRelevantAddressPrefix(prefix) = allow {\n\tprefix == \"*\"\n\tallow = true\n}\n\nelse = allow {\n\tprefix == \"0.0.0.0\"\n\tallow = true\n}\n\nelse = allow {\n\tendswith(prefix, \"/0\")\n\tallow = true\n}\n\nelse = allow {\n\tprefix == \"internet\"\n\tallow = true\n}\n\nelse = allow {\n\tprefix == \"any\"\n\tallow = true\n}\n"
    remediation_instructions = null
    type                     = "TERRAFORM"
  }
}

# __generated__ by Terraform from "19df3283-cb81-446e-bea4-bd5987572efa"
resource "wiz_cloud_configuration_rule" "ccn_884a_opmon2r4" {
  description              = "This rule checks whether Key Vault resource logs are enabled.  \nThis rule fails if the Diagnostic Settings are configured as one of the following:  \n* At least one of the log categories is not enabled.\n* Category Groups `allLogs` or `audit` are disabled or do not have a compliant retention policy.\n* Retention policy days is not configured to `365` or `0`.\n\nKey Vault resource logs can be used to identify and diagnose issues, track changes, and improve security and compliance. In addition, resource logs can be integrated with various log management and monitoring tools to provide centralized log management and analysis, making it easier to identify patterns, troubleshoot issues, and make data-driven decisions for investigation purposes when a security incident occurs or when your network is compromised.  \nIt is recommended to enable all logging types on the Key Vault."
  enabled                  = true
  function_as_control      = false
  name                     = "Key Vault resource logs should be enabled"
  opa_policy               = "package wiz\n\nimport future.keywords.in\n\ndefault result = \"pass\"\n\nallLogs := {\"audit\", \"allLogs\"}\napprovedRetentionPolicyDays := {0, 365}\n\nnonCompliantLogCategoryConfiguration(log) {\n\tlog.category\n\tnot log.enabled\n}{\n\tlog.category\n\tlog.enabled\n\tlog.retentionPolicy.enabled\n\tnot log.retentionPolicy.days in approvedRetentionPolicyDays\n}\n\nnotAllLogsCategoryGroup(log) {\n\tlog.categoryGroup in allLogs\n\tnot log.enabled\n}{\n\tlog.categoryGroup in allLogs\n\tlog.enabled\n\tlog.retentionPolicy.enabled\n\tnot log.retentionPolicy.days in approvedRetentionPolicyDays\n}\n\nnonCompliantDiagnosticSettingsConfiguration[diagnosticSettings] {\n\tdiagnosticSettings := input.DiagnosticSettingsResources[settings]\n\tlog := diagnosticSettings.properties.logs[l]\n\tnonCompliantLogCategoryConfiguration(log)\n}{\n\tdiagnosticSettings := input.DiagnosticSettingsResources[settings]\n\tlog := diagnosticSettings.properties.logs[l]\n\tnotAllLogsCategoryGroup(log)\n}\n\nresult = \"fail\" {\n\tcount(nonCompliantDiagnosticSettingsConfiguration) == count(input.DiagnosticSettingsResources)\n}\n\ncurrentConfiguration := \"Key Vault resource logs are disabled\"\nexpectedConfiguration := \"Key Vault resource logs should be enabled\"\n"
  remediation_instructions = "Perform the following command to enable all resource logs for Key Vault via Azure CLI:\n\nIf you do not have Diagnostic Settings configured for your Key Vault, create one and enabled resource logs with the following command.\nIf you already have Diagnostic Settings configured for your Key Vault, skip to the next command.\n```\naz monitor diagnostic-settings create \\\n--name <set name for the diagnostic settings> \\\n--resource {{resourceId}} \\\n--logs \"[{categoryGroup:allLogs,enabled:true,retention-policy:{enabled:false,days:0}}]\" \\\n--storage-account <Your Storage Account ID or name> || --workspace <Your Workspace ID or name> || --event-hub <Your Event Hub ID or name> --event-hub-rule <Your Event Hub Rule ID>\n```\n\nIf you already have Diagnostic Settings configured for your Key Vault, use the following command to enable all resource logs.\n```\naz monitor diagnostic-settings update \\\n--name <your diagnostic settings name> \\\n--resource {{resourceId}} \\\n--logs \"[{categoryGroup:allLogs,enabled:true,retention-policy:{enabled:false,days:0}}]\" \n```"
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["Microsoft.KeyVault/vaults"]
}

# __generated__ by Terraform from "f40a4158-82e3-4cd9-9a10-546ade66b2ab"
resource "wiz_cloud_configuration_rule" "ccn_884a_acc6r2" {
  description              = "This rule checks whether the Conditional Access Policy requires MFA for Azure management.  \nThis rule fails if the policy has all of the following:\n* `applications.includeApplications` contains `All` or `797f4846-ba00-4fd7-ba43-dac1f8f63013` - Azure management ID\n* `users.includeUsers` contains `All`\n* `builtInControls` contains `mfa` or `authenticationStrength.requirementsSatisfied` contains `mfa`\n* `state` is `enabled`\n\n>**Note**  \nThis rule does not indicate a misconfiguration and is used as part of Control `wc-id-1234`."
  enabled                  = true
  function_as_control      = false
  name                     = "Conditional Access Policy requires MFA for Azure management"
  opa_policy               = "package wiz\n\nimport future.keywords.in\n\ndefault result = \"pass\"\n\nconditions := input.conditions\nallIncludingAzureMgmt := {\"all\", \"797f4846-ba00-4fd7-ba43-dac1f8f63013\"}\n\nrequireMfaForAzureMgmt {\n\tlower(conditions.applications.includeApplications[_]) in allIncludingAzureMgmt\n\tlower(conditions.users.includeUsers[_]) == \"all\"\n\tlower(input.grantControls.builtInControls[_]) == \"mfa\"\n\tlower(input.state) == \"enabled\"\n}{\n\tlower(conditions.applications.includeApplications[_]) in allIncludingAzureMgmt\n\tlower(conditions.users.includeUsers[_]) == \"all\"\n\tlower(input.grantControls.authenticationStrength.requirementsSatisfied) == \"mfa\"\n\tlower(input.state) == \"enabled\"\n}\n\n# This rule fails if the Conditional Access Policy requires MFA for Azure management.\nresult = \"fail\" {\n\trequireMfaForAzureMgmt\n}\n\ncurrentConfiguration := sprintf(\"'%v' policy requires MFA for Azure management\", [input.displayName])"
  remediation_instructions = ">**Note**  \nThis rule does not indicate a misconfiguration and is used as part of a Control."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "INFORMATIONAL"
  target_native_types      = ["ConditionalAccessPolicy"]
}

# __generated__ by Terraform from "ae99d1be-3ddd-4545-a7ed-f8542601aeab"
resource "wiz_cloud_configuration_rule" "ccn_884a_opexp8r1" {
  description              = "Entra ID Logs contain the history of sign-in activity, as well as an audit trail of the changes made in Azure AD for a particular tenant. They can provide crucial, tenant-wide insights, and are important in order to understand who did what, and when. \n\n>**Note**  \n>This rule should always pass on every Subscription since the logs are enabled by default and can't be disabled."
  enabled                  = true
  function_as_control      = false
  name                     = "Microsoft Entra ID (AAD) logs are disabled"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\nresult = \"fail\" {\n\tnot input.tenantId\n}\n\n#  Microsoft Entra ID (AAD) logs are enabled by default and can't be disabled"
  remediation_instructions = null
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "INFORMATIONAL"
  target_native_types      = ["Microsoft.AzureActiveDirectory/tenants"]
}

# __generated__ by Terraform from "fc191873-5e2b-413a-9c5e-389b0007a7b1"
resource "wiz_cloud_configuration_rule" "ccn_884a_mpinfo9r2" {
  description              = "This rule checks whether the Backup Vault immutability settings are enabled.  \nThis rule fails if the field `immutabilitySettings.state` is not set to `Locked` or `Unlocked`.  \nImmutability ensures that once data is stored in the backup vault, it cannot be altered or deleted, even by those with privileged access.  \nThe immutability settings state can be set to `Unlocked`, meaning the vault has immutability enabled and doesn't allow operations that could result in loss of backups. However, the setting can be disabled.  \nIf the immutability settings state is set to `Locked`, it means that the vault has immutability enabled and it cannot be disabled."
  enabled                  = true
  function_as_control      = false
  name                     = "Backup Vault immutability settings should be enabled"
  opa_policy               = "package wiz\n\nimport future.keywords.in\n\ndefault result = \"pass\"\n\nresult = \"fail\" {\n \tnot lower(input.Properties.SecuritySettings.ImmutabilitySettings.State) in [\"locked\", \"unlocked\"]\n}\n\ncurrentConfiguration := \"Backup Vault immutability settings is disabled\"\nexpectedConfiguration := \"Backup Vault immutability settings should be set to 'Locked' or 'Unlocked'\""
  remediation_instructions = "Perform the following command to enable the immutability settings of the Backup Vault via Azure CLI:  \n```\naz dataprotection backup-vault update --ids {{id}} --immutability-state Unlocked\n```\n>**Note**  \n>The `Unlocked` immutability state can be disabled. If you want, you can change the immutability state to `Locked`, which cannot be disabled.  \n>Note that immutability locking is irreversible, so ensure that you take a well-informed decision when opting to lock."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "MEDIUM"
  target_native_types      = ["Microsoft.DataProtection/backupVaults"]
}

# __generated__ by Terraform from "47a72232-eac2-4031-8a5e-d37c87ab8523"
resource "wiz_cloud_configuration_rule" "ccn_884a_opmon2r1" {
  description              = "This rule checks whether the Azure Activity Logs are integrated with Azure Monitor.  \nThis rule fails when none of the Diagnostic Settings have `workspaceId` configured.  \nWhen deploying diagnostic settings with Log Analytics, Azure can stream subscription audit logs to a Log Analytics workspace to monitor subscription-level events.  \nIt is recommended to enable Azure Monitor integration to proactively monitor problems and issues with your Azure Activity Logs."
  enabled                  = true
  function_as_control      = false
  name                     = "Activity logs should be integrated with Azure Monitor"
  opa_policy               = "package wiz\n\ndefault result = \"pass\"\n\ncheckIfWritesToLogAnalytics[diagnosticSettingID] {\n\tdiagnosticSettingID := input.DiagnosticSettings[_].properties.workspaceId\n}\n\nresult = \"fail\" {\n\tcount(checkIfWritesToLogAnalytics) == 0\n}\n\ncurrentConfiguration := \"There is no log that is writing to Analytics workspace\"\nexpectedConfiguration := \"Create a diagnostic setting subscription that will write logs to Analytics workspace\""
  remediation_instructions = "Perform the following command to create a diagnostic setting configuration that streams subscriptions audit logs to a Log Analytics workspace via Azure CLI:  \n```  \naz monitor diagnostic-settings subscription create \\\n\t--location <location> \\\n\t--logs '[  \n\t\t{  \n\t\t \"category\": \"Security\",  \n\t\t \"enabled\": true  \n\t\t},  \n\t\t{  \n\t\t \"category\": \"Administrative\",  \n\t\t \"enabled\": true  \n\t\t},  \n\t\t{  \n\t\t \"category\": \"ServiceHealth\",  \n\t\t \"enabled\": true  \n\t\t},  \n\t\t{  \n\t\t \"category\": \"Alert\",  \n\t\t \"enabled\": true  \n\t\t},  \n\t\t{  \n\t\t \"category\": \"Recommendation\",  \n\t\t \"enabled\": true  \n\t\t},  \n\t\t{  \n\t\t \"category\": \"Policy\",  \n\t\t \"enabled\": true  \n\t\t},  \n\t\t{  \n\t\t \"category\": \"Autoscale\",  \n\t\t \"enabled\": true  \n\t\t},  \n\t\t{  \n\t\t \"category\": \"ResourceHealth\",  \n\t\t \"enabled\": true  \n\t\t}  \n\t\t]' \\\n\t--name <name> \\\n\t--workspace <workspace>  \n```  \n>**Note**  \nIn order to use this command, you need to have a workspace. You can find more information about how to create one in [here](https://docs.microsoft.com/en-us/azure/machine-learning/how-to-manage-workspace-cli?tabs=createnewresources#create-a-workspace)."
  scope_account_ids        = []
  scope_project_id         = null
  security_sub_categories  = []
  severity                 = "LOW"
  target_native_types      = ["Microsoft.Subscription"]
}
