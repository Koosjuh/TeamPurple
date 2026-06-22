Per Product + Other
```kql
Resources
| extend ResourceType = tolower(type)
| extend ResourceCategory = case(
    ResourceType == "microsoft.hybridcompute/machines", "Azure Arc Servers",
    ResourceType == "microsoft.compute/virtualmachines", "Azure Virtual Machines",
    ResourceType == "microsoft.storage/storageaccounts", "Storage Accounts",
    ResourceType == "microsoft.keyvault/vaults", "Key Vaults",
    ResourceType == "microsoft.operationalinsights/workspaces", "Log Analytics Workspaces",
    ResourceType == "microsoft.insights/datacollectionrules", "Data Collection Rules",
    ResourceType == "microsoft.insights/actiongroups", "Action Groups",
    ResourceType == "microsoft.network/virtualnetworks", "Virtual Networks",
    ResourceType == "microsoft.network/networksecuritygroups", "Network Security Groups",
    ResourceType == "microsoft.web/sites", "App Services",
    ResourceType == "microsoft.web/serverfarms", "App Service Plans",
    ResourceType == "microsoft.web/certificates", "App Service Certificates",
    ResourceType == "microsoft.sql/servers", "SQL Servers",
    ResourceType == "microsoft.sql/servers/databases", "SQL Databases",
    ResourceType == "microsoft.dbformysql/flexibleservers", "MySQL Flexible Servers",
    ResourceType == "microsoft.dbforpostgresql/flexibleservers", "PostgreSQL Flexible Servers",
    ResourceType == "microsoft.documentdb/databaseaccounts", "Cosmos DB Accounts",
    ResourceType == "microsoft.cache/redis", "Azure Cache for Redis",
    ResourceType == "microsoft.containerservice/managedclusters", "AKS Clusters",
    ResourceType == "microsoft.kubernetes/connectedclusters", "Connected Kubernetes Clusters",
    ResourceType == "microsoft.containerregistry/registries", "Container Registries",
    ResourceType == "microsoft.apimanagement/service", "API Management Services",
    ResourceType == "microsoft.logic/workflows", "Logic Apps",
    ResourceType == "microsoft.web/connections", "API Connections",
    ResourceType == "microsoft.security/securityconnectors", "Security Connectors",
    ResourceType == "microsoft.security/assessments", "Security Assessments",
    "Other Resources"
)
| extend ProtectBucket = case(
    ResourceType in ("microsoft.storage/storageaccounts","microsoft.keyvault/vaults","microsoft.resources/subscriptions","microsoft.resources/resourcegroups","microsoft.authorization/policyassignments","microsoft.authorization/roleassignments","microsoft.network/networksecuritygroups","microsoft.network/virtualnetworks","microsoft.operationalinsights/workspaces","microsoft.insights/datacollectionrules","microsoft.insights/actiongroups"), "Azure Landing Zone Protect",
    ResourceType in ("microsoft.hybridcompute/machines","microsoft.compute/virtualmachines"), "Server Protect Azure",
    ResourceType in ("microsoft.web/sites","microsoft.web/serverfarms","microsoft.web/certificates", "microsoft.logic/workflows"), "Azure App Service Protect",
    ResourceType in ("microsoft.sql/servers","microsoft.sql/servers/databases","microsoft.dbformysql/flexibleservers","microsoft.dbforpostgresql/flexibleservers","microsoft.documentdb/databaseaccounts","microsoft.cache/redis"), "Azure Database Protect",
    ResourceType in ("microsoft.containerservice/managedclusters","microsoft.kubernetes/connectedclusters","microsoft.containerregistry/registries"), "Azure Kubernetes Protect",
    ResourceType in ("microsoft.security/automations","microsoft.security/assessments","microsoft.security/securityconnectors"), "EASM",
    ResourceType in ("microsoft.apimanagement/service", "microsoft.web/connections"), "Azure API Protect",
    "MISC"
)
| summarize Count = count()
    by subscriptionId, ProtectBucket, ResourceCategory
| extend SummaryItem = iff(ResourceCategory == "Other Resources", strcat(Count, " Other Resources"), strcat(Count, " ", ResourceCategory))
| summarize ResourceSummary = strcat_array(make_list(SummaryItem), ", ")
    by subscriptionId, ProtectBucket
| join kind=leftouter (
    ResourceContainers
    | where type =~ "microsoft.resources/subscriptions"
    | project subscriptionId, SubscriptionName = name
) on subscriptionId
| project SubscriptionName, subscriptionId, ProtectBucket, ResourceSummary
| order by SubscriptionName asc, ProtectBucket asc
```

OTHER

```kql
Resources
| extend ResourceType = tolower(type)
| where ResourceType !in (
    "microsoft.hybridcompute/machines",
    "microsoft.compute/virtualmachines",
    "microsoft.storage/storageaccounts",
    "microsoft.keyvault/vaults",
    "microsoft.operationalinsights/workspaces",
    "microsoft.insights/datacollectionrules",
    "microsoft.insights/actiongroups",
    "microsoft.network/virtualnetworks",
    "microsoft.network/networksecuritygroups",
    "microsoft.web/sites",
    "microsoft.web/serverfarms",
    "microsoft.web/certificates",
    "microsoft.sql/servers",
    "microsoft.sql/servers/databases",
    "microsoft.dbformysql/flexibleservers",
    "microsoft.dbforpostgresql/flexibleservers",
    "microsoft.documentdb/databaseaccounts",
    "microsoft.cache/redis",
    "microsoft.containerservice/managedclusters",
    "microsoft.kubernetes/connectedclusters",
    "microsoft.containerregistry/registries",
    "microsoft.apimanagement/service",
    "microsoft.logic/workflows",
    "microsoft.web/connections",
    "microsoft.security/securityconnectors",
    "microsoft.security/assessments"
)
| summarize Count=count() by subscriptionId, ResourceType
| order by subscriptionId asc, Count desc
```


### Resource Inventory by Defender for Cloud Workload

This query analyzes all Azure resources within the selected subscriptions and groups them into security workload categories that align with Microsoft Defender for Cloud plans, such as:

- Azure Landing Zone Protect
- Server Protect Azure
- Azure App Service Protect
- Azure Database Protect
- Azure Kubernetes Protect
- Azure API Protect
- External Attack Surface Management (EASM)
- Miscellaneous Resources

For each subscription, the query provides a summarized inventory of protected resource types and their counts. 

This allows to quickly understand the scope of resources that may fall under each Defender for Cloud protection domain and helps validate Defender plan coverage.

### Azure Resource Graph Explorer

This KQL is not used via Sentinel or Advanced hunting but via the Azure Resource Graph Explorer. 

Azure Resource Graph Explorer provides a live view of all Azure Resource Manager (ARM) resources within a tenant and can be used to inspect resource types, properties, and configurations.

##### Access methods:

1. Navigate to the Azure Portal. https://portal.azure.com
2. Access **Resource Manager**
3. Under **Tools** you will find **Azure Resource Graph Explorer** and here you can use the KQL

### Output
| Subscription Name | Defender for Cloud Workload | Resource Inventory |
|-------------------|-----------------------------|-------------------|
| Azure subscription 1 | Azure API Protect | 1 API Connection |
| Azure subscription 1 | Azure App Service Protect | 1 Logic App |
| Azure subscription 1 | Azure Landing Zone Protect | 1 Action Group, 2 Data Collection Rules, 1 Log Analytics Workspace |
| Azure subscription 1 | Miscellaneous Resources | 3 Other Resources |
