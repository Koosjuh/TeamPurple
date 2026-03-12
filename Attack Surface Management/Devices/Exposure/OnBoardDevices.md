```kql
DeviceTvmSecureConfigurationAssessment
| where Timestamp >= ago(7d)
| where ConfigurationId has "20000"
| where OSPlatform contains "Windows"
| summarize count() by ConfigurationId
```
