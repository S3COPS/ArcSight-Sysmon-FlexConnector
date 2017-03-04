# ArcSight-Sysmon-FlexConnector
HPE ArcSight Windows Native FlexConnector for Microsoft Sysmon tool

Sysmon WINC Parser
Built for Sysinternals Sysmon v6.00 - System activity monitor, Copyright (C) Mark Russinovich and Thomas Garnier
Device / Product version: Sysmon v6.0, should be backward compatible to Sysmon v3.
https://technet.microsoft.com/en-gb/sysinternals/sysmon

SmartConnector Type: Windows Native Connector
Dependencies: HPE ArcSight SmartConnector Framework at least 7.4 (For automatic IPv6 Parsing)

# Installation Summary
Copy the fcp and acp folders and the contents to the <Connector_Home>/current/user/agent/ folder on the Windows Native Connector
Add the following Event Log to the Windows Native Connector Custom Log section:Microsoft-Windows-Sysmon/Operational
or add directly to the agent.properties file:agents[0].windowshoststable[0].eventlogtypes=Microsoft-Windows-Sysmon/Operational 

Restart the Windows Native Connector

For more details on configuration of Sysmon refer to 

an excellent sample sysmon config file is hosted on 
