# ArcSight-Sysmon-FlexConnector
Microfocus ArcSight Windows Native FlexConnector for Microsoft Sysmon tool https://technet.microsoft.com/en-gb/sysinternals/sysmon

Sysmon WINC Parser
Updated for Sysinternals Sysmon v10.x - System activity monitor, Copyright (C) Mark Russinovich and Thomas Garnier

NOTE: when using DNS Query Logging functionality, you may want to ensure the ArcSight SmartConnector Java Image is whitelisted or does not carry out DNS lookups or you will see the original DNS Query as well as a followup query from the <ArcSight Connector>jre/bin/java.exe image on the SmartConnector Host.

Device / Product version: Sysmon v10.x, should be backward compatible to Sysmon v3.
https://technet.microsoft.com/en-gb/sysinternals/sysmon

SmartConnector Type: Windows Native Connector
Dependencies: Microfocus ArcSight SmartConnector Framework at least 7.4 (For automatic IPv6 Parsing)

# Installation Summary
Copy the fcp and acp folders and the contents to the CONNECTOR_HOME/current/user/agent/ folder on the Windows Native Connector

Add the following Event Log to the Windows Native Connector Custom Log section:Microsoft-Windows-Sysmon/Operational

or add directly to the agent.properties file:agents[0].windowshoststable[0].eventlogtypes=Microsoft-Windows-Sysmon/Operational 

Restart the Windows Native Connector

For more details on configuration of Sysmon refer to https://technet.microsoft.com/en-gb/sysinternals/sysmon

for an excellent sample sysmon config file refer to https://github.com/SwiftOnSecurity/sysmon-config

# Field Mappings Summary: Common Fields

| ArcSight Fields                    | Mapping                                                   |
|------------------------------------|-----------------------------------------------------------|
| deviceVendor                       | Microsoft                                                 |
| deviceProduct                      | Sysmon                                                    |
| endTime                            | UtcTime                                                   |
| deviceCustomDate1                  | UtcTime                                                   |
| deviceCustomDate1Label             | Event TimeStamp (UTC)                                     |
| deviceTimeZone                     | UC                                                        |
| transportProtocol                  | Protocol                                                  |
| fileName                           | TargetFilename                                            |
| fileCreateTime                     | CreationUtcTime                                           |
| oldFileCreateTime                  | PreviousCreationUtcTime                                   |
| fileId                             | FileVersion                                               |
| fileHash                           | SHA256                                                    |
| additionaldata.Hash_SHA1           | SHA1                                                      |
| additionaldata.Hash_MD5            | MD5                                                       |
| additionaldata.Hash_SHA256         | SHA256                                                    |
| deviceProcessId                    | ProcessId                                                 |
| deviceProcessName                  | Image                                                     |
| deviceAction                       | __oneOf(State,EventType)                                  |
| deviceFacility                     | RuleName                                                  |
| sourceUserName                     | User                                                      |
| sourceUserId                       | LogonId                                                   |
| sourceAddress                      | SourceIp                                                  |
| sourcePort                         | SourcePort                                                |
| sourceHostName                     | SourceHostname                                            |
| sourceProcessId                    | __oneOfInteger(ParentProcessId,SourceProcessId,ProcessId) |
| sourceProcessName                  | __oneOf(ParentImage,SourceImage,Image)                    |
| destinationAddress                 | DestinationIp                                             |
| destinationPort                    | DestinationPort                                           |
| destinationHostName                | DestinationHostname                                       |
| destinationProcessName             | __oneOf(ImageLoaded,TargetImage,Image)                    |
| destinationProcessId               | TargetProcessId                                           |
| destinationServiceName             | Product                                                   |
| deviceCustomNumber2                | TerminalSessionId                                         |
| deviceCustomNumber2Label           | Terminal Session ID                                       |
| deviceCustomNumber3                | SequenceNumber                                            |
| deviceCustomNumber3Label           | Sequence Number                                           |
| deviceCustomString4                | Initiated                                                 |
| deviceCustomString4Label           | Initiated                                                 |
| deviceCustomString5                | IntegrityLevel                                            |
| deviceCustomString5Label           | IntegrityLevel                                            |
| deviceCustomString6                | ProcessGuid                                               |
| deviceCustomString6Label           | Process Guid                                              |
| flexString1                        | SourceProcessGUID                                         |
| flexString1Label                   | Source Process Guid                                       |
| flexString2                        | TargetProcessGUID                                         |
| flexString2Label                   | Target Process GUID                                       |
| oldFilePermission                  | Description                                               |
| oldFileType                        | Company                                                   |
| additionaldata.SourcePortName      | SourcePortName                                            |
| additionaldata.DestinationPortName | DestinationPortName                                       |
| additionaldata.DestinationIsIpv6   | DestinationIsIpv6                                         |
| additionaldata.SourceIsIpv6        | SourceIsIpv6                                              |
| additionaldata.FileVersion         | FileVersion                                               |
| additionaldata.Description         | Description                                               |
| additionaldata.Product             | Product                                                   |
| additionaldata.Company             | Company                                                   |


# Event Specific Fields:

| EventID | ArcSight Fields          | Mapping                                                                                                                                                                                       |
|---------|--------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1       | message                  | __concatenate("Process Created: ",Image," Product: ",Product," Company: ",Company," Description: ",Description," FileVersion: ",FileVersion)                                                  |
| 1       | deviceEventClassId       | SysmonTask-SYSMON_CREATE_PROCESS                                                                                                                                                              |
| 1       | deviceCustomString1Label | Command Line                                                                                                                                                                                  |
| 1       | deviceCustomString1      | CommandLine                                                                                                                                                                                   |
| 1       | deviceCustomString2Label | Parent Command Line                                                                                                                                                                           |
| 1       | deviceCustomString2      | ParentCommandLine                                                                                                                                                                             |
| 1       | deviceCustomString3Label | Current Directory                                                                                                                                                                             |
| 1       | deviceCustomString3      | CurrentDirectory                                                                                                                                                                              |
| 1       | deviceCustomString4Label | Parent Process GUID                                                                                                                                                                           |
| 1       | deviceCustomString4      | ParentProcessGuid                                                                                                                                                                             |
| 1       | destinationServiceName   | Product                                                                                                                                                                                       |
| 1       | oldFileName              | OriginalFileName                                                                                                                                                                              |
|         |                          |                                                                                                                                                                                               |
| 2       | message                  | __concatenate("File creation time changed. Filename: ",TargetFilename)                                                                                                                        |
| 2       | deviceEventClassId       | SysmonTask-SYSMON_FILE_TIME                                                                                                                                                                   |
|         |                          |                                                                                                                                                                                               |
| 3       | message                  | __concatenate("A network connection was detected from ",SourceIp," to ",DestinationIp," destination port ",DestinationPort)                                                                   |
| 3       | deviceEventClassId       | SysmonTask-SYSMON_NETWORK_CONNECT                                                                                                                                                             |
|         |                          |                                                                                                                                                                                               |
| 4       | message                  | __concatenate("Sysmon Service state changed: ",State)                                                                                                                                         |
| 4       | deviceEventClassId       | SysmonTask-SYSMON_SERVICE_STATE_CHANGE                                                                                                                                                        |
| 4       | deviceCustomString1Label | Sysmon Version                                                                                                                                                                                |
| 4       | deviceCustomString1      | Version                                                                                                                                                                                       |
| 4       | deviceCustomString2Label | Schema Version                                                                                                                                                                                |
| 4       | deviceCustomString2      | SchemaVersion                                                                                                                                                                                 |
|         |                          |                                                                                                                                                                                               |
| 5       | message                  | __concatenate("Process Terminated: ",Image)                                                                                                                                                   |
| 5       | deviceEventClassId       | SysmonTask-SYSMON_PROCESS_TERMINATE                                                                                                                                                           |
|         |                          |                                                                                                                                                                                               |
| 6       | message                  | __concatenate("Driver Loaded: ",ImageLoaded," Signed: ",Signed," Valid: ",SignatureStatus)                                                                                                    |
| 6       | deviceEventClassId       | SysmonTask-SYSMON_DRIVER_LOAD                                                                                                                                                                 |
| 6       | deviceCustomString1Label | Signed                                                                                                                                                                                        |
| 6       | deviceCustomString1      | Signed                                                                                                                                                                                        |
| 6       | deviceCustomString2Label | Signature                                                                                                                                                                                     |
| 6       | deviceCustomString2      | Signature                                                                                                                                                                                     |
| 6       | deviceCustomString3Label | Signature Status                                                                                                                                                                              |
| 6       | deviceCustomString3      | SignatureStatus                                                                                                                                                                               |
|         |                          |                                                                                                                                                                                               |
| 7       | message                  | __concatenate("Image Loaded: ",ImageLoaded," Signed: ",Signed," Valid: ",SignatureStatus," Product: ",Product," Company: ",Company," Description: ",Description," FileVersion: ",FileVersion) |
| 7       | deviceEventClassId       | SysmonTask-SYSMON_IMAGE_LOAD                                                                                                                                                                  |
| 7       | deviceCustomString1Label | Signed                                                                                                                                                                                        |
| 7       | deviceCustomString1      | Signed                                                                                                                                                                                        |
| 7       | deviceCustomString2Label | Signature                                                                                                                                                                                     |
| 7       | deviceCustomString2      | Signature                                                                                                                                                                                     |
| 7       | deviceCustomString3Label | Signature Status                                                                                                                                                                              |
| 7       | deviceCustomString3      | SignatureStatus                                                                                                                                                                               |
| 7       | destinationServiceName   | Product                                                                                                                                                                                       |
| 7       | oldFileName              | OriginalFileName                                                                                                                                                                              |
|         |                          |                                                                                                                                                                                               |
| 8       | message                  | CreateRemoteThread detected                                                                                                                                                                   |
| 8       | deviceEventClassId       | SysmonTask-SYSMON_CREATE_REMOTE_THREAD                                                                                                                                                        |
| 8       | deviceCustomString1Label | New Thread ID                                                                                                                                                                                 |
| 8       | deviceCustomString1      | NewThreadId                                                                                                                                                                                   |
| 8       | deviceCustomString2Label | Start Address                                                                                                                                                                                 |
| 8       | deviceCustomString2      | StartAddress                                                                                                                                                                                  |
| 8       | deviceCustomString3Label | Start Module                                                                                                                                                                                  |
| 8       | deviceCustomString3      | StartModule                                                                                                                                                                                   |
| 8       | deviceCustomString4Label | Start Function                                                                                                                                                                                |
| 8       | deviceCustomString4      | StartFunction                                                                                                                                                                                 |
|         |                          |                                                                                                                                                                                               |
| 9       | message                  | __concatenate("RawAccessRead detected. Image: ",Image)                                                                                                                                        |
| 9       | deviceEventClassId       | SysmonTask-SYSMON_RAWACCESS_READ                                                                                                                                                              |
| 9       | deviceCustomString1Label | Device                                                                                                                                                                                        |
| 9       | deviceCustomString1      | Device                                                                                                                                                                                        |
|         |                          |                                                                                                                                                                                               |
| 10      | message                  | __concatenate("Process accessed. Target Process: ",TargetImage)                                                                                                                               |
| 10      | deviceEventClassId       | SysmonTask-SYSMON_ACCESS_PROCESS                                                                                                                                                              |
| 10      | deviceCustomString1Label | Source Thread ID                                                                                                                                                                              |
| 10      | deviceCustomString1      | SourceThreadId                                                                                                                                                                                |
| 10      | deviceCustomString2Label | Granted Access                                                                                                                                                                                |
| 10      | deviceCustomString2      | GrantedAccess                                                                                                                                                                                 |
| 10      | deviceCustomString3Label | Call Trace                                                                                                                                                                                    |
| 10      | deviceCustomString3      | CallTrace                                                                                                                                                                                     |
|         |                          |                                                                                                                                                                                               |
| 11      | message                  | __concatenate("File: ",TargetFilename," created by: ",Image)                                                                                                                                  |
| 11      | deviceEventClassId       | SysmonTask-SYSMON_FILE_CREATE                                                                                                                                                                 |
|         |                          |                                                                                                                                                                                               |
| 12      | message                  | __concatenate("Registry: ",EventType," Object: ",TargetObject," by process: ",Image)                                                                                                          |
| 12      | deviceEventClassId       | SysmonTask-SYSMON_REG_KEY                                                                                                                                                                     |
| 12      | fileName                 | TargetObject                                                                                                                                                                                  |
|         |                          |                                                                                                                                                                                               |
| 13      | message                  | __concatenate("Registry Value: ",TargetObject," set by process: ",Image)                                                                                                                      |
| 13      | deviceEventClassId       | SysmonTask-SYSMON_REG_SETVALUE                                                                                                                                                                |
| 13      | deviceCustomString1Label | Registry Value Details                                                                                                                                                                        |
| 13      | deviceCustomString1      | Details                                                                                                                                                                                       |
| 13      | fileName                 | TargetObject                                                                                                                                                                                  |
|         |                          |                                                                                                                                                                                               |
| 14      | message                  | __concatenate("Registry Object renamed: ",TargetObject," New name: ",NewName)                                                                                                                 |
| 14      | deviceEventClassId       | SysmonTask-SYSMON_REG_NAME                                                                                                                                                                    |
| 14      | oldFileName              | TargetObject                                                                                                                                                                                  |
| 14      | fileName                 | NewName                                                                                                                                                                                       |
|         |                          |                                                                                                                                                                                               |
| 15      | message                  | __concatenate("File Stream Created: ",TargetFilename," by process: ",Image)                                                                                                                   |
| 15      | deviceEventClassId       | SysmonTask-SYSMON_FILE_CREATE_STREAM_HASH                                                                                                                                                     |
|         |                          |                                                                                                                                                                                               |
| 16      | message                  | __concatenate("Sysmon configuration changed. Configuration: ",Configuration)                                                                                                                  |
| 16      | deviceEventClassId       | SysmonTask-SYSMON_SERVICE_CONFIGURATION_CHANGE                                                                                                                                                |
| 16      | fileName                 | Configuration                                                                                                                                                                                 |
| 16      | fileHash                 | ConfigurationFileHash                                                                                                                                                                         |
|         |                          |                                                                                                                                                                                               |
| 17      | message                  | __concatenate("Pipe: ",PipeName," created                                                                                                                                                     |
| 17      | deviceEventClassId       | SysmonTask-SYSMON_CREATE_NAMEDPIPE                                                                                                                                                            |
| 17      | fileName                 | PipeName                                                                                                                                                                                      |
|         |                          |                                                                                                                                                                                               |
| 18      | message                  | __concatenate("Pipe: ",PipeName," connected                                                                                                                                                   |
| 18      | deviceEventClassId       | SysmonTask-SYSMON_CONNECT_NAMEDPIPE                                                                                                                                                           |
| 18      | fileName                 | PipeName                                                                                                                                                                                      |
|         |                          |                                                                                                                                                                                               |
| 19      | message                  | __concatenate(Name," ",Operation," Namespace: ",Namespace)                                                                                                                                    |
| 19      | deviceEventClassId       | SysmonTask-SYSMON_WMI_FILTER                                                                                                                                                                  |
| 19      | deviceCustomString1Label | Name                                                                                                                                                                                          |
| 19      | deviceCustomString1      | Name                                                                                                                                                                                          |
| 19      | deviceCustomString2Label | Operation                                                                                                                                                                                     |
| 19      | deviceCustomString2      | Operation                                                                                                                                                                                     |
| 19      | deviceCustomString3Label | Event Namespace                                                                                                                                                                               |
| 19      | deviceCustomString3      | EventNamespace                                                                                                                                                                                |
| 19      | deviceCustomString4Label | Query                                                                                                                                                                                         |
| 19      | deviceCustomString4      | Query                                                                                                                                                                                         |
|         |                          |                                                                                                                                                                                               |
| 20      | message                  | __concatenate(Name," ",Operation," Type: ",Type," Location: ",Destination)                                                                                                                    |
| 20      | deviceEventClassId       | SysmonTask-SYSMON_WMI_CONSUMER                                                                                                                                                                |
| 20      | deviceCustomString1Label | Name                                                                                                                                                                                          |
| 20      | deviceCustomString1      | Name                                                                                                                                                                                          |
| 20      | deviceCustomString2Label | Operation                                                                                                                                                                                     |
| 20      | deviceCustomString2      | Operation                                                                                                                                                                                     |
| 20      | deviceCustomString3Label | Type                                                                                                                                                                                          |
| 20      | deviceCustomString3      | Type                                                                                                                                                                                          |
| 20      | fileName                 | Destination                                                                                                                                                                                   |
|         |                          |                                                                                                                                                                                               |
| 21      | message                  | __concatenate(EventType," Created by: ",User)                                                                                                                                                 |
| 21      | deviceEventClassId       | SysmonTask-SYSMON_WMI_BINDING                                                                                                                                                                 |
| 21      | deviceCustomString1Label | Consumer                                                                                                                                                                                      |
| 21      | deviceCustomString1      | Consumer                                                                                                                                                                                      |
| 21      | deviceCustomString2Label | Operation                                                                                                                                                                                     |
| 21      | deviceCustomString2      | Operation                                                                                                                                                                                     |
| 21      | deviceCustomString3Label | Filter                                                                                                                                                                                        |
| 21      | deviceCustomString3      | Filter                                                                                                                                                                                        |
|         |                          |                                                                                                                                                                                               |
| 22      | message                  | Mapped by DNS Response Code                                                                                                                                                                   |
| 22      | deviceEventClassId       | SysmonTask-DNS_QUERY                                                                                                                                                                          |
| 22      | destinationHostName      | QueryName                                                                                                                                                                                     |
| 22      | requestUrl               | QueryName                                                                                                                                                                                     |
| 22      | deviceCustomNumber1Label | Query Status                                                                                                                                                                                  |
| 22      | deviceCustomNumber1      | __safeToLong(QueryStatus)                                                                                                                                                                     |
| 22      | deviceCustomString1Label | Query Results                                                                                                                                                                                 |
| 22      | deviceCustomString1      | QueryResults                                                                                                                                                                                  |
|         |                          |                                                                                                                                                                                               |
| 255     | message                  | __concatenate("Sysmon Error ID: ",ID," Description: ",Description)                                                                                                                            |
| 255     | deviceEventClassId       | SysmonTask-SYSMON_ERROR                                                                                                                                                                       |
| 255     | deviceCustomString1Label | ID                                                                                                                                                                                            |
| 255     | deviceCustomString1      | ID                                                                                                                                                                                            |
| 255     | deviceCustomString2Label | Description                                                                                                                                                                                   |
| 255     | deviceCustomString2      | Description                                                                                                                                                                                   |




# USE CASE

Detect suspicious processes, Powershell use, dual use tools and attempts of lateral movement (and more)

Commmercial content package available for ArcSight SYSMON Content Package Via SOC Prime (https://socprime.com/)
Sysmon Framework contains 26 scenarios which are recommended for monitoring in SOC and early detection of APT activity.
https://tdm.socprime.com/use-case-library/info/425/

# Update 04/10/2019 - Microfocus release SmartConnector for Microsoft Sysmon
Microfocus have now released an out of the box SmartConnector for Sysmon - most organisations should check that out in the first instance.
https://community.microfocus.com/t5/ArcSight-Connectors/MS-Sysmon-Logs-Windows-Event-Log-Native/ta-p/2697357
We will review the continued maintenance of this FlexConnector once the quality / adoption of the OOB release is better known.

