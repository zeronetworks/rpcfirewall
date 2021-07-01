SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS
               Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
               Warning=0x2:STATUS_SEVERITY_WARNING
               Error=0x3:STATUS_SEVERITY_ERROR
              )

FacilityNames=(System=0x0:FACILITY_SYSTEM
               Runtime=0x2:FACILITY_RUNTIME
               Stubs=0x3:FACILITY_STUBS
               Io=0x4:FACILITY_IO_ERROR_CODE
              )


LanguageNames =
    (
        English = 0x0409:Messages_ENU
    )


MessageIdTypedef=DWORD

;////////////////////////////////////////
;// Events
;//

MessageId       = 0x1
Severity        = Informational
Facility        = Runtime
SymbolicName    = PROCESS_PROTECTION_ADDED
Language        = English
RPC Firewall protection added.%n%nProcess Information:%n%tProcess ID:%t%2%n%tImage Path:%t%1
.

MessageId       = 0x2
Severity        = Informational
Facility        = Runtime
SymbolicName    = PROCESS_PROTECTION_REMOVED
Language        = English
RPC Firewall protection removed.%n%nProcess Information:%n%tProcess ID:%t%2%n%tImage Path:%t%1
.

MessageId       = 0x3
Severity        = Informational
Facility        = Runtime
SymbolicName    = RPC_SERVER_CALL
Language        = English
An RPC server function was called.%n%nProcess Information:%n%tProcess ID:%t%2%n%tImage Path:%t%3%n%tRPCRT_Func:%t%1%n%nNetwork Information:%n%tProtocol:%t%4%n%tEndpoint:%t%5%n%tSource Network Address:%t%6%n%nRPC Information:%n%tInterfaceUuid:%t%7%n%tOpNum:%t%t%8%n%nSubject:%n%tSecurity ID:%t%9%n%nDetailed Authentication Information:%n%tAuthentication Level:%t%10%n%tAuthentication Service:%t%11
.
