////////////////////////////////////////
// Events
//
//
//  Values are 32 bit values laid out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//
#define FACILITY_SYSTEM                  0x0
#define FACILITY_RUNTIME                 0x2
#define FACILITY_STUBS                   0x3
#define FACILITY_IO_ERROR_CODE           0x4


//
// Define the severity codes
//
#define STATUS_SEVERITY_SUCCESS          0x0
#define STATUS_SEVERITY_INFORMATIONAL    0x1
#define STATUS_SEVERITY_WARNING          0x2
#define STATUS_SEVERITY_ERROR            0x3


//
// MessageId: PROCESS_PROTECTION_ADDED
//
// MessageText:
//
// RPC Firewall protection added.%n%nProcess Information:%n%tProcess ID:%t%2%n%tImage Path:%t%1
//
#define PROCESS_PROTECTION_ADDED         ((DWORD)0x40020001L)

//
// MessageId: PROCESS_PROTECTION_REMOVED
//
// MessageText:
//
// RPC Firewall protection removed.%n%nProcess Information:%n%tProcess ID:%t%2%n%tImage Path:%t%1
//
#define PROCESS_PROTECTION_REMOVED       ((DWORD)0x40020002L)

//
// MessageId: RPC_SERVER_CALL
//
// MessageText:
//
// An RPC server function was called.%n%nProcess Information:%n%tProcess ID:%t%2%n%tImage Path:%t%3%n%tRPCRT_Func:%t%1%n%nNetwork Information:%n%tProtocol:%t%4%n%tEndpoint:%t%5%n%tClient Network Address:%t%6%n%tClient Port:%t%12%n%tServer Network Address:%t%13%n%tServer Port:%t%14%nRPC Information:%n%tInterfaceUuid:%t%7%n%tOpNum:%t%t%8%n%nSubject:%n%tSecurity ID:%t%9%n%nDetailed Authentication Information:%n%tAuthentication Level:%t%10%n%tAuthentication Service:%t%11
//
#define RPC_SERVER_CALL                  ((DWORD)0x40020003L)

