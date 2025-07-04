#pragma once

#include <winternl.h>
#include <ntstatus.h>

#define USER_SHARED_DATA        0x7FFE0000
#define SharedUserData          ((_KUSER_SHARED_DATA * const)USER_SHARED_DATA)

#pragma pack(push, 4)

//0xa80 bytes (sizeof)
typedef struct _KUSER_SHARED_DATA
{
    ULONG TickCountLowDeprecated;                                           //0x0
    ULONG TickCountMultiplier;                                              //0x4
    volatile struct _KSYSTEM_TIME* InterruptTime;                            //0x8
    volatile struct _KSYSTEM_TIME* SystemTime;                               //0x14
    volatile struct _KSYSTEM_TIME* TimeZoneBias;                             //0x20
    USHORT ImageNumberLow;                                                  //0x2c
    USHORT ImageNumberHigh;                                                 //0x2e
    WCHAR NtSystemRoot[260];                                                //0x30
    ULONG MaxStackTraceDepth;                                               //0x238
    ULONG CryptoExponent;                                                   //0x23c
    ULONG TimeZoneId;                                                       //0x240
    ULONG LargePageMinimum;                                                 //0x244
    ULONG AitSamplingValue;                                                 //0x248
    ULONG AppCompatFlag;                                                    //0x24c
    ULONGLONG RNGSeedVersion;                                               //0x250
    ULONG GlobalValidationRunlevel;                                         //0x258
    volatile LONG TimeZoneBiasStamp;                                        //0x25c
    ULONG NtBuildNumber;                                                    //0x260
    enum _NT_PRODUCT_TYPE NtProductType;                                    //0x264
    UCHAR ProductTypeIsValid;                                               //0x268
    UCHAR Reserved0[1];                                                     //0x269
    USHORT NativeProcessorArchitecture;                                     //0x26a
    ULONG NtMajorVersion;                                                   //0x26c
    ULONG NtMinorVersion;                                                   //0x270
    UCHAR ProcessorFeatures[64];                                            //0x274
    ULONG Reserved1;                                                        //0x2b4
    ULONG Reserved3;                                                        //0x2b8
    volatile ULONG TimeSlip;                                                //0x2bc
    enum _ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;            //0x2c0
    ULONG BootId;                                                           //0x2c4
    union _LARGE_INTEGER SystemExpirationDate;                              //0x2c8
    ULONG SuiteMask;                                                        //0x2d0
    UCHAR KdDebuggerEnabled;                                                //0x2d4
    union
    {
        UCHAR MitigationPolicies;                                           //0x2d5
        struct
        {
            UCHAR NXSupportPolicy : 2;                                        //0x2d5
            UCHAR SEHValidationPolicy : 2;                                    //0x2d5
            UCHAR CurDirDevicesSkippedForDlls : 2;                            //0x2d5
            UCHAR Reserved : 2;                                               //0x2d5
        };
    };
    USHORT CyclesPerYield;                                                  //0x2d6
    volatile ULONG ActiveConsoleId;                                         //0x2d8
    volatile ULONG DismountCount;                                           //0x2dc
    ULONG ComPlusPackage;                                                   //0x2e0
    ULONG LastSystemRITEventTickCount;                                      //0x2e4
    ULONG NumberOfPhysicalPages;                                            //0x2e8
    UCHAR SafeBootMode;                                                     //0x2ec
    UCHAR VirtualizationFlags;                                              //0x2ed
    UCHAR Reserved12[2];                                                    //0x2ee
    union
    {
        ULONG SharedDataFlags;                                              //0x2f0
        struct
        {
            ULONG DbgErrorPortPresent : 1;                                    //0x2f0
            ULONG DbgElevationEnabled : 1;                                    //0x2f0
            ULONG DbgVirtEnabled : 1;                                         //0x2f0
            ULONG DbgInstallerDetectEnabled : 1;                              //0x2f0
            ULONG DbgLkgEnabled : 1;                                          //0x2f0
            ULONG DbgDynProcessorEnabled : 1;                                 //0x2f0
            ULONG DbgConsoleBrokerEnabled : 1;                                //0x2f0
            ULONG DbgSecureBootEnabled : 1;                                   //0x2f0
            ULONG DbgMultiSessionSku : 1;                                     //0x2f0
            ULONG DbgMultiUsersInSessionSku : 1;                              //0x2f0
            ULONG DbgStateSeparationEnabled : 1;                              //0x2f0
            ULONG SpareBits : 21;                                             //0x2f0
        };
    };
    ULONG DataFlagsPad[1];                                                  //0x2f4
    ULONGLONG TestRetInstruction;                                           //0x2f8
    LONGLONG QpcFrequency;                                                  //0x300
    ULONG SystemCall;                                                       //0x308
    ULONG Reserved2;                                                        //0x30c
    ULONGLONG FullNumberOfPhysicalPages;                                    //0x310
    ULONGLONG SystemCallPad[1];                                             //0x318
    union
    {
        volatile struct _KSYSTEM_TIME* TickCount;                            //0x320
        volatile ULONGLONG TickCountQuad;                                   //0x320
        ULONG ReservedTickCountOverlay[3];                                  //0x320
    };
    ULONG TickCountPad[1];                                                  //0x32c
    ULONG Cookie;                                                           //0x330
    ULONG CookiePad[1];                                                     //0x334
    LONGLONG ConsoleSessionForegroundProcessId;                             //0x338
    ULONGLONG TimeUpdateLock;                                               //0x340
    ULONGLONG BaselineSystemTimeQpc;                                        //0x348
    ULONGLONG BaselineInterruptTimeQpc;                                     //0x350
    ULONGLONG QpcSystemTimeIncrement;                                       //0x358
    ULONGLONG QpcInterruptTimeIncrement;                                    //0x360
    UCHAR QpcSystemTimeIncrementShift;                                      //0x368
    UCHAR QpcInterruptTimeIncrementShift;                                   //0x369
    USHORT UnparkedProcessorCount;                                          //0x36a
    ULONG EnclaveFeatureMask[4];                                            //0x36c
    ULONG TelemetryCoverageRound;                                           //0x37c
    USHORT UserModeGlobalLogger[16];                                        //0x380
    ULONG ImageFileExecutionOptions;                                        //0x3a0
    ULONG LangGenerationCount;                                              //0x3a4
    ULONGLONG Reserved4;                                                    //0x3a8
    volatile ULONGLONG InterruptTimeBias;                                   //0x3b0
    volatile ULONGLONG QpcBias;                                             //0x3b8
    ULONG ActiveProcessorCount;                                             //0x3c0
    volatile UCHAR ActiveGroupCount;                                        //0x3c4
    UCHAR Reserved9;                                                        //0x3c5
    union
    {
        USHORT QpcData;                                                     //0x3c6
        struct
        {
            volatile UCHAR QpcBypassEnabled;                                //0x3c6
            UCHAR QpcReserved;                                              //0x3c7
        };
    };
    union _LARGE_INTEGER TimeZoneBiasEffectiveStart;                        //0x3c8
    union _LARGE_INTEGER TimeZoneBiasEffectiveEnd;                          //0x3d0
    struct _XSTATE_CONFIGURATION XState;                                    //0x3d8
    struct _KSYSTEM_TIME* FeatureConfigurationChangeStamp;                   //0x720
    ULONG Spare;                                                            //0x72c
    ULONGLONG UserPointerAuthMask;                                          //0x730
    ULONG Reserved10[210];                                                  //0x738
};
#pragma pack(pop)

#ifndef RTL_CONSTANT_STRING
#define RTL_CONSTANT_STRING(s) { sizeof(s) - sizeof((s)[0]), sizeof(s), const_cast<PWSTR>(s) }
#endif

#define NtCurrentProcess		((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread			((HANDLE)(LONG_PTR)-2)
#define NtCurrentPeb()			(NtCurrentTeb()->ProcessEnvironmentBlock)
#define NtCurrentProcessId()	(NtCurrentTeb()->ClientId.UniqueProcess)
#define NtCurrentThreadId()		(NtCurrentTeb()->ClientId.UniqueThread)
#define RtlProcessHeap()		(NtCurrentPeb()->ProcessHeap)






typedef struct _PEB_CUSTOM {
    BYTE Reserved1[0x30];
    PVOID ProcessHeap;
} PEB_CUSTOM, * PPEB_CUSTOM;

extern "C" NTSTATUS NTAPI NtQueryIntervalProfile(
    ULONG ProfileSource,
    PULONG Interval
);

typedef struct MY_LIST_ENTRY64 {
    ULONGLONG Flink;
    ULONGLONG Blink;
} _MY_LIST_ENTRY64;

typedef struct _LDR_DATA_TABLE_ENTRY64 {
    LIST_ENTRY64 InLoadOrderLinks;
    LIST_ENTRY64 InMemoryOrderLinks;
    LIST_ENTRY64 InInitializationOrderLinks;
    ULONGLONG DllBase;
    ULONGLONG EntryPoint;
    ULONG SizeOfImage;
    _UNICODE_STRING FullDllName;
    _UNICODE_STRING BaseDllName;
    // etc...
} LDR_DATA_TABLE_ENTRY64;


typedef struct MY_PEB
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages : 1;                                    //0x3
            UCHAR IsProtectedProcess : 1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
            UCHAR IsPackagedProcess : 1;                                      //0x3
            UCHAR IsAppContainer : 1;                                         //0x3
            UCHAR IsProtectedProcessLight : 1;                                //0x3
            UCHAR IsLongPathAwareProcess : 1;                                 //0x3
        };
    };
    UCHAR Padding0[4];                                                      //0x4
    VOID* Mutant;                                                           //0x8
    VOID* ImageBaseAddress;                                                 //0x10
    struct _PEB_LDR_DATA* Ldr;                                              //0x18
    struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x20
    VOID* SubSystemData;                                                    //0x28
    VOID* ProcessHeap;                                                      //0x30
    struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
    union _SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x40
    VOID* IFEOKey;                                                          //0x48
    union
    {
        ULONG CrossProcessFlags;                                            //0x50
        struct
        {
            ULONG ProcessInJob : 1;                                           //0x50
            ULONG ProcessInitializing : 1;                                    //0x50
            ULONG ProcessUsingVEH : 1;                                        //0x50
            ULONG ProcessUsingVCH : 1;                                        //0x50
            ULONG ProcessUsingFTH : 1;                                        //0x50
            ULONG ProcessPreviouslyThrottled : 1;                             //0x50
            ULONG ProcessCurrentlyThrottled : 1;                              //0x50
            ULONG ProcessImagesHotPatched : 1;                                //0x50
            ULONG ReservedBits0 : 24;                                         //0x50
        };
    };
    UCHAR Padding1[4];                                                      //0x54
    union
    {
        VOID* KernelCallbackTable;                                          //0x58
        VOID* UserSharedInfoPtr;                                            //0x58
    };
    ULONG SystemReserved;                                                   //0x60
    ULONG AtlThunkSListPtr32;                                               //0x64
    VOID* ApiSetMap;                                                        //0x68
    ULONG TlsExpansionCounter;                                              //0x70
    UCHAR Padding2[4];                                                      //0x74
    struct _RTL_BITMAP* TlsBitmap;                                          //0x78
    ULONG TlsBitmapBits[2];                                                 //0x80
    VOID* ReadOnlySharedMemoryBase;                                         //0x88
    VOID* SharedData;                                                       //0x90
    VOID** ReadOnlyStaticServerData;                                        //0x98
    VOID* AnsiCodePageData;                                                 //0xa0
    VOID* OemCodePageData;                                                  //0xa8
    VOID* UnicodeCaseTableData;                                             //0xb0
    ULONG NumberOfProcessors;                                               //0xb8
    ULONG NtGlobalFlag;                                                     //0xbc
    union _LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
    ULONGLONG HeapSegmentReserve;                                           //0xc8
    ULONGLONG HeapSegmentCommit;                                            //0xd0
    ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
    ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
    ULONG NumberOfHeaps;                                                    //0xe8
    ULONG MaximumNumberOfHeaps;                                             //0xec
    VOID** ProcessHeaps;                                                    //0xf0
    VOID* GdiSharedHandleTable;                                             //0xf8
    VOID* ProcessStarterHelper;                                             //0x100
    ULONG GdiDCAttributeList;                                               //0x108
    UCHAR Padding3[4];                                                      //0x10c
    struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
    ULONG OSMajorVersion;                                                   //0x118
    ULONG OSMinorVersion;                                                   //0x11c
    USHORT OSBuildNumber;                                                   //0x120
    USHORT OSCSDVersion;                                                    //0x122
    ULONG OSPlatformId;                                                     //0x124
    ULONG ImageSubsystem;                                                   //0x128
    ULONG ImageSubsystemMajorVersion;                                       //0x12c
    ULONG ImageSubsystemMinorVersion;                                       //0x130
    UCHAR Padding4[4];                                                      //0x134
    ULONGLONG ActiveProcessAffinityMask;                                    //0x138
    ULONG GdiHandleBuffer[60];                                              //0x140
    VOID( *PostProcessInitRoutine )( );                                       //0x230
    struct _RTL_BITMAP* TlsExpansionBitmap;                                 //0x238
    ULONG TlsExpansionBitmapBits[32];                                       //0x240
    ULONG SessionId;                                                        //0x2c0
    UCHAR Padding5[4];                                                      //0x2c4
    union _ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
    union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
    VOID* pShimData;                                                        //0x2d8
    VOID* AppCompatInfo;                                                    //0x2e0
    struct _UNICODE_STRING CSDVersion;                                      //0x2e8
    struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x2f8
    struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x300
    struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x308
    struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x310
    ULONGLONG MinimumStackCommit;                                           //0x318
    VOID* SparePointers[2];                                                 //0x320
    VOID* PatchLoaderData;                                                  //0x330
    struct _CHPEV2_PROCESS_INFO* ChpeV2ProcessInfo;                         //0x338
    ULONG AppModelFeatureState;                                             //0x340
    ULONG SpareUlongs[2];                                                   //0x344
    USHORT ActiveCodePage;                                                  //0x34c
    USHORT OemCodePage;                                                     //0x34e
    USHORT UseCaseMapping;                                                  //0x350
    USHORT UnusedNlsField;                                                  //0x352
    VOID* WerRegistrationData;                                              //0x358
    VOID* WerShipAssertPtr;                                                 //0x360
    VOID* EcCodeBitMap;                                                     //0x368
    VOID* pImageHeaderHash;                                                 //0x370
    union
    {
        ULONG TracingFlags;                                                 //0x378
        struct
        {
            ULONG HeapTracingEnabled : 1;                                     //0x378
            ULONG CritSecTracingEnabled : 1;                                  //0x378
            ULONG LibLoaderTracingEnabled : 1;                                //0x378
            ULONG SpareTracingBits : 29;                                      //0x378
        };
    };
    UCHAR Padding6[4];                                                      //0x37c
    ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
    ULONGLONG TppWorkerpListLock;                                           //0x388
    struct _LIST_ENTRY TppWorkerpList;                                      //0x390
    VOID* WaitOnAddressHashTable[128];                                      //0x3a0
    VOID* TelemetryCoverageHeader;                                          //0x7a0
    ULONG CloudFileFlags;                                                   //0x7a8
    ULONG CloudFileDiagFlags;                                               //0x7ac
    CHAR PlaceholderCompatibilityMode;                                      //0x7b0
    CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
    struct _LEAP_SECOND_DATA* LeapSecondData;                               //0x7b8
    union
    {
        ULONG LeapSecondFlags;                                              //0x7c0
        struct
        {
            ULONG SixtySecondEnabled : 1;                                     //0x7c0
            ULONG Reserved : 31;                                              //0x7c0
        };
    };
    ULONG NtGlobalFlag2;                                                    //0x7c4
    ULONGLONG ExtendedFeatureDisableMask;                                   //0x7c8
} _MY_PEB;

//0xa0 bytes (sizeof)
typedef struct _KLDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    VOID* ExceptionTable;                                                   //0x10
    ULONG ExceptionTableSize;                                               //0x18
    VOID* GpValue;                                                          //0x20
    struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;                        //0x28
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    ULONG Flags;                                                            //0x68
    USHORT LoadCount;                                                       //0x6c
    union
    {
        USHORT SignatureLevel : 4;                                            //0x6e
        USHORT SignatureType : 3;                                             //0x6e
        USHORT Frozen : 2;                                                    //0x6e
        USHORT HotPatch : 1;                                                  //0x6e
        USHORT Unused : 6;                                                    //0x6e
        USHORT EntireField;                                                 //0x6e
    } u1;                                                                   //0x6e
    VOID* SectionPointer;                                                   //0x70
    ULONG CheckSum;                                                         //0x78
    ULONG CoverageSectionSize;                                              //0x7c
    VOID* CoverageSection;                                                  //0x80
    VOID* LoadedImports;                                                    //0x88
    union
    {
        VOID* Spare;                                                        //0x90
        struct _KLDR_DATA_TABLE_ENTRY* NtDataTableEntry;                    //0x90
    };
    ULONG SizeOfImageNotRounded;                                            //0x98
    ULONG TimeDateStamp;                                                    //0x9c
};

#ifndef RTL_CONSTANT_OBJECT_ATTRIBUTES
#define RTL_CONSTANT_OBJECT_ATTRIBUTES(p, a) { sizeof(OBJECT_ATTRIBUTES), nullptr, p, a, nullptr, nullptr }
#endif

#define NT_MACHINE					L"\\Registry\\Machine\\"
#define SVC_BASE					NT_MACHINE L"System\\CurrentControlSet\\Services\\"

#define RTL_REGISTRY_ABSOLUTE         0   // Full path from root
#define RTL_REGISTRY_SERVICES         1   // \Registry\Machine\System\CurrentControlSet\Services
#define RTL_REGISTRY_CONTROL          2   // \Registry\Machine\System\CurrentControlSet\Control
#define RTL_REGISTRY_WINDOWS_NT       3   // \Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion
#define RTL_REGISTRY_DEVICEMAP        4   // \Registry\Machine\Hardware\DeviceMap
#define RTL_REGISTRY_USER             5   // \Registry\User\<SID>
#define RTL_REGISTRY_HANDLE           0x40000000
#define RTL_REGISTRY_OPTIONAL         0x80000000

typedef enum _RTL_PATH_TYPE {
    RtlPathTypeUnknown = 0,
    RtlPathTypeUncAbsolute,         // \\server\share
    RtlPathTypeDriveAbsolute,       // C:\path
    RtlPathTypeDriveRelative,       // C:path (relative to current dir of drive)
    RtlPathTypeRooted,              // \path (rooted but no drive)
    RtlPathTypeRelative,            // path (relative path)
    RtlPathTypeLocalDevice,         // \\.\ or \\?\ device paths
    RtlPathTypeRootLocalDevice      // \\?\C:\path or \\?\UNC\server\share
} RTL_PATH_TYPE;

extern "C" {NTSYSAPI NTSTATUS NTAPI NtLoadDriver( PUNICODE_STRING DriverServiceName ); }

extern "C" {NTSYSAPI NTSTATUS NTAPI NtUnloadDriver( PUNICODE_STRING DriverServiceName ); }

extern "C" {NTSYSAPI NTSTATUS NTAPI RtlCreateRegistryKey( ULONG RelativeTo, PCWSTR Path ); }

extern "C" {NTSYSAPI NTSTATUS NTAPI RtlWriteRegistryValue( ULONG RelativeTo, PCWSTR Path, PCWSTR ValueName, ULONG ValueType, PVOID ValueData, ULONG ValueLength ); }

extern "C" { NTSYSAPI NTSTATUS NTAPI RtlAdjustPrivilege( ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled ); }

extern "C" { NTSYSAPI NTSTATUS NTAPI RtlGetFullPathName_UEx( _In_ PWSTR FileName, _In_ ULONG BufferLength, _Out_writes_bytes_( BufferLength ) PWSTR Buffer, _Out_opt_ PWSTR* FilePart, _Out_opt_ RTL_PATH_TYPE* InputPathType ); }

extern "C" { NTSYSAPI NTSTATUS NTAPI RtlGetFullPathName_UEx( _In_ PWSTR FileName, _In_ ULONG BufferLength, _Out_writes_bytes_( BufferLength ) PWSTR Buffer, _Out_opt_ PWSTR* FilePart, _Out_opt_ RTL_PATH_TYPE* InputPathType ); }



typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef PVOID( *RtlAllocateHeap_t )( PVOID, ULONG, SIZE_T );
extern "C" {PVOID RtlAllocateHeap( PVOID HeapHandle, ULONG Flags, SIZE_T Size ); }

typedef BOOLEAN( *RtlFreeHeap_t )( PVOID, ULONG, PVOID );
extern "C" BOOLEAN RtlFreeHeap( PVOID HeapHandle, ULONG Flags, PVOID HeapBase );