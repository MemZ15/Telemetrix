#pragma once
#include "includes.h"

#define HEADER_FIELD(NtHeaders, Field) ((NtHeaders)->OptionalHeader.Field)
typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;
extern "C" NTSTATUS NTAPI NtCreateSection(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
);

extern "C" NTSTATUS NTAPI NtMapViewOfSection(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ DWORD InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect
);

extern "C" NTSTATUS NTAPI NtUnmapViewOfSection(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress
);

extern "C" NTSTATUS NTAPI NtReadFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_ PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key
);

inline NTSTATUS RtlOpenFile(
    _Out_ PHANDLE FileHandle,
    _In_ PCWSTR FilePath
) {
    UNICODE_STRING UnicodePath;
    WCHAR NtPath[MAX_PATH] = { 0 };

    // Prefix with \??\ to make it a valid NT path
    if ( swprintf_s( NtPath, L"\\??\\%ls", FilePath ) < 0 ) {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }

    RtlInitUnicodeString( &UnicodePath, NtPath );

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes( &ObjectAttributes, &UnicodePath, OBJ_CASE_INSENSITIVE, NULL, NULL );

    IO_STATUS_BLOCK IoStatusBlock = {};

    return NtCreateFile(
        FileHandle,
        GENERIC_READ | SYNCHRONIZE,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
}


extern "C" NTSTATUS NTAPI RtlImageNtHeaderEx(
    _In_ ULONG Flags,
    _In_ PVOID Base,
    _In_ SIZE_T Size,
    _Out_ PIMAGE_NT_HEADERS* OutHeaders
);


