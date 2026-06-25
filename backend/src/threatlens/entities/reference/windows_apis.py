"""Seed list of Windows API functions commonly referenced in malware analysis.

``WINDOWS_APIS`` maps a lowercased function name to its canonical (cased) form.
The detector also recognizes native (``Nt``/``Zw``/``Rtl``) functions outside
this list via a conservative heuristic; this catalog covers frequently-abused
Win32/native calls so they classify with high confidence.
"""

from __future__ import annotations

_APIS: tuple[str, ...] = (
    # Memory / process injection
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "VirtualFree", "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "CreateRemoteThreadEx", "OpenProcess", "OpenThread", "QueueUserAPC",
    "SetThreadContext", "GetThreadContext", "ResumeThread", "SuspendThread",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "NtMapViewOfSection",
    "NtCreateThreadEx", "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
    "NtProtectVirtualMemory", "RtlMoveMemory", "RtlCopyMemory", "RtlCreateUserThread",
    "HeapAlloc", "HeapCreate", "GlobalAlloc", "MapViewOfFile", "CreateFileMapping",
    # Module / symbol resolution
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "GetModuleHandleA", "GetModuleHandleW", "GetModuleFileNameA",
    # Process / execution
    "CreateProcessA", "CreateProcessW", "CreateProcessInternalW", "WinExec",
    "ShellExecuteA", "ShellExecuteExW", "CreateThread", "ExitProcess",
    "TerminateProcess", "GetCurrentProcess",
    # Files
    "CreateFileA", "CreateFileW", "WriteFile", "ReadFile", "DeleteFileA",
    "MoveFileA", "CopyFileA", "SetFileAttributesA",
    # Registry
    "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegCreateKeyExA",
    "RegQueryValueExA", "RegDeleteValueA", "RegCloseKey", "RegGetValueA",
    # Networking / download
    "InternetOpenA", "InternetOpenUrlA", "InternetReadFile", "HttpOpenRequestA",
    "HttpSendRequestA", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
    "URLDownloadToFileA", "URLDownloadToFileW", "send", "recv", "connect", "WSASocketA",
    # Services / persistence
    "CreateServiceA", "OpenSCManagerA", "StartServiceA", "RegisterServiceCtrlHandler",
    # Hooking / keylogging
    "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState",
    "GetForegroundWindow", "FindWindowA", "GetClipboardData",
    # Process enumeration
    "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
    "EnumProcesses", "EnumProcessModules",
    # Anti-analysis
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "OutputDebugStringA", "GetTickCount", "QueryPerformanceCounter", "Sleep",
    "NtDelayExecution", "GetSystemInfo",
    # Crypto
    "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA", "CryptGenKey",
    "CryptHashData", "BCryptEncrypt", "BCryptDecrypt",
    # Tokens / privileges
    "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA",
    "DuplicateTokenEx", "ImpersonateLoggedOnUser", "SetTokenInformation",
    # Synchronization / misc
    "CreateMutexA", "OpenMutexA", "GetComputerNameA", "GetUserNameA",
    "RegisterHotKey", "GetModuleHandleExA",
)

WINDOWS_APIS: dict[str, str] = {name.lower(): name for name in _APIS}
