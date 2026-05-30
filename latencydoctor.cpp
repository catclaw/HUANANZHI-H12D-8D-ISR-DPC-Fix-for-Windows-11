#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <psapi.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <shlwapi.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// DPC Latency Doctor
// A conservative Windows latency diagnostics and tuning utility.
//
// It intentionally avoids binary patching Windows, Microsoft-signed files, or
// third-party drivers. Windows driver signing, PatchGuard, Secure Boot, and
// servicing make that class of change fragile and dangerous. Instead this tool
// focuses on reversible configuration changes and evidence collection.

using std::wstring;
namespace fs = std::filesystem;

static constexpr DWORD SERVICE_KERNEL_OR_FILE = SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER;

struct DriverInfo {
    wstring name;
    wstring path;
    wstring company;
    wstring description;
    wstring product;
    wstring version;
    wstring serviceName;
    wstring serviceDisplayName;
    DWORD serviceStart = 0xffffffff;
    DWORD serviceType = 0;
    ULONGLONG fileSize = 0;
    FILETIME writeTime{};
    bool loaded = false;
    void* base = nullptr;
};

struct CounterSample {
    LARGE_INTEGER idle{};
    LARGE_INTEGER kernel{};
    LARGE_INTEGER user{};
    LARGE_INTEGER dpc{};
    LARGE_INTEGER interrupt{};
    ULONG interruptCount = 0;
};

typedef LONG NTSTATUS;
using NtQuerySystemInformationFn = NTSTATUS (NTAPI *)(ULONG, PVOID, ULONG, PULONG);

struct ServiceMapEntry {
    wstring serviceName;
    wstring displayName;
    DWORD type = 0;
    DWORD start = 0xffffffff;
    wstring imagePath;
};

typedef struct _RTL_PROCESS_MODULE_INFORMATION_LOCAL {
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
} RTL_PROCESS_MODULE_INFORMATION_LOCAL;

typedef struct _RTL_PROCESS_MODULES_LOCAL {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION_LOCAL Modules[1];
} RTL_PROCESS_MODULES_LOCAL;

struct BackupWriter {
    fs::path dir;
    std::wofstream log;
    bool enabled = true;

    explicit BackupWriter(const fs::path& d, bool writeFiles) : dir(d), enabled(writeFiles) {
        if (enabled) {
            fs::create_directories(dir);
            log.open(dir / L"changes.log", std::ios::app);
        }
    }

    void line(const wstring& s) {
        if (!enabled || !log.is_open()) return;
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::tm tm{};
        localtime_s(&tm, &now);
        log << L"[" << std::put_time(&tm, L"%Y-%m-%d %H:%M:%S") << L"] " << s << L"\n";
        log.flush();
    }
};

static NtQuerySystemInformationFn getNtQuerySystemInformation() {
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return nullptr;
    NtQuerySystemInformationFn fn = nullptr;
    FARPROC proc = GetProcAddress(ntdll, "NtQuerySystemInformation");
    static_assert(sizeof(fn) == sizeof(proc), "unexpected function pointer size");
    std::memcpy(&fn, &proc, sizeof(fn));
    return fn;
}

static wstring toLower(wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return (wchar_t)towlower(c); });
    return s;
}

static wstring trim(wstring s) {
    auto notSpace = [](wchar_t c) { return !iswspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), notSpace));
    s.erase(std::find_if(s.rbegin(), s.rend(), notSpace).base(), s.end());
    return s;
}

static wstring basenameOf(const wstring& path) {
    if (path.empty()) return L"";
    const wchar_t* p = PathFindFileNameW(path.c_str());
    return p ? wstring(p) : path;
}

static wstring expandEnvStrings(const wstring& s) {
    DWORD needed = ExpandEnvironmentStringsW(s.c_str(), nullptr, 0);
    if (!needed) return s;
    std::vector<wchar_t> buf(needed + 2);
    if (!ExpandEnvironmentStringsW(s.c_str(), buf.data(), (DWORD)buf.size())) return s;
    return wstring(buf.data());
}

static wstring normalizeImagePath(wstring p) {
    p = trim(p);
    if (p.rfind(L"\\??\\", 0) == 0) {
        p = p.substr(4);
    }
    if (p.size() >= 2 && p.front() == L'"') {
        auto end = p.find(L'"', 1);
        if (end != wstring::npos) p = p.substr(1, end - 1);
    } else {
        auto sysPos = toLower(p).find(L".sys");
        if (sysPos != wstring::npos) p = p.substr(0, sysPos + 4);
    }
    p = expandEnvStrings(p);
    if (p.rfind(L"\\SystemRoot\\", 0) == 0 || p.rfind(L"\\systemroot\\", 0) == 0) {
        wchar_t win[MAX_PATH]{};
        GetWindowsDirectoryW(win, MAX_PATH);
        p = wstring(win) + p.substr(11);
    } else if (p.rfind(L"System32\\", 0) == 0 || p.rfind(L"system32\\", 0) == 0) {
        wchar_t win[MAX_PATH]{};
        GetWindowsDirectoryW(win, MAX_PATH);
        p = wstring(win) + L"\\" + p;
    }
    return p;
}

static wstring ansiToWide(const char* s) {
    if (!s || !*s) return L"";
    int needed = MultiByteToWideChar(CP_ACP, 0, s, -1, nullptr, 0);
    if (needed <= 0) return L"";
    std::vector<wchar_t> buf(needed + 1);
    MultiByteToWideChar(CP_ACP, 0, s, -1, buf.data(), needed);
    return wstring(buf.data());
}

static wstring formatFileTime(FILETIME ft) {
    if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) return L"";
    FILETIME local{};
    FileTimeToLocalFileTime(&ft, &local);
    SYSTEMTIME st{};
    FileTimeToSystemTime(&local, &st);
    wchar_t buf[64]{};
    swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static wstring readRegString(HKEY root, const wstring& subkey, const wstring& value) {
    HKEY h{};
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS) return L"";
    DWORD type = 0;
    DWORD cb = 0;
    auto rc = RegQueryValueExW(h, value.empty() ? nullptr : value.c_str(), nullptr, &type, nullptr, &cb);
    if (rc != ERROR_SUCCESS || cb == 0 || (type != REG_SZ && type != REG_EXPAND_SZ && type != REG_MULTI_SZ)) {
        RegCloseKey(h);
        return L"";
    }
    std::vector<wchar_t> buf((cb / sizeof(wchar_t)) + 2);
    rc = RegQueryValueExW(h, value.empty() ? nullptr : value.c_str(), nullptr, &type, (LPBYTE)buf.data(), &cb);
    RegCloseKey(h);
    if (rc != ERROR_SUCCESS) return L"";
    return wstring(buf.data());
}

static std::optional<DWORD> readRegDword(HKEY root, const wstring& subkey, const wstring& value) {
    HKEY h{};
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS) return std::nullopt;
    DWORD type = 0;
    DWORD data = 0;
    DWORD cb = sizeof(data);
    auto rc = RegQueryValueExW(h, value.c_str(), nullptr, &type, (LPBYTE)&data, &cb);
    RegCloseKey(h);
    if (rc != ERROR_SUCCESS || type != REG_DWORD) return std::nullopt;
    return data;
}

static bool ensureKey(HKEY root, const wstring& subkey, HKEY& h) {
    DWORD disp = 0;
    return RegCreateKeyExW(root, subkey.c_str(), 0, nullptr, 0,
                           KEY_READ | KEY_WRITE | KEY_WOW64_64KEY,
                           nullptr, &h, &disp) == ERROR_SUCCESS;
}

static wstring regRootName(HKEY root) {
    if (root == HKEY_LOCAL_MACHINE) return L"HKLM";
    if (root == HKEY_CURRENT_USER) return L"HKCU";
    return L"HK?";
}

static void backupRegValue(BackupWriter& backup, HKEY root, const wstring& subkey, const wstring& value) {
    HKEY h{};
    DWORD type = 0;
    DWORD cb = 0;
    LONG rc = RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &h);
    if (rc == ERROR_SUCCESS) {
        rc = RegQueryValueExW(h, value.c_str(), nullptr, &type, nullptr, &cb);
    }

    std::wstringstream ss;
    ss << L"REG_BACKUP\t" << regRootName(root) << L"\t" << subkey << L"\t" << value << L"\t";

    if (rc != ERROR_SUCCESS) {
        ss << L"<MISSING>";
        backup.line(ss.str());
        if (h) RegCloseKey(h);
        return;
    }

    std::vector<BYTE> data(cb);
    rc = RegQueryValueExW(h, value.c_str(), nullptr, &type, data.data(), &cb);
    RegCloseKey(h);
    if (rc != ERROR_SUCCESS) {
        ss << L"<READ_ERROR>";
        backup.line(ss.str());
        return;
    }

    ss << type << L"\t";
    if (type == REG_DWORD && cb >= sizeof(DWORD)) {
        DWORD d = *(DWORD*)data.data();
        ss << L"dword:" << std::hex << std::setw(8) << std::setfill(L'0') << d;
    } else if ((type == REG_SZ || type == REG_EXPAND_SZ) && cb >= sizeof(wchar_t)) {
        ss << L"string:" << (wchar_t*)data.data();
    } else {
        ss << L"hex:";
        for (DWORD i = 0; i < cb; ++i) {
            ss << std::hex << std::setw(2) << std::setfill(L'0') << (int)data[i];
        }
    }
    backup.line(ss.str());
}

static bool setRegDword(BackupWriter& backup, HKEY root, const wstring& subkey, const wstring& value, DWORD data, bool dryRun) {
    auto old = readRegDword(root, subkey, value);
    std::wcout << L"  " << regRootName(root) << L"\\" << subkey << L"\\" << value
               << L" = 0x" << std::hex << data << std::dec;
    if (old) std::wcout << L" (was 0x" << std::hex << *old << std::dec << L")";
    else std::wcout << L" (was missing/non-DWORD)";
    std::wcout << (dryRun ? L" [preview]\n" : L"\n");
    if (dryRun) return true;

    backupRegValue(backup, root, subkey, value);
    HKEY h{};
    if (!ensureKey(root, subkey, h)) {
        std::wcerr << L"    failed to open/create key, error " << GetLastError() << L"\n";
        return false;
    }
    LONG rc = RegSetValueExW(h, value.c_str(), 0, REG_DWORD, (const BYTE*)&data, sizeof(data));
    RegCloseKey(h);
    if (rc != ERROR_SUCCESS) {
        std::wcerr << L"    failed to write, error " << rc << L"\n";
        return false;
    }
    return true;
}

static bool setRegString(BackupWriter& backup, HKEY root, const wstring& subkey, const wstring& value, const wstring& data, bool dryRun) {
    auto old = readRegString(root, subkey, value);
    std::wcout << L"  " << regRootName(root) << L"\\" << subkey << L"\\" << value
               << L" = \"" << data << L"\"";
    if (!old.empty()) std::wcout << L" (was \"" << old << L"\")";
    else std::wcout << L" (was missing/non-string)";
    std::wcout << (dryRun ? L" [preview]\n" : L"\n");
    if (dryRun) return true;

    backupRegValue(backup, root, subkey, value);
    HKEY h{};
    if (!ensureKey(root, subkey, h)) {
        std::wcerr << L"    failed to open/create key, error " << GetLastError() << L"\n";
        return false;
    }
    DWORD bytes = (DWORD)((data.size() + 1) * sizeof(wchar_t));
    LONG rc = RegSetValueExW(h, value.c_str(), 0, REG_SZ, (const BYTE*)data.c_str(), bytes);
    RegCloseKey(h);
    if (rc != ERROR_SUCCESS) {
        std::wcerr << L"    failed to write, error " << rc << L"\n";
        return false;
    }
    return true;
}

static bool runProcess(const wstring& cmd, bool dryRun, DWORD* exitCodeOut = nullptr) {
    std::wcout << L"  $ " << cmd << (dryRun ? L" [preview]\n" : L"\n");
    if (dryRun) return true;

    std::vector<wchar_t> mutableCmd(cmd.begin(), cmd.end());
    mutableCmd.push_back(0);

    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    if (!CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        std::wcerr << L"    failed to start, error " << GetLastError() << L"\n";
        return false;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD ec = 0;
    GetExitCodeProcess(pi.hProcess, &ec);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (exitCodeOut) *exitCodeOut = ec;
    if (ec != 0) {
        std::wcerr << L"    exit code " << ec << L"\n";
        return false;
    }
    return true;
}

static std::vector<wstring> splitTabs(const wstring& s) {
    std::vector<wstring> parts;
    size_t start = 0;
    while (start <= s.size()) {
        size_t pos = s.find(L'\t', start);
        if (pos == wstring::npos) {
            parts.push_back(s.substr(start));
            break;
        }
        parts.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    return parts;
}

static HKEY parseRootName(const wstring& s) {
    if (s == L"HKLM") return HKEY_LOCAL_MACHINE;
    if (s == L"HKCU") return HKEY_CURRENT_USER;
    return nullptr;
}

static bool restoreLoggedValue(const wstring& line) {
    size_t marker = line.find(L"REG_BACKUP\t");
    if (marker == wstring::npos) return true;
    auto fields = splitTabs(line.substr(marker + 11));
    if (fields.size() < 4) return true;

    HKEY root = parseRootName(fields[0]);
    if (!root) return false;
    const wstring& subkey = fields[1];
    const wstring& value = fields[2];
    const wstring& typeOrMissing = fields[3];

    HKEY h{};
    if (typeOrMissing == L"<MISSING>") {
        LONG open = RegOpenKeyExW(root, subkey.c_str(), 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &h);
        if (open == ERROR_FILE_NOT_FOUND) return true;
        if (open != ERROR_SUCCESS) return false;
        LONG rc = RegDeleteValueW(h, value.c_str());
        RegCloseKey(h);
        std::wcout << L"  delete newly-created " << fields[0] << L"\\" << subkey << L"\\" << value << L"\n";
        return rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND;
    }

    if (fields.size() < 5) return true;
    DWORD type = (DWORD)_wtoi(typeOrMissing.c_str());
    if (RegCreateKeyExW(root, subkey.c_str(), 0, nullptr, 0,
                        KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &h, nullptr) != ERROR_SUCCESS) {
        return false;
    }

    bool ok = true;
    const wstring& data = fields[4];
    if (type == REG_DWORD && data.rfind(L"dword:", 0) == 0) {
        DWORD d = (DWORD)wcstoul(data.substr(6).c_str(), nullptr, 16);
        ok = RegSetValueExW(h, value.c_str(), 0, REG_DWORD, (const BYTE*)&d, sizeof(d)) == ERROR_SUCCESS;
        std::wcout << L"  restore " << fields[0] << L"\\" << subkey << L"\\" << value
                   << L" = 0x" << std::hex << d << std::dec << L"\n";
    } else if ((type == REG_SZ || type == REG_EXPAND_SZ) && data.rfind(L"string:", 0) == 0) {
        wstring s = data.substr(7);
        DWORD bytes = (DWORD)((s.size() + 1) * sizeof(wchar_t));
        ok = RegSetValueExW(h, value.c_str(), 0, type, (const BYTE*)s.c_str(), bytes) == ERROR_SUCCESS;
        std::wcout << L"  restore " << fields[0] << L"\\" << subkey << L"\\" << value
                   << L" = \"" << s << L"\"\n";
    }
    RegCloseKey(h);
    return ok;
}

static bool restoreChangeLog(const fs::path& logPath) {
    if (!fs::exists(logPath)) return true;
    std::wifstream in(logPath);
    if (!in) return false;
    bool ok = true;
    wstring line;
    while (std::getline(in, line)) {
        ok = restoreLoggedValue(line) && ok;
    }
    return ok;
}

static bool isAdmin() {
    BOOL isMember = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                                 &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isMember);
        FreeSid(adminGroup);
    }
    return isMember == TRUE;
}

static bool fileExists(const wstring& path) {
    DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static wstring system32Path(const wstring& exe) {
    wchar_t sys[MAX_PATH]{};
    GetSystemDirectoryW(sys, MAX_PATH);
    return wstring(sys) + L"\\" + exe;
}

static std::map<wstring, ServiceMapEntry> enumerateDriverServices() {
    std::map<wstring, ServiceMapEntry> out;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return out;

    DWORD bytesNeeded = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_STATE_ALL,
                          nullptr, 0, &bytesNeeded, &count, &resume, nullptr);
    std::vector<BYTE> buf(bytesNeeded + 64);
    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_STATE_ALL,
                               buf.data(), (DWORD)buf.size(), &bytesNeeded, &count, &resume, nullptr)) {
        CloseServiceHandle(scm);
        return out;
    }
    auto services = (ENUM_SERVICE_STATUS_PROCESSW*)buf.data();
    for (DWORD i = 0; i < count; ++i) {
        ServiceMapEntry e;
        e.serviceName = services[i].lpServiceName;
        e.displayName = services[i].lpDisplayName ? services[i].lpDisplayName : L"";
        e.type = services[i].ServiceStatusProcess.dwServiceType;

        SC_HANDLE svc = OpenServiceW(scm, e.serviceName.c_str(), SERVICE_QUERY_CONFIG);
        if (svc) {
            DWORD need = 0;
            QueryServiceConfigW(svc, nullptr, 0, &need);
            std::vector<BYTE> cfgbuf(need + 64);
            auto cfg = (QUERY_SERVICE_CONFIGW*)cfgbuf.data();
            if (QueryServiceConfigW(svc, cfg, (DWORD)cfgbuf.size(), &need)) {
                e.start = cfg->dwStartType;
                e.imagePath = normalizeImagePath(cfg->lpBinaryPathName ? cfg->lpBinaryPathName : L"");
            }
            CloseServiceHandle(svc);
        }
        out[toLower(basenameOf(e.imagePath))] = e;
    }
    CloseServiceHandle(scm);
    return out;
}

static wstring queryVersionString(const wstring& file, const wchar_t* key) {
    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(file.c_str(), &handle);
    if (!size) return L"";
    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(file.c_str(), 0, size, data.data())) return L"";

    struct LANGANDCODEPAGE { WORD wLanguage; WORD wCodePage; } *translate = nullptr;
    UINT cbTranslate = 0;
    if (!VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation", (LPVOID*)&translate, &cbTranslate) ||
        cbTranslate < sizeof(LANGANDCODEPAGE)) {
        return L"";
    }
    wchar_t subBlock[128]{};
    swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\%s",
               translate[0].wLanguage, translate[0].wCodePage, key);
    LPVOID value = nullptr;
    UINT len = 0;
    if (!VerQueryValueW(data.data(), subBlock, &value, &len) || !value || len == 0) return L"";
    return wstring((wchar_t*)value);
}

static wstring queryFileVersion(const wstring& file) {
    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(file.c_str(), &handle);
    if (!size) return L"";
    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(file.c_str(), 0, size, data.data())) return L"";
    VS_FIXEDFILEINFO* ffi = nullptr;
    UINT len = 0;
    if (!VerQueryValueW(data.data(), L"\\", (LPVOID*)&ffi, &len) || !ffi) return L"";
    std::wstringstream ss;
    ss << HIWORD(ffi->dwFileVersionMS) << L'.' << LOWORD(ffi->dwFileVersionMS) << L'.'
       << HIWORD(ffi->dwFileVersionLS) << L'.' << LOWORD(ffi->dwFileVersionLS);
    return ss.str();
}

static std::vector<DriverInfo> enumerateLoadedDrivers() {
    std::vector<DriverInfo> drivers;
    std::map<wstring, ServiceMapEntry> services = enumerateDriverServices();

    auto fn = getNtQuerySystemInformation();
    if (!fn) return drivers;
    ULONG needed = 0;
    NTSTATUS st = fn(11 /* SystemModuleInformation */, nullptr, 0, &needed);
    if (needed == 0) return drivers;
    std::vector<BYTE> buffer(needed + 64 * 1024);
    st = fn(11 /* SystemModuleInformation */, buffer.data(), (ULONG)buffer.size(), &needed);
    if (st < 0) return drivers;

    auto modules = reinterpret_cast<RTL_PROCESS_MODULES_LOCAL*>(buffer.data());
    std::set<wstring> seen;
    for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
        const auto& m = modules->Modules[i];
        DriverInfo d;
        d.path = normalizeImagePath(ansiToWide(reinterpret_cast<const char*>(m.FullPathName)));
        d.name = basenameOf(d.path);
        if (d.name.empty()) {
            d.name = ansiToWide(reinterpret_cast<const char*>(m.FullPathName + m.OffsetToFileName));
        }
        wstring key = toLower(d.name + L"|" + d.path);
        if (seen.count(key)) continue;
        seen.insert(key);
        d.loaded = true;
        d.base = m.ImageBase;

        auto svcIt = services.find(toLower(d.name));
        if (svcIt != services.end()) {
            d.serviceName = svcIt->second.serviceName;
            d.serviceDisplayName = svcIt->second.displayName;
            d.serviceStart = svcIt->second.start;
            d.serviceType = svcIt->second.type;
            if (!svcIt->second.imagePath.empty()) d.path = svcIt->second.imagePath;
        }

        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (GetFileAttributesExW(d.path.c_str(), GetFileExInfoStandard, &fad)) {
            d.writeTime = fad.ftLastWriteTime;
            d.fileSize = ((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
        }
        d.company = queryVersionString(d.path, L"CompanyName");
        d.description = queryVersionString(d.path, L"FileDescription");
        d.product = queryVersionString(d.path, L"ProductName");
        d.version = queryFileVersion(d.path);
        drivers.push_back(d);
    }
    std::sort(drivers.begin(), drivers.end(), [](const DriverInfo& a, const DriverInfo& b) {
        return toLower(a.name) < toLower(b.name);
    });
    return drivers;
}

static void printKnownCause(const DriverInfo& d) {
    wstring n = toLower(d.name);
    auto contains = [&](const wchar_t* x) { return n.find(x) != wstring::npos; };

    if (contains(L"nvlddmkm") || contains(L"dxgkrnl") || contains(L"dxgmms")) {
        std::wcout << L"    likely GPU/display path: long DPCs often come from NVIDIA scheduling, power state transitions, HAGS/MPO, overlays, or monitor refresh/VRR changes.\n";
    } else if (contains(L"wdf01000")) {
        std::wcout << L"    framework wrapper: WDF is usually the messenger; inspect USB, HID, audio, network, or vendor drivers active at the same time.\n";
    } else if (contains(L"storport") || contains(L"stornvme") || contains(L"iaStor") || contains(L"disk")) {
        std::wcout << L"    storage path: NVMe/SATA controller power saving, firmware, filter drivers, and heavy paging can show up here.\n";
    } else if (contains(L"ndis") || contains(L"tcpip") || contains(L"net") || contains(L"rt640") || contains(L"e2f") || contains(L"i225") || contains(L"wifi")) {
        std::wcout << L"    network path: adapter interrupt moderation, energy-efficient Ethernet, Wi-Fi roaming/power saving, or VPN/filter drivers are common causes.\n";
    } else if (contains(L"avg") || contains(L"avast") || contains(L"symantec") || contains(L"wdfilter")) {
        std::wcout << L"    security/filter path: real-time scanners and filesystem/network filters can add latency during I/O bursts.\n";
    } else if (contains(L"usb") || contains(L"xhci") || contains(L"hid") || contains(L"kbd") || contains(L"mou")) {
        std::wcout << L"    USB/HID path: selective suspend, hubs, polling devices, and vendor HID filters can trigger ISR/DPC bursts.\n";
    }
}

static void printDriverTable(const std::vector<DriverInfo>& drivers, bool onlyInteresting) {
    std::set<wstring> interesting = {
        L"nvlddmkm.sys", L"dxgkrnl.sys", L"dxgmms2.sys", L"wdf01000.sys", L"ntoskrnl.exe",
        L"storport.sys", L"stornvme.sys", L"ndis.sys", L"tcpip.sys", L"avgmonflt.sys",
        L"avgvmm.sys", L"avgsp.sys", L"usbport.sys", L"usbxhci.sys", L"hdaudbus.sys",
        L"portcls.sys", L"acpi.sys"
    };
    for (const auto& d : drivers) {
        wstring lower = toLower(d.name);
        bool show = !onlyInteresting || interesting.count(lower) ||
                    lower.find(L"nvidia") != wstring::npos ||
                    lower.find(L"avg") != wstring::npos ||
                    lower.find(L"net") != wstring::npos ||
                    lower.find(L"stor") != wstring::npos;
        if (!show) continue;
        std::wcout << L"\n  " << d.name;
        if (!d.description.empty()) std::wcout << L" - " << d.description;
        std::wcout << L"\n";
        if (!d.company.empty() || !d.version.empty()) {
            std::wcout << L"    " << d.company << L"  version " << d.version << L"\n";
        }
        if (!d.serviceName.empty()) {
            std::wcout << L"    service " << d.serviceName << L", start type " << d.serviceStart << L"\n";
        }
        if (!d.path.empty()) std::wcout << L"    " << d.path << L"\n";
        if (d.writeTime.dwLowDateTime || d.writeTime.dwHighDateTime) {
            std::wcout << L"    modified " << formatFileTime(d.writeTime) << L", size " << d.fileSize << L" bytes\n";
        }
        printKnownCause(d);
    }
}

static std::vector<CounterSample> queryProcessorCounters() {
    auto fn = getNtQuerySystemInformation();
    if (!fn) return {};
    DWORD cpuCount = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (!cpuCount) cpuCount = 64;
    std::vector<CounterSample> samples(cpuCount + 16);
    ULONG retLen = 0;
    NTSTATUS st = fn(8 /* SystemProcessorPerformanceInformation */,
                     samples.data(), (ULONG)(samples.size() * sizeof(CounterSample)), &retLen);
    if (st < 0 || retLen < sizeof(CounterSample)) return {};
    samples.resize(retLen / sizeof(CounterSample));
    return samples;
}

static void sampleCounters(int seconds) {
    std::wcout << L"\nSampling processor interrupt/DPC time for " << seconds << L" seconds...\n";
    auto a = queryProcessorCounters();
    if (a.empty()) {
        std::wcerr << L"Could not query processor performance counters.\n";
        return;
    }
    std::this_thread::sleep_for(std::chrono::seconds(seconds));
    auto b = queryProcessorCounters();
    if (b.size() != a.size()) {
        std::wcerr << L"Counter shape changed during sample.\n";
        return;
    }

    struct Row { size_t cpu; double dpcMsPerSec; double isrMsPerSec; double interruptsPerSec; };
    std::vector<Row> rows;
    double totalDpc = 0, totalIsr = 0, totalInts = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        double dpcMs = (double)(b[i].dpc.QuadPart - a[i].dpc.QuadPart) / 10000.0 / seconds;
        double isrMs = (double)(b[i].interrupt.QuadPart - a[i].interrupt.QuadPart) / 10000.0 / seconds;
        double ints = (double)(b[i].interruptCount - a[i].interruptCount) / seconds;
        totalDpc += dpcMs;
        totalIsr += isrMs;
        totalInts += ints;
        rows.push_back({i, dpcMs, isrMs, ints});
    }
    std::sort(rows.begin(), rows.end(), [](const Row& x, const Row& y) {
        return (x.dpcMsPerSec + x.isrMsPerSec) > (y.dpcMsPerSec + y.isrMsPerSec);
    });

    std::wcout << L"  Total DPC time:       " << std::fixed << std::setprecision(3) << totalDpc << L" ms/sec\n";
    std::wcout << L"  Total interrupt time: " << std::fixed << std::setprecision(3) << totalIsr << L" ms/sec\n";
    std::wcout << L"  Interrupt rate:       " << std::fixed << std::setprecision(1) << totalInts << L" interrupts/sec\n";
    std::wcout << L"\n  Hottest CPUs by interrupt+DPC time:\n";
    std::wcout << L"    CPU     DPC ms/s    ISR ms/s    interrupts/s\n";
    for (size_t i = 0; i < std::min<size_t>(rows.size(), 12); ++i) {
        std::wcout << L"    " << std::setw(3) << rows[i].cpu
                   << L"     " << std::setw(8) << std::fixed << std::setprecision(3) << rows[i].dpcMsPerSec
                   << L"    " << std::setw(8) << rows[i].isrMsPerSec
                   << L"    " << std::setw(12) << std::fixed << std::setprecision(1) << rows[i].interruptsPerSec
                   << L"\n";
    }
}

static wstring getComputerInfoLine() {
    OSVERSIONINFOEXW os{};
    os.dwOSVersionInfoSize = sizeof(os);
    typedef LONG (WINAPI *RtlGetVersionFn)(PRTL_OSVERSIONINFOW);
    RtlGetVersionFn rtl = nullptr;
    FARPROC rtlProc = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    static_assert(sizeof(rtl) == sizeof(rtlProc), "unexpected function pointer size");
    std::memcpy(&rtl, &rtlProc, sizeof(rtl));
    if (rtl) rtl((PRTL_OSVERSIONINFOW)&os);
    SYSTEM_INFO si{};
    GetNativeSystemInfo(&si);
    MEMORYSTATUSEX mem{};
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    std::wstringstream ss;
    ss << (os.dwBuildNumber >= 22000 ? L"Windows 11" : L"Windows")
       << L" (" << os.dwMajorVersion << L"." << os.dwMinorVersion << L"." << os.dwBuildNumber << L")"
       << L", " << si.dwNumberOfProcessors << L" logical CPUs"
       << L", " << (mem.ullTotalPhys / (1024ull * 1024ull * 1024ull)) << L" GiB RAM";
    return ss.str();
}

static void inspectPowerAndGraphics() {
    std::wcout << L"\nCurrent latency-relevant settings:\n";

    auto sr = readRegDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile",
        L"SystemResponsiveness");
    std::wcout << L"  MMCSS SystemResponsiveness: " << (sr ? std::to_wstring(*sr) : L"<missing>") << L"\n";

    auto nti = readRegDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile",
        L"NetworkThrottlingIndex");
    if (nti) {
        std::wcout << L"  NetworkThrottlingIndex: 0x" << std::hex << *nti << std::dec << L"\n";
    } else {
        std::wcout << L"  NetworkThrottlingIndex: <missing>\n";
    }

    auto pto = readRegDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Power\\PowerThrottling",
        L"PowerThrottlingOff");
    std::wcout << L"  PowerThrottlingOff: " << (pto ? std::to_wstring(*pto) : L"<missing>") << L"\n";

    auto hwsch = readRegDword(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers",
        L"HwSchMode");
    std::wcout << L"  Hardware accelerated GPU scheduling HwSchMode: " << (hwsch ? std::to_wstring(*hwsch) : L"<default>") << L"\n";

    auto mpo = readRegDword(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\Dwm",
        L"OverlayTestMode");
    std::wcout << L"  MPO OverlayTestMode: " << (mpo ? std::to_wstring(*mpo) : L"<default>") << L"\n";
}

static wstring timestampForPath() {
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm{};
    localtime_s(&tm, &now);
    std::wstringstream ss;
    ss << std::put_time(&tm, L"%Y%m%d-%H%M%S");
    return ss.str();
}

static bool exportRegistry(const fs::path& backupDir, bool dryRun) {
    fs::create_directories(backupDir);
    std::vector<std::pair<wstring, wstring>> exports = {
        {L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile", L"multimedia-systemprofile.reg"},
        {L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power", L"power-control.reg"},
        {L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers", L"graphicsdrivers.reg"},
        {L"HKLM\\SOFTWARE\\Microsoft\\Windows\\Dwm", L"dwm.reg"},
        {L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}", L"network-adapters.reg"}
    };
    bool ok = true;
    for (auto& e : exports) {
        wstring cmd = L"reg.exe export \"" + e.first + L"\" \"" + (backupDir / e.second).wstring() + L"\" /y";
        ok = runProcess(cmd, dryRun) && ok;
    }
    return ok;
}

static bool applyPowerCfgLatency(bool dryRun) {
    std::wcout << L"\nPower policy changes (AC and DC for consistency):\n";
    std::vector<wstring> cmds = {
        // PCI Express / Link State Power Management = Off
        L"powercfg.exe /setacvalueindex SCHEME_CURRENT 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0",
        L"powercfg.exe /setdcvalueindex SCHEME_CURRENT 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0",
        // USB settings / USB selective suspend = Disabled
        L"powercfg.exe /setacvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0",
        L"powercfg.exe /setdcvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0",
        // Wireless adapter power saving = Maximum Performance
        L"powercfg.exe /setacvalueindex SCHEME_CURRENT 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0",
        L"powercfg.exe /setdcvalueindex SCHEME_CURRENT 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0",
        L"powercfg.exe /setactive SCHEME_CURRENT"
    };
    bool ok = true;
    for (const auto& cmd : cmds) ok = runProcess(cmd, dryRun) && ok;
    return ok;
}

static bool applyNetworkAdapterPowerTweaks(BackupWriter& backup, bool dryRun) {
    std::wcout << L"\nNetwork adapter power-saving registry changes:\n";
    const wstring cls = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}";
    HKEY hClass{};
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, cls.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hClass) != ERROR_SUCCESS) {
        std::wcerr << L"  Could not open network adapter class key.\n";
        return false;
    }

    std::vector<wstring> names = {
        L"*EEE", L"EEE", L"EnableGreenEthernet", L"GreenEthernet", L"AdvancedEEE",
        L"AutoPowerSaveModeEnabled", L"AutoDisableGigabit", L"ReduceSpeedOnPowerDown",
        L"PowerSavingMode", L"EnablePME", L"ULPMode", L"SelectiveSuspend",
        L"DeviceSleepOnDisconnect"
    };

    bool ok = true;
    for (DWORD i = 0;; ++i) {
        wchar_t sub[256]{};
        DWORD subLen = 256;
        LONG er = RegEnumKeyExW(hClass, i, sub, &subLen, nullptr, nullptr, nullptr, nullptr);
        if (er == ERROR_NO_MORE_ITEMS) break;
        if (er != ERROR_SUCCESS) continue;
        if (wcslen(sub) != 4 || !iswdigit(sub[0])) continue;

        wstring subkey = cls + L"\\" + sub;
        wstring desc = readRegString(HKEY_LOCAL_MACHINE, subkey, L"DriverDesc");
        if (desc.empty()) continue;
        std::wcout << L"  Adapter " << sub << L": " << desc << L"\n";

        for (const auto& name : names) {
            HKEY h{};
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS) continue;
            DWORD type = 0, cb = 0;
            LONG rc = RegQueryValueExW(h, name.c_str(), nullptr, &type, nullptr, &cb);
            RegCloseKey(h);
            if (rc != ERROR_SUCCESS) continue;

            if (type == REG_DWORD) {
                ok = setRegDword(backup, HKEY_LOCAL_MACHINE, subkey, name, 0, dryRun) && ok;
            } else if (type == REG_SZ) {
                ok = setRegString(backup, HKEY_LOCAL_MACHINE, subkey, name, L"0", dryRun) && ok;
            }
        }
    }
    RegCloseKey(hClass);
    return ok;
}

static bool applyRegistryLatencyTweaks(BackupWriter& backup, bool dryRun) {
    std::wcout << L"\nCore registry latency changes:\n";
    bool ok = true;
    ok = setRegDword(backup, HKEY_LOCAL_MACHINE,
                     L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile",
                     L"SystemResponsiveness", 0, dryRun) && ok;
    ok = setRegDword(backup, HKEY_LOCAL_MACHINE,
                     L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Multimedia\\SystemProfile",
                     L"NetworkThrottlingIndex", 0xffffffff, dryRun) && ok;
    ok = setRegDword(backup, HKEY_LOCAL_MACHINE,
                     L"SYSTEM\\CurrentControlSet\\Control\\Power\\PowerThrottling",
                     L"PowerThrottlingOff", 1, dryRun) && ok;
    return ok;
}

static bool applyExpertTweaks(BackupWriter& backup, bool dryRun, bool timerTweaks, bool disableMpo, std::optional<DWORD> hwSchMode) {
    bool ok = true;
    if (timerTweaks) {
        std::wcout << L"\nExpert boot timer changes (reboot required):\n";
        ok = runProcess(L"bcdedit.exe /set disabledynamictick yes", dryRun) && ok;
        // Intentionally do not force HPET/useplatformclock. On modern systems that often makes latency worse.
    }
    if (disableMpo) {
        std::wcout << L"\nExpert NVIDIA/MPO workaround:\n";
        ok = setRegDword(backup, HKEY_LOCAL_MACHINE,
                         L"SOFTWARE\\Microsoft\\Windows\\Dwm",
                         L"OverlayTestMode", 5, dryRun) && ok;
    }
    if (hwSchMode) {
        std::wcout << L"\nExpert HAGS setting:\n";
        ok = setRegDword(backup, HKEY_LOCAL_MACHINE,
                         L"SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers",
                         L"HwSchMode", *hwSchMode, dryRun) && ok;
    }
    return ok;
}

static void writeReport(const fs::path& path, const std::vector<DriverInfo>& drivers, int seconds) {
    std::wofstream out(path);
    out << L"DPC Latency Doctor report\n";
    out << L"System: " << getComputerInfoLine() << L"\n";
    out << L"Sample seconds: " << seconds << L"\n\n";
    out << L"Loaded drivers\n";
    out << L"Name\tCompany\tDescription\tVersion\tService\tStartType\tModified\tPath\n";
    for (const auto& d : drivers) {
        out << d.name << L"\t" << d.company << L"\t" << d.description << L"\t" << d.version
            << L"\t" << d.serviceName << L"\t" << d.serviceStart << L"\t"
            << formatFileTime(d.writeTime) << L"\t" << d.path << L"\n";
    }
}

static int cmdScan(const std::vector<wstring>& args) {
    int seconds = 30;
    bool allDrivers = false;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == L"--all-drivers") allDrivers = true;
        else if (args[i] == L"--seconds" && i + 1 < args.size()) seconds = std::max(1, _wtoi(args[++i].c_str()));
        else if (args[i].find_first_not_of(L"0123456789") == wstring::npos) seconds = std::max(1, _wtoi(args[i].c_str()));
    }

    std::wcout << L"DPC Latency Doctor scan by Iman Mirbioki - iman@spacechain.org\n";
    std::wcout << L"  " << getComputerInfoLine() << L"\n";
    std::wcout << L"  Admin: " << (isAdmin() ? L"yes" : L"no") << L"\n";
    inspectPowerAndGraphics();
    auto drivers = enumerateLoadedDrivers();
    std::wcout << L"\nLoaded driver analysis:";
    printDriverTable(drivers, !allDrivers);
    sampleCounters(seconds);

    fs::path report = fs::current_path() / (L"latencydoctor-report-" + timestampForPath() + L".tsv");
    writeReport(report, drivers, seconds);
    std::wcout << L"\nReport written: " << report.wstring() << L"\n";
    std::wcout << L"\nNext steps:\n";
    std::wcout << L"  1. If nvlddmkm/dxgkrnl are hot in LatencyMon, run: latencydoctor optimize --apply --disable-mpo\n";
    std::wcout << L"  2. If network/storage devices are hot, the default optimize profile disables their common power-saving paths.\n";
    std::wcout << L"  3. Use trace 60 to collect a WPR ETL for WPA when per-driver attribution is still unclear.\n";
    return 0;
}

static int cmdTrace(const std::vector<wstring>& args) {
    int seconds = 60;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == L"--seconds" && i + 1 < args.size()) seconds = std::max(5, _wtoi(args[++i].c_str()));
        else if (args[i].find_first_not_of(L"0123456789") == wstring::npos) seconds = std::max(5, _wtoi(args[i].c_str()));
    }
    wstring wpr = system32Path(L"wpr.exe");
    if (!fileExists(wpr)) {
        std::wcerr << L"wpr.exe was not found. Install Windows Performance Toolkit for ETW tracing.\n";
        return 2;
    }
    fs::path out = fs::current_path() / (L"latencydoctor-trace-" + timestampForPath() + L".etl");
    std::wcout << L"Starting WPR CPU/GPU/disk trace for " << seconds << L" seconds. Reproduce the stutter now.\n";
    bool ok = runProcess(L"\"" + wpr + L"\" -start CPU -start DiskIO -start GPU -filemode", false);
    if (!ok) {
        std::wcerr << L"Could not start WPR. Try running this command from an elevated console.\n";
        return 3;
    }
    std::this_thread::sleep_for(std::chrono::seconds(seconds));
    ok = runProcess(L"\"" + wpr + L"\" -stop \"" + out.wstring() + L"\"", false);
    if (!ok) return 4;
    std::wcout << L"Trace written: " << out.wstring() << L"\n";
    std::wcout << L"Open it in Windows Performance Analyzer and inspect DPC/ISR Duration by Module, Function, and CPU.\n";
    return 0;
}

static int cmdOptimize(const std::vector<wstring>& args) {
    bool apply = false;
    bool network = true;
    bool timerTweaks = false;
    bool disableMpo = false;
    std::optional<DWORD> hwSchMode;

    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == L"--apply") apply = true;
        else if (args[i] == L"--no-network") network = false;
        else if (args[i] == L"--timer-tweaks") timerTweaks = true;
        else if (args[i] == L"--disable-mpo") disableMpo = true;
        else if (args[i] == L"--hags-off") hwSchMode = 1;
        else if (args[i] == L"--hags-on") hwSchMode = 2;
    }

    bool dryRun = !apply;
    if (!dryRun && !isAdmin()) {
        std::wcerr << L"Optimization needs an elevated console. Run with gsudo, for example:\n";
        std::wcerr << L"  gsudo .\\latencydoctor.exe optimize --apply\n";
        return 5;
    }

    fs::path backupDir = fs::current_path() / (L"latencydoctor-backup-" + timestampForPath());
    BackupWriter backup(backupDir, !dryRun);
    backup.line(L"Optimization started. DryRun=" + wstring(dryRun ? L"true" : L"false"));

    std::wcout << L"DPC Latency Doctor optimize " << (dryRun ? L"(preview only)" : L"(APPLY)") << L"\n";
    if (!dryRun) std::wcout << L"Backup directory: " << backupDir.wstring() << L"\n";
    if (!dryRun) exportRegistry(backupDir, false);

    bool ok = true;
    ok = applyRegistryLatencyTweaks(backup, dryRun) && ok;
    ok = applyPowerCfgLatency(dryRun) && ok;
    if (network) ok = applyNetworkAdapterPowerTweaks(backup, dryRun) && ok;
    ok = applyExpertTweaks(backup, dryRun, timerTweaks, disableMpo, hwSchMode) && ok;

    std::wcout << L"\nDone. " << (dryRun ? L"No changes were written." : L"Reboot is recommended before retesting LatencyMon.") << L"\n";
    if (dryRun) {
        std::wcout << L"To apply: latencydoctor optimize --apply";
        if (disableMpo) std::wcout << L" --disable-mpo";
        if (timerTweaks) std::wcout << L" --timer-tweaks";
        if (hwSchMode && *hwSchMode == 1) std::wcout << L" --hags-off";
        if (hwSchMode && *hwSchMode == 2) std::wcout << L" --hags-on";
        std::wcout << L"\n";
    } else {
        std::wcout << L"Backups/logs: " << backupDir.wstring() << L"\n";
    }
    return ok ? 0 : 1;
}

static int cmdRestore(const std::vector<wstring>& args) {
    if (args.empty()) {
        std::wcerr << L"restore requires a backup directory.\n";
        return 2;
    }
    if (!isAdmin()) {
        std::wcerr << L"Restore needs an elevated console. Run with gsudo.\n";
        return 5;
    }
    fs::path dir(args[0]);
    if (!fs::is_directory(dir)) {
        std::wcerr << L"Not a directory: " << dir.wstring() << L"\n";
        return 2;
    }
    bool ok = true;
    for (auto& p : fs::directory_iterator(dir)) {
        if (p.path().extension() == L".reg") {
            ok = runProcess(L"reg.exe import \"" + p.path().wstring() + L"\"", false) && ok;
        }
    }
    ok = restoreChangeLog(dir / L"changes.log") && ok;
    std::wcout << L"Restore " << (ok ? L"finished." : L"finished with errors.") << L" Reboot before retesting.\n";
    return ok ? 0 : 1;
}

static void usage() {
    std::wcout << L"DPC Latency Doctor for Windows 11 x64 by Iman Mirbioki - iman@spacechain.org\n\n";
    std::wcout << L"Commands:\n";
    std::wcout << L"  latencydoctor scan [seconds] [--all-drivers]\n";
    std::wcout << L"      Analyze loaded drivers, relevant settings, and CPU interrupt/DPC time.\n\n";
    std::wcout << L"  latencydoctor trace [seconds]\n";
    std::wcout << L"      Collect a WPR ETW trace for deep DPC/ISR attribution in WPA.\n\n";
    std::wcout << L"  latencydoctor optimize [--apply] [--disable-mpo] [--hags-off|--hags-on] [--timer-tweaks] [--no-network]\n";
    std::wcout << L"      Preview or apply reversible latency-focused tuning. Without --apply this is a dry run.\n\n";
    std::wcout << L"  latencydoctor restore <latencydoctor-backup-dir>\n";
    std::wcout << L"      Import .reg backups created by optimize.\n\n";
    std::wcout << L"Examples:\n";
    std::wcout << L"  .\\latencydoctor.exe scan 60\n";
    std::wcout << L"  gsudo .\\latencydoctor.exe optimize --apply --disable-mpo\n";
    std::wcout << L"  gsudo .\\latencydoctor.exe optimize --apply --timer-tweaks\n";
}

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    std::vector<wstring> args;
    for (int i = 1; i < argc; ++i) args.push_back(argv[i]);
    if (args.empty() || args[0] == L"-h" || args[0] == L"--help" || args[0] == L"help") {
        usage();
        return 0;
    }
    wstring cmd = toLower(args[0]);
    std::vector<wstring> rest(args.begin() + 1, args.end());
    try {
        if (cmd == L"scan") return cmdScan(rest);
        if (cmd == L"trace") return cmdTrace(rest);
        if (cmd == L"optimize") return cmdOptimize(rest);
        if (cmd == L"restore") return cmdRestore(rest);
        usage();
        return 2;
    } catch (const std::exception& ex) {
        std::cerr << "Fatal error: " << ex.what() << "\n";
        return 99;
    }
}
