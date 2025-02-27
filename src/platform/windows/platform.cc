// Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

#include "platform.h"

#include "core/logger.h"
#include "platform/platform.h"
#include "util/fmt.h"
#include "util/helpers.h"

#include <memory>
#include <utility>

#include <pathfind.hpp>

#include <ztd/out_ptr/out_ptr.hpp>

using namespace zeek::agent;
using namespace zeek::agent::platform::windows;
using namespace ztd::out_ptr;

void platform::init(const Configuration& cfg) {}

void platform::done() { windows::WMIManager::Get().Shutdown(); }

std::string platform::name() { return "Windows"; }

std::optional<filesystem::path> platform::configurationFile() {
    filesystem::path dir;
    if ( auto programdata = platform::getenv("PROGRAMDATA") )
        dir = filesystem::path(*programdata);
    else
        dir = filesystem::path("c:") / "ProgramData";

    return dir / "ZeekAgent" / "zeek-agent.cfg";
}

std::optional<filesystem::path> platform::dataDirectory() {
    filesystem::path dir;
    if ( auto programdata = platform::getenv("PROGRAMDATA") )
        dir = filesystem::path(*programdata);
    else
        dir = filesystem::path("c:") / "ProgramData";

    dir = dir / "ZeekAgent" / ".cache";

    std::error_code ec;
    filesystem::create_directories(dir, ec);
    if ( ec )
        throw FatalError(frmt("cannot create path '{}'", dir.string()));

    return dir;
}

bool platform::isTTY() { return true; }

Result<Nothing> platform::setenv(const char* name, const char* value, int overwrite) {
    if ( overwrite == 0 ) {
        // It doesn't matter what the length is set to here. The array is just being used
        // to check for existence.
        char existing[10];
        int ret = GetEnvironmentVariableA(name, existing, 10);

        // Anything non-zero means that a length of the existing value was returned and
        // that the variable exists.
        if ( ret != 0 )
            return Nothing();
    }

    if ( ! SetEnvironmentVariableA(name, value) )
        return result::Error("failed to set environment variable");

    return Nothing();
}

extern std::optional<std::string> platform::getenv(const std::string& name) {
    constexpr DWORD max_buffer_size = 32768; // From GetEnvironmentVariable's documentation
    char* buf = NULL;
    char* tmp = NULL;
    DWORD ret = 1;
    DWORD requested_size = 0;

    while ( true ) {
        tmp = reinterpret_cast<char*>(realloc(NULL, ret));
        if ( ! tmp ) {
            free(buf);
            return std::nullopt;
        }

        buf = tmp;
        requested_size = ret;

        ret = GetEnvironmentVariableA(name.c_str(), buf, requested_size);
        if ( ret == 0 ) {
            free(buf);
            return std::nullopt;
        }

        // If ret is less than the size, then we got a good value and can just return.
        // Otherwise we need to expand the buffer and try again.
        if ( ret < requested_size ) {
            std::string value{buf};
            free(buf);
            return value;
        }
    }
}

struct SIDFreer {
    void operator()(PSID sid) { FreeSid(sid); }
};
using SIDPtr = std::unique_ptr<std::remove_pointer<PSID>::type, SIDFreer>;

bool platform::runningAsAdmin() {
    // Adapted from
    // https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-checktokenmembership
    BOOL is_member;
    SIDPtr administrator_group;
    SID_IDENTIFIER_AUTHORITY auth_nt = SECURITY_NT_AUTHORITY;
    is_member = AllocateAndInitializeSid(&auth_nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0,
                                         0, 0, out_ptr<PSID>(administrator_group));

    if ( ! is_member )
        return false;

    if ( ! CheckTokenMembership(nullptr, administrator_group.get(), &is_member) )
        is_member = false;

    return is_member;
}

void platform::initializeOptions(Options* options) {
    // Nothing to do.
}

std::optional<std::string> platform::retrieveConfigurationOption(const std::string& path) {
    // Nothing to do.
    return {};
}

WMIManager& WMIManager::Get() {
    static WMIManager wmi;
    return wmi;
}

WMIManager::WMIManager() {
    HRESULT res = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if ( FAILED(res) )
        return;

    res = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL,
                               EOAC_NONE, 0);
    if ( FAILED(res) )
        return;

    IWbemLocatorPtr loc{nullptr};
    res = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator,
                           out_ptr<IWbemLocatorPtr::pointer>(loc));
    if ( FAILED(res) || ! loc )
        return;

    IWbemServicesPtr cimv2{nullptr};
    cimv2_root = makeBstr(L"root\\CIMV2");
    res = loc->ConnectServer(cimv2_root.get(), NULL, NULL, NULL, WBEM_FLAG_CONNECT_USE_MAX_WAIT, NULL, NULL,
                             out_ptr<IWbemServicesPtr::pointer>(cimv2));
    if ( FAILED(res) || ! cimv2 )
        return;

    wql = makeBstr(L"WQL");

    locator = std::move(loc);
    cimv2_service = std::move(cimv2);
}

WMIManager::~WMIManager() { Shutdown(); }

void WMIManager::Shutdown() {
    cimv2_service.reset();
    locator.reset();
}

WMIManager::IEnumWbemClassObjectPtr WMIManager::GetQueryEnumerator(const std::wstring& query) const {
    auto b_query = makeBstr(query);
    IEnumWbemClassObjectPtr enumerator = nullptr;
    HRESULT res = cimv2_service->ExecQuery(wql.get(), b_query.get(), WBEM_FLAG_FORWARD_ONLY, NULL,
                                           out_ptr<IEnumWbemClassObject*>(enumerator));
    if ( FAILED(res) ) {
        IErrorInfo* error;
        auto result = GetErrorInfo(0, &error);
        if ( SUCCEEDED(result) && error ) {
            BSTR description = NULL;
            result = error->GetDescription(&description);
            if ( SUCCEEDED(result) && description ) {
                ZEEK_AGENT_DEBUG("WMIManager", "Failed to fetch WMI data: {}", narrowWstring(description));
            }
        }

        return nullptr;
    }

    return std::move(enumerator);
}

std::string WMIManager::GetOSVersion() const {
    std::wstring version;

    IEnumWbemClassObjectPtr enumerator = GetQueryEnumerator(L"SELECT * from Win32_OperatingSystem");
    if ( ! enumerator )
        return "";

    HRESULT res;
    IWbemClassObjectPtr obj = nullptr;
    int num_elems = 0;
    while ( (res = enumerator->Next(WBEM_INFINITE, 1, out_ptr<IWbemClassObjectPtr::pointer>(obj),
                                    reinterpret_cast<ULONG*>(&num_elems))) != WBEM_S_FALSE ) {
        if ( FAILED(res) )
            break;

        VARIANT var;
        VariantInit(&var);
        if ( SUCCEEDED(obj->Get(L"Caption", 0, &var, NULL, NULL)) && var.vt == VT_BSTR )
            version += var.bstrVal;

        if ( ! version.empty() )
            version += L" ";

        VariantInit(&var);
        if ( SUCCEEDED(obj->Get(L"Version", 0, &var, NULL, NULL)) && var.vt == VT_BSTR )
            version += var.bstrVal;
    }

    return narrowWstring(version);
}

std::vector<AccountInfo> WMIManager::GetUserData() const {
    std::vector<AccountInfo> out;

    GetUserData(L"Win32_UserAccount", false, out);
    GetUserData(L"Win32_SystemAccount", true, out);

    return out;
}

void WMIManager::GetUserData(const std::wstring& key, bool system_accounts, std::vector<AccountInfo>& out) const {
    std::wstring query = L"SELECT Caption, Name, SID from " + key;
    auto enumerator = GetQueryEnumerator(query);
    if ( ! enumerator )
        return;

    HRESULT res;
    IWbemClassObjectPtr obj = nullptr;
    int num_elems = 0;
    while ( (res = enumerator->Next(WBEM_INFINITE, 1, out_ptr<IWbemClassObject*>(obj),
                                    reinterpret_cast<ULONG*>(&num_elems))) != WBEM_S_FALSE ) {
        if ( FAILED(res) )
            break;

        AccountInfo info;
        info.is_system_acct = system_accounts;

        // I'm not sure the repeated calls to VariantClear() are needed below but I can't find any
        // documentation for repeatedly using VARIANT object. I assume that as long as Init is
        // because it's used and Clear is called afterwards, we're fine here.

        VARIANT var;
        VariantInit(&var);
        if ( SUCCEEDED(obj->Get(L"Caption", 0, &var, NULL, NULL)) && var.vt == VT_BSTR )
            info.name = narrowWstring(var.bstrVal);
        VariantClear(&var);

        VariantInit(&var);
        if ( SUCCEEDED(obj->Get(L"Name", 0, &var, NULL, NULL)) && var.vt == VT_BSTR )
            info.full_name = narrowWstring(var.bstrVal);
        VariantClear(&var);

        VariantInit(&var);
        if ( SUCCEEDED(obj->Get(L"SID", 0, &var, NULL, NULL)) && var.vt == VT_BSTR )
            info.sid = narrowWstring(var.bstrVal);
        VariantClear(&var);

        std::wstring path_query = frmt(L"SELECT LocalPath from Win32_UserProfile WHERE SID = \"{}\"", var.bstrVal);

        if ( auto user_enum = GetQueryEnumerator(path_query) ) {
            IWbemClassObjectPtr user_obj = nullptr;
            int num_user_elems = 0;
            if ( user_enum->Next(WBEM_INFINITE, 1, out_ptr<IWbemClassObject*>(user_obj),
                                 reinterpret_cast<ULONG*>(&num_elems)) != WBEM_S_FALSE ) {
                VariantInit(&var);
                if ( SUCCEEDED(user_obj->Get(L"LocalPath", 0, &var, NULL, NULL)) && var.vt == VT_BSTR )
                    info.home_directory = narrowWstring(var.bstrVal);
                VariantClear(&var);
            }
        }

        // Adapted from
        // https://devblogs.microsoft.com/scripting/how-can-i-determine-if-the-local-administrator-account-has-been-renamed-on-a-computer/
        if ( startsWith(info.sid, "S-1-5") && endsWith(info.sid, "-500") )
            info.is_admin = true;

        out.push_back(std::move(info));
    }
}
