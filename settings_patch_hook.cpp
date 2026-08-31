#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "settings_patch_hook.h"
#include "local_crypto.hpp"

#include <safetyhook.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cwchar>
#include <mutex>
#include <string>
#include <vector>

namespace {

SafetyHookInline g_create_file_hook{};
std::atomic_bool g_installed{false};
std::mutex g_install_mutex;
std::mutex g_settings_mutex;
thread_local bool g_inside_create_file_hook = false;

constexpr DWORD kIoChunkSize = 64 * 1024;

std::wstring normalize_path_for_match(LPCWSTR file_name)
{
    if (file_name == nullptr || *file_name == L'\0') {
        return {};
    }

    DWORD required = GetFullPathNameW(file_name, 0, nullptr, nullptr);
    if (required == 0) {
        return {};
    }

    std::vector<wchar_t> buffer(static_cast<std::size_t>(required) + 1);
    DWORD length = GetFullPathNameW(
        file_name,
        static_cast<DWORD>(buffer.size()),
        buffer.data(),
        nullptr
    );

    if (length == 0 || length >= buffer.size()) {
        return {};
    }

    std::wstring path(buffer.data(), length);

    for (wchar_t& ch : path) {
        if (ch == L'/') {
            ch = L'\\';
        }
    }

    if (path.rfind(L"\\\\?\\", 0) == 0) {
        path.erase(0, 4);
    }

    return path;
}

bool is_utools_settings_path(const std::wstring& path)
{
    static constexpr wchar_t kSuffix[] =
        L"\\AppData\\Roaming\\uTools\\settings";

    constexpr std::size_t kSuffixLen =
        (sizeof(kSuffix) / sizeof(kSuffix[0])) - 1;

    if (path.size() < kSuffixLen) {
        return false;
    }

    const wchar_t* tail = path.c_str() + (path.size() - kSuffixLen);
    return _wcsicmp(tail, kSuffix) == 0;
}

HANDLE original_create_file_w(
    LPCWSTR file_name,
    DWORD desired_access,
    DWORD share_mode,
    LPSECURITY_ATTRIBUTES security_attributes,
    DWORD creation_disposition,
    DWORD flags_and_attributes,
    HANDLE template_file)
{
    return g_create_file_hook.call<HANDLE>(
        file_name,
        desired_access,
        share_mode,
        security_attributes,
        creation_disposition,
        flags_and_attributes,
        template_file
    );
}

bool read_all(HANDLE file, std::string& output)
{
    LARGE_INTEGER zero{};
    if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN)) {
        return false;
    }

    output.clear();
    std::vector<char> buffer(kIoChunkSize);

    for (;;) {
        DWORD bytes_read = 0;
        if (!ReadFile(
                file,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytes_read,
                nullptr)) {
            return false;
        }

        if (bytes_read == 0) {
            return true;
        }

        output.append(buffer.data(), bytes_read);
    }
}

bool write_all(HANDLE file, const std::string& data)
{
    std::size_t offset = 0;

    while (offset < data.size()) {
        const DWORD chunk = static_cast<DWORD>(
            (std::min)(
                data.size() - offset,
                static_cast<std::size_t>(kIoChunkSize)
            )
        );

        DWORD written = 0;
        if (!WriteFile(
                file,
                data.data() + offset,
                chunk,
                &written,
                nullptr)) {
            return false;
        }

        if (written == 0) {
            SetLastError(ERROR_WRITE_FAULT);
            return false;
        }

        offset += written;
    }

    return true;
}

void process_settings_file(const std::wstring& settings_path)
{
    std::lock_guard<std::mutex> lock(g_settings_mutex);

    HANDLE file = original_create_file_w(
        settings_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (file == INVALID_HANDLE_VALUE) {
        return;
    }

    std::string file_text;
    if (!read_all(file, file_text)) {
        CloseHandle(file);
        return;
    }

    const bool has_utf8_bom =
        file_text.size() >= 3 &&
        static_cast<unsigned char>(file_text[0]) == 0xEF &&
        static_cast<unsigned char>(file_text[1]) == 0xBB &&
        static_cast<unsigned char>(file_text[2]) == 0xBF;

    std::string json_text = has_utf8_bom
        ? file_text.substr(3)
        : file_text;

    const bool had_line_break =
        json_text.find('\n') != std::string::npos ||
        json_text.find('\r') != std::string::npos;

    const bool had_trailing_newline =
        !json_text.empty() &&
        (json_text.back() == '\n' || json_text.back() == '\r');

    nlohmann::ordered_json root = nlohmann::ordered_json::parse(
        json_text,
        nullptr,
        false
    );

    if (root.is_discarded() || !root.is_object()) {
        CloseHandle(file);
        return;
    }

    if (!root.contains("account")) {
        CloseHandle(file);
        return;
    }

    nlohmann::ordered_json& account = root["account"];
    if (!account.is_object()) {
        CloseHandle(file);
        return;
    }

    std::string info_text;
    if (account.contains("info")) {
        const nlohmann::ordered_json& info = account["info"];
        info_text = info.is_string()
            ? info.get<std::string>()
            : info.dump();
    }

	std::string decrypted = localDecrypt(info_text);
	nlohmann::ordered_json info_json = nlohmann::ordered_json::parse(decrypted);

	if (info_json.value("type", 0) != 1) {
		info_json["type"] = 1;
		info_json["expired_at"] = 4102415999ULL;

		account["info"] = localEncrypt(info_json.dump());
	}

    std::string updated_text = root.dump(had_line_break ? 4 : -1);
    if (had_trailing_newline) {
        updated_text.push_back('\n');
    }
    if (has_utf8_bom) {
        updated_text.insert(0, "\xEF\xBB\xBF");
    }

    LARGE_INTEGER zero{};
    bool write_ok = SetFilePointerEx(file, zero, nullptr, FILE_BEGIN) != FALSE;
    if (write_ok) {
        write_ok = write_all(file, updated_text);
    }
    if (write_ok) {
        write_ok = SetEndOfFile(file) != FALSE;
    }
    if (write_ok) {
        write_ok = FlushFileBuffers(file) != FALSE;
    }

    if (!write_ok) {
    }

    CloseHandle(file);
}

HANDLE WINAPI hooked_create_file_w(
    LPCWSTR file_name,
    DWORD desired_access,
    DWORD share_mode,
    LPSECURITY_ATTRIBUTES security_attributes,
    DWORD creation_disposition,
    DWORD flags_and_attributes,
    HANDLE template_file)
{
    if (g_inside_create_file_hook) {
        return original_create_file_w(
            file_name,
            desired_access,
            share_mode,
            security_attributes,
            creation_disposition,
            flags_and_attributes,
            template_file
        );
    }

    struct ReentryGuard {
        ReentryGuard() { g_inside_create_file_hook = true; }
        ~ReentryGuard() { g_inside_create_file_hook = false; }
    } guard;

    const std::wstring normalized = normalize_path_for_match(file_name);

    if (!normalized.empty() && is_utools_settings_path(normalized)) {
        process_settings_file(normalized);
    }

    return original_create_file_w(
        file_name,
        desired_access,
        share_mode,
        security_attributes,
        creation_disposition,
        flags_and_attributes,
        template_file
    );
}

void* resolve_create_file_w()
{
    HMODULE module = GetModuleHandleW(L"KernelBase.dll");
    if (module == nullptr) {
        return nullptr;
    }

    FARPROC proc = GetProcAddress(module, "CreateFileW");
    return reinterpret_cast<void*>(proc);
}

} // namespace

extern "C" int settings_patch_hook_install(void)
{
    std::lock_guard<std::mutex> lock(g_install_mutex);

    if (g_installed.load(std::memory_order_acquire)) {
        return 1;
    }

    void* create_file_w = resolve_create_file_w();
    if (create_file_w == nullptr) {
        return 0;
    }

    g_create_file_hook = safetyhook::create_inline(
        create_file_w,
        reinterpret_cast<void*>(&hooked_create_file_w)
    );

    if (!g_create_file_hook) {
        return 0;
    }

    g_installed.store(true, std::memory_order_release);


    return 1;
}

extern "C" int settings_patch_hook_uninstall(void)
{
    std::lock_guard<std::mutex> lock(g_install_mutex);

    if (!g_installed.load(std::memory_order_acquire)) {
        return 1;
    }

    g_create_file_hook = {};
    g_installed.store(false, std::memory_order_release);


    return 1;
}

extern "C" int settings_patch_hook_is_installed(void)
{
    return g_installed.load(std::memory_order_acquire) ? 1 : 0;
}
