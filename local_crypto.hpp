#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <wincrypt.h>

#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>

extern "C"
{
#include "3rdparty/monocypher.h"
}

#if defined(_MSC_VER)
#pragma comment(lib, "advapi32.lib")
#endif

namespace utools_local_crypto_detail
{
inline constexpr char KEY_PREFIX[] = "H22`OB~6i{A{TXqIqPEg";
inline constexpr char KEY_SUFFIX[] = "|Wea6ywQQ`1q>_QyY2f1";
inline constexpr char NONCE[]      = "$}ddA+eul*(&JdhElqXYl9]6";

inline std::string getWindowsError(DWORD error)
{
    LPSTR buffer = nullptr;

    const DWORD size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        reinterpret_cast<LPSTR>(&buffer),
        0,
        nullptr);

    if (size != 0 && buffer != nullptr)
    {
        std::string result(buffer, size);
        LocalFree(buffer);
        return result;
    }

    return "Windows error " + std::to_string(error);
}

inline std::string getMachineGuid()
{
    HKEY hKey = nullptr;

    LONG result = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Cryptography",
        0,
        KEY_READ | KEY_WOW64_64KEY,
        &hKey);

    if (result != ERROR_SUCCESS)
    {
        throw std::runtime_error(
            "RegOpenKeyExA failed: " + getWindowsError(result));
    }

    DWORD type = 0;
    DWORD size = 0;

    result = RegQueryValueExA(
        hKey,
        "MachineGuid",
        nullptr,
        &type,
        nullptr,
        &size);

    if (result != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        throw std::runtime_error(
            "Cannot query MachineGuid size: " + getWindowsError(result));
    }

    if (type != REG_SZ && type != REG_EXPAND_SZ)
    {
        RegCloseKey(hKey);
        throw std::runtime_error("MachineGuid registry type is unexpected");
    }

    std::string buffer(size, '\0');

    result = RegQueryValueExA(
        hKey,
        "MachineGuid",
        nullptr,
        &type,
        reinterpret_cast<BYTE*>(buffer.data()),
        &size);

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS)
    {
        throw std::runtime_error(
            "Cannot read MachineGuid: " + getWindowsError(result));
    }

    const std::size_t nul = buffer.find('\0');
    if (nul != std::string::npos)
    {
        buffer.resize(nul);
    }

    return buffer;
}

inline std::array<std::uint8_t, 16> md5Raw(const void* data, std::size_t dataSize)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContextA(
            &hProv,
            nullptr,
            nullptr,
            PROV_RSA_FULL,
            CRYPT_VERIFYCONTEXT))
    {
        throw std::runtime_error(
            "CryptAcquireContextA failed: " + getWindowsError(GetLastError()));
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        const DWORD error = GetLastError();
        CryptReleaseContext(hProv, 0);
        throw std::runtime_error(
            "CryptCreateHash failed: " + getWindowsError(error));
    }

    if (dataSize > MAXDWORD)
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        throw std::runtime_error("Input too large for CryptHashData");
    }

    if (!CryptHashData(
            hHash,
            reinterpret_cast<const BYTE*>(data),
            static_cast<DWORD>(dataSize),
            0))
    {
        const DWORD error = GetLastError();
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        throw std::runtime_error(
            "CryptHashData failed: " + getWindowsError(error));
    }

    std::array<std::uint8_t, 16> digest{};
    DWORD digestSize = static_cast<DWORD>(digest.size());

    if (!CryptGetHashParam(
            hHash,
            HP_HASHVAL,
            digest.data(),
            &digestSize,
            0))
    {
        const DWORD error = GetLastError();
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        throw std::runtime_error(
            "CryptGetHashParam failed: " + getWindowsError(error));
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    if (digestSize != digest.size())
    {
        throw std::runtime_error("Unexpected MD5 digest size");
    }

    return digest;
}

inline std::string bytesToHex(const std::uint8_t* data, std::size_t size)
{
    static constexpr char HEX[] = "0123456789abcdef";

    std::string output(size * 2, '\0');
    for (std::size_t i = 0; i < size; ++i)
    {
        output[i * 2]     = HEX[(data[i] >> 4) & 0x0F];
        output[i * 2 + 1] = HEX[data[i] & 0x0F];
    }
    return output;
}

inline std::string md5Hex(const std::string& input)
{
    const auto digest = md5Raw(input.data(), input.size());
    return bytesToHex(digest.data(), digest.size());
}

inline std::array<std::uint8_t, 32> deriveLocalKey(const std::string& machineGuid)
{
    std::string input;
    input.reserve(
        std::strlen(KEY_PREFIX) + machineGuid.size() + std::strlen(KEY_SUFFIX));

    input += KEY_PREFIX;
    input += machineGuid;
    input += KEY_SUFFIX;

    const std::string hexKey = md5Hex(input);
    if (hexKey.size() != 32)
    {
        throw std::runtime_error("LocalSecretKey size is not 32");
    }

    std::array<std::uint8_t, 32> key{};
    std::memcpy(key.data(), hexKey.data(), key.size());
    return key;
}

inline std::array<std::uint8_t, 24> makeNonce()
{
    std::array<std::uint8_t, 24> nonce{};
    std::memcpy(nonce.data(), NONCE, nonce.size());
    return nonce;
}

inline std::string encryptBinary(
    const std::string& plaintext,
    const std::array<std::uint8_t, 32>& key,
    const std::array<std::uint8_t, 24>& nonce)
{
    constexpr std::size_t TAG_SIZE = 16;

    std::string encrypted(plaintext.size() + TAG_SIZE, '\0');

    auto* cipherText = reinterpret_cast<std::uint8_t*>(encrypted.data());
    auto* mac = reinterpret_cast<std::uint8_t*>(encrypted.data() + plaintext.size());
    const auto* plainText = plaintext.empty()
        ? nullptr
        : reinterpret_cast<const std::uint8_t*>(plaintext.data());

    crypto_aead_lock(
        cipherText,
        mac,
        key.data(),
        nonce.data(),
        nullptr,
        0,
        plainText,
        plaintext.size());

    return encrypted;
}

inline std::string decryptBinary(
    const std::string& encrypted,
    const std::array<std::uint8_t, 32>& key,
    const std::array<std::uint8_t, 24>& nonce)
{
    constexpr std::size_t TAG_SIZE = 16;

    if (encrypted.size() < TAG_SIZE)
    {
        throw std::runtime_error(
            "Encrypted data is shorter than 16-byte authentication tag");
    }

    const std::size_t cipherSize = encrypted.size() - TAG_SIZE;
    const auto* cipherText = reinterpret_cast<const std::uint8_t*>(encrypted.data());
    const auto* mac = reinterpret_cast<const std::uint8_t*>(encrypted.data() + cipherSize);

    std::string plaintext(cipherSize, '\0');
    auto* plainText = plaintext.empty()
        ? nullptr
        : reinterpret_cast<std::uint8_t*>(plaintext.data());

    const int result = crypto_aead_unlock(
        plainText,
        mac,
        key.data(),
        nonce.data(),
        nullptr,
        0,
        cipherText,
        cipherSize);

    if (result != 0)
    {
        throw std::runtime_error(
            "Decryption failed (wrong key / nonce / ciphertext / tag)");
    }

    return plaintext;
}

inline std::uint8_t hexCharValue(char c)
{
    if (c >= '0' && c <= '9')
    {
        return static_cast<std::uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f')
    {
        return static_cast<std::uint8_t>(c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F')
    {
        return static_cast<std::uint8_t>(c - 'A' + 10);
    }
    throw std::runtime_error("Invalid HEX character");
}

inline std::string hexToBytes(const std::string& input)
{
    std::string hex;
    hex.reserve(input.size());

    for (char c : input)
    {
        if (!std::isspace(static_cast<unsigned char>(c)))
        {
            hex.push_back(c);
        }
    }

    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
    {
        hex.erase(0, 2);
    }

    if (hex.empty())
    {
        return {};
    }

    if ((hex.size() % 2) != 0)
    {
        throw std::runtime_error("HEX length must be even");
    }

    std::string output(hex.size() / 2, '\0');

    for (std::size_t i = 0, j = 0; i < hex.size(); i += 2, ++j)
    {
        const std::uint8_t hi = hexCharValue(hex[i]);
        const std::uint8_t lo = hexCharValue(hex[i + 1]);
        output[j] = static_cast<char>((hi << 4) | lo);
    }

    return output;
}

inline std::string binaryToHex(const std::string& data)
{
    return bytesToHex(
        reinterpret_cast<const std::uint8_t*>(data.data()),
        data.size());
}

} // namespace utools_local_crypto_detail

inline std::string localEncrypt(const std::string& plaintext)
{
    const std::string machineGuid = utools_local_crypto_detail::getMachineGuid();
    const auto key = utools_local_crypto_detail::deriveLocalKey(machineGuid);
    const auto nonce = utools_local_crypto_detail::makeNonce();

    return utools_local_crypto_detail::binaryToHex(
        utools_local_crypto_detail::encryptBinary(plaintext, key, nonce));
}

inline std::string localDecrypt(const std::string& encryptedHex)
{
    const std::string encrypted = utools_local_crypto_detail::hexToBytes(encryptedHex);
    const std::string machineGuid = utools_local_crypto_detail::getMachineGuid();
    const auto key = utools_local_crypto_detail::deriveLocalKey(machineGuid);
    const auto nonce = utools_local_crypto_detail::makeNonce();

    return utools_local_crypto_detail::decryptBinary(encrypted, key, nonce);
}
