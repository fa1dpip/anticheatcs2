#include "filescanner.h"

#include <Windows.h>
#include <wincrypt.h>
#include <filesystem>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

#pragma comment(lib, "Advapi32.lib")

FileScanner::FileScanner(QObject *parent)
    : QThread(parent)
{
    loadSignatures();
}

void FileScanner::requestStop()
{
    m_stopRequested = true;
}

void FileScanner::loadSignatures()
{
    QFile f("config/signatures.json");
    if (!f.open(QIODevice::ReadOnly))
        return;
    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    f.close();
    if (doc.isObject()) {
        QJsonObject obj = doc.object();
        QJsonObject hashes = obj.value("file_hashes").toObject();
        for (auto it = hashes.begin(); it != hashes.end(); ++it) {
            m_signatures.insert(it.key().toLower(), it.value().toString());
        }
    }
}

QString FileScanner::hashFileMd5(const std::wstring &path)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return {};
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return {};
    }

    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return {};
    }

    const DWORD bufSize = 8192;
    BYTE buffer[bufSize];
    DWORD bytesRead = 0;
    while (ReadFile(hFile, buffer, bufSize, &bytesRead, nullptr) && bytesRead) {
        CryptHashData(hHash, buffer, bytesRead, 0);
    }
    CloseHandle(hFile);

    BYTE hash[16];
    DWORD hashSize = sizeof(hash);
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashSize, 0);

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    QString hex;
    for (DWORD i = 0; i < hashSize; ++i) {
        hex += QString::asprintf("%02x", hash[i]);
    }
    return hex.toLower();
}

void FileScanner::run()
{
    quint64 filesScanned = 0;
    quint64 totalFiles = 0;
    DWORD mask = GetLogicalDrives();

    std::vector<std::wstring> roots;
    for (int i = 0; i < 26; ++i) {
        if (mask & (1 << i)) {
            wchar_t drive[] = { static_cast<wchar_t>('A' + i), L':', L'\\', 0 };
            roots.emplace_back(drive);
        }
    }

    for (const auto &root : roots) {
        for (auto it = std::filesystem::recursive_directory_iterator(root, std::filesystem::directory_options::skip_permission_denied);
             it != std::filesystem::recursive_directory_iterator(); ++it) {
            if (m_stopRequested) {
                emit scanFinished();
                return;
            }
            if (it->is_regular_file())
                ++totalFiles;
        }
    }

    for (const auto &root : roots) {
        for (auto it = std::filesystem::recursive_directory_iterator(root, std::filesystem::directory_options::skip_permission_denied);
             it != std::filesystem::recursive_directory_iterator(); ++it) {
            if (m_stopRequested) {
                emit scanFinished();
                return;
            }
            if (!it->is_regular_file())
                continue;

            std::wstring wpath = it->path().wstring();
            QString md5 = hashFileMd5(wpath);
            if (m_signatures.contains(md5)) {
                emit fileFound(QString::fromStdWString(wpath), m_signatures.value(md5));
            }

            ++filesScanned;
            if (filesScanned % 100 == 0) {
                emit progressUpdated(filesScanned, totalFiles);
            }
        }
    }

    emit progressUpdated(filesScanned, totalFiles);
    emit scanFinished();
}
