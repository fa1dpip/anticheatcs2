#include "memoryscanner.h"

MemoryScanner::MemoryScanner(QObject *parent)
    : QThread(parent)
{
}

#include <Windows.h>
#include <TlHelp32.h>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>

struct MemSignature {
    QByteArray pattern;
    QString name;
};

static bool searchBytes(const QByteArray &data, const QByteArray &pattern, quint64 &offset)
{
    int idx = data.indexOf(pattern);
    if (idx >= 0) {
        offset = static_cast<quint64>(idx);
        return true;
    }
    return false;
}

void MemoryScanner::run()
{
    QFile f("config/signatures.json");
    if (!f.open(QIODevice::ReadOnly)) {
        emit scanFinished();
        return;
    }
    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    f.close();

    std::vector<MemSignature> sigs;
    if (doc.isObject()) {
        QJsonObject memObj = doc.object().value("memory_signatures").toObject();
        for (auto it = memObj.begin(); it != memObj.end(); ++it) {
            MemSignature s{ QByteArray::fromHex(it.key().toUtf8()), it.value().toString() };
            sigs.push_back(std::move(s));
        }
    }

    if (sigs.empty()) {
        emit scanFinished();
        return;
    }

    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{ sizeof(pe) };
        if (Process32FirstW(snap, &pe)) {
            do {
                QString exe = QString::fromWCharArray(pe.szExeFile).toLower();
                if (exe == "cs2.exe") {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }

    if (!pid) {
        emit scanFinished();
        return;
    }

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        emit scanFinished();
        return;
    }

    SYSTEM_INFO sys;
    GetSystemInfo(&sys);
    quint64 addr = reinterpret_cast<quint64>(sys.lpMinimumApplicationAddress);
    quint64 maxAddr = reinterpret_cast<quint64>(sys.lpMaximumApplicationAddress);
    MEMORY_BASIC_INFORMATION mbi;
    QByteArray buffer;
    while (addr < maxAddr) {
        if (VirtualQueryEx(hProc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != sizeof(mbi))
            break;
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) && (mbi.Protect & (PAGE_READWRITE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))) {
            buffer.resize(mbi.RegionSize);
            SIZE_T read = 0;
            if (ReadProcessMemory(hProc, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &read) && read > 0) {
                QByteArray data = QByteArray::fromRawData(buffer.data(), static_cast<int>(read));
                for (const MemSignature &s : sigs) {
                    quint64 off;
                    if (searchBytes(data, s.pattern, off)) {
                        emit signatureFound(s.name, addr + off);
                    }
                }
            }
        }
        addr = reinterpret_cast<quint64>(mbi.BaseAddress) + mbi.RegionSize;
    }

    CloseHandle(hProc);
    emit scanFinished();
}
