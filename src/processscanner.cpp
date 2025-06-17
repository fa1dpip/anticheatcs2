#include "processscanner.h"

#include <Windows.h>
#include <TlHelp32.h>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

ProcessScanner::ProcessScanner(QObject *parent)
    : QThread(parent)
{
}

void ProcessScanner::run()
{
    QFile f("config/signatures.json");
    if (!f.open(QIODevice::ReadOnly)) {
        emit scanFinished();
        return;
    }
    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    f.close();
    QStringList names;
    if (doc.isObject()) {
        QJsonObject obj = doc.object();
        QJsonArray arr = obj.value("process_names").toArray();
        for (const QJsonValue &v : arr) {
            names.append(v.toString().toLower());
        }
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        emit scanFinished();
        return;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            QString exe = QString::fromWCharArray(pe.szExeFile).toLower();
            if (names.contains(exe)) {
                emit processFound(static_cast<qint64>(pe.th32ProcessID), exe);
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);

    emit scanFinished();
}
