#ifndef FILESCANNER_H
#define FILESCANNER_H

#include <QThread>
#include <QHash>
#include <atomic>

class FileScanner : public QThread
{
    Q_OBJECT
public:
    explicit FileScanner(QObject *parent = nullptr);

    void requestStop();

protected:
    void run() override;

private:
    void loadSignatures();
    QString hashFileMd5(const std::wstring &path);

signals:
    void fileFound(QString filePath, QString cheatName);
    void progressUpdated(quint64 scanned, quint64 total);
    void scanFinished();

private:
    QHash<QString, QString> m_signatures;
    std::atomic_bool m_stopRequested{false};
};

#endif // FILESCANNER_H
