#ifndef MEMORYSCANNER_H
#define MEMORYSCANNER_H

#include <QThread>

class MemoryScanner : public QThread
{
    Q_OBJECT
public:
    explicit MemoryScanner(QObject *parent = nullptr);

protected:
    void run() override;

signals:
    void signatureFound(QString name, quint64 address);
    void scanFinished();
};

#endif // MEMORYSCANNER_H
