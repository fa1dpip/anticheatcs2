#ifndef PROCESSSCANNER_H
#define PROCESSSCANNER_H

#include <QThread>

class ProcessScanner : public QThread
{
    Q_OBJECT
public:
    explicit ProcessScanner(QObject *parent = nullptr);

protected:
    void run() override;

signals:
    void processFound(qint64 pid, QString name);
    void scanFinished();
};

#endif // PROCESSSCANNER_H
