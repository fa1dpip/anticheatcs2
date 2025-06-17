#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QThread>

class ProcessScanner;
class FileScanner;
class MemoryScanner;

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onScanProcesses();
    void onProcessFound(qint64 pid, QString name);
    void onProcessScanFinished();

    void onStartFileScan();
    void onFileFound(QString path, QString cheatName);
    void onFileScanProgress(quint64 done, quint64 total);
    void onFileScanFinished();
    void onCancelFileScan();

    void onStartMemoryScan();
    void onMemoryPatternFound(QString name, quint64 address);
    void onMemoryScanFinished();
    void onDeleteSelectedFile();

private:
    ProcessScanner *processScanner = nullptr;
    FileScanner *fileScanner = nullptr;
    MemoryScanner *memoryScanner = nullptr;
};

#endif // MAINWINDOW_H
