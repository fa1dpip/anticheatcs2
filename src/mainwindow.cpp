#include "mainwindow.h"
#include "processscanner.h"
#include "filescanner.h"
#include "memoryscanner.h"

#include <QPushButton>
#include <QProgressBar>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QMessageBox>

#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle("CS2 Anti-Cheat");

    QWidget *central = new QWidget(this);
    setCentralWidget(central);

    QVBoxLayout *layout = new QVBoxLayout(central);
    QTabWidget *tabWidget = new QTabWidget(central);
    layout->addWidget(tabWidget);

    QWidget *tabOverview = new QWidget();
    tabWidget->addTab(tabOverview, tr("Overview"));

    QWidget *tabFile = new QWidget();
    QVBoxLayout *fileLayout = new QVBoxLayout(tabFile);
    QPushButton *scanFilesButton = new QPushButton(tr("Сканировать файлы"));
    scanFilesButton->setObjectName("scanFilesButton");
    fileLayout->addWidget(scanFilesButton);
    QProgressBar *fileProgress = new QProgressBar();
    fileProgress->setObjectName("fileProgressBar");
    fileLayout->addWidget(fileProgress);
    QPushButton *cancelFileButton = new QPushButton(tr("Отмена"));
    cancelFileButton->setObjectName("cancelFileScanButton");
    fileLayout->addWidget(cancelFileButton);
    QTableWidget *tableFiles = new QTableWidget();
    tableFiles->setObjectName("tableFiles");
    tableFiles->setColumnCount(2);
    tableFiles->setHorizontalHeaderLabels({tr("Путь"), tr("Название чита")});
    fileLayout->addWidget(tableFiles);
    tabWidget->addTab(tabFile, tr("File Scan"));

    QWidget *tabProcesses = new QWidget();
    QVBoxLayout *procLayout = new QVBoxLayout(tabProcesses);
    QPushButton *scanProcessesButton = new QPushButton(tr("Сканировать процессы"));
    scanProcessesButton->setObjectName("scanProcessesButton");
    procLayout->addWidget(scanProcessesButton);
    QTableWidget *tableProcesses = new QTableWidget();
    tableProcesses->setObjectName("tableProcesses");
    tableProcesses->setColumnCount(2);
    tableProcesses->setHorizontalHeaderLabels({tr("PID"), tr("Имя процесса")});
    procLayout->addWidget(tableProcesses);
    tabWidget->addTab(tabProcesses, tr("Process Scan"));

    QWidget *tabMemory = new QWidget();
    QVBoxLayout *memLayout = new QVBoxLayout(tabMemory);
    QPushButton *scanMemoryButton = new QPushButton(tr("Сканировать память"));
    scanMemoryButton->setObjectName("scanMemoryButton");
    memLayout->addWidget(scanMemoryButton);
    QTableWidget *tableMemory = new QTableWidget();
    tableMemory->setObjectName("tableMemory");
    tableMemory->setColumnCount(2);
    tableMemory->setHorizontalHeaderLabels({tr("Адрес"), tr("Название чита")});
    memLayout->addWidget(tableMemory);
    tabWidget->addTab(tabMemory, tr("Memory Scan"));

    QWidget *tabSettings = new QWidget();
    tabWidget->addTab(tabSettings, tr("Settings"));

    connect(scanProcessesButton, &QPushButton::clicked, this, &MainWindow::onScanProcesses);
    connect(scanFilesButton, &QPushButton::clicked, this, &MainWindow::onStartFileScan);
    connect(cancelFileButton, &QPushButton::clicked, this, &MainWindow::onCancelFileScan);
    connect(scanMemoryButton, &QPushButton::clicked, this, &MainWindow::onStartMemoryScan);
}

MainWindow::~MainWindow()
{
}

void MainWindow::onScanProcesses()
{
    if (processScanner) {
        return;
    }
    processScanner = new ProcessScanner(this);
    connect(processScanner, &ProcessScanner::processFound, this, &MainWindow::onProcessFound);
    connect(processScanner, &ProcessScanner::scanFinished, this, &MainWindow::onProcessScanFinished);
    connect(processScanner, &QThread::finished, processScanner, &QObject::deleteLater);
    processScanner->start();
}

void MainWindow::onProcessFound(qint64 pid, QString name)
{
    QTableWidget *table = findChild<QTableWidget*>("tableProcesses");
    if (!table)
        return;
    int row = table->rowCount();
    table->insertRow(row);
    table->setItem(row, 0, new QTableWidgetItem(QString::number(pid)));
    table->setItem(row, 1, new QTableWidgetItem(name));
}

void MainWindow::onProcessScanFinished()
{
    processScanner = nullptr;
}

void MainWindow::onStartFileScan()
{
    if (fileScanner)
        return;
    fileScanner = new FileScanner(this);
    connect(fileScanner, &FileScanner::fileFound, this, &MainWindow::onFileFound);
    connect(fileScanner, &FileScanner::progressUpdated, this, &MainWindow::onFileScanProgress);
    connect(fileScanner, &FileScanner::scanFinished, this, &MainWindow::onFileScanFinished);
    connect(fileScanner, &QThread::finished, fileScanner, &QObject::deleteLater);
    fileScanner->start();
}

void MainWindow::onFileFound(QString path, QString cheatName)
{
    QTableWidget *table = findChild<QTableWidget*>("tableFiles");
    if (!table)
        return;
    int row = table->rowCount();
    table->insertRow(row);
    table->setItem(row, 0, new QTableWidgetItem(path));
    table->setItem(row, 1, new QTableWidgetItem(cheatName));
}

void MainWindow::onFileScanProgress(quint64 done, quint64 total)
{
    QProgressBar *bar = findChild<QProgressBar*>("fileProgressBar");
    if (!bar)
        return;
    bar->setMaximum(static_cast<int>(total));
    bar->setValue(static_cast<int>(done));
}

void MainWindow::onFileScanFinished()
{
    fileScanner = nullptr;
}

void MainWindow::onCancelFileScan()
{
    if (fileScanner)
        fileScanner->requestStop();
}

void MainWindow::onStartMemoryScan()
{
    if (memoryScanner)
        return;
    memoryScanner = new MemoryScanner(this);
    connect(memoryScanner, &MemoryScanner::signatureFound, this, &MainWindow::onMemoryPatternFound);
    connect(memoryScanner, &MemoryScanner::scanFinished, this, &MainWindow::onMemoryScanFinished);
    connect(memoryScanner, &QThread::finished, memoryScanner, &QObject::deleteLater);
    memoryScanner->start();
}

void MainWindow::onMemoryPatternFound(QString name, quint64 address)
{
    QTableWidget *table = findChild<QTableWidget*>("tableMemory");
    if (!table)
        return;
    int row = table->rowCount();
    table->insertRow(row);
    table->setItem(row, 0, new QTableWidgetItem(QString("0x%1").arg(address, 0, 16)));
    table->setItem(row, 1, new QTableWidgetItem(name));
}

void MainWindow::onMemoryScanFinished()
{
    memoryScanner = nullptr;
}

void MainWindow::onDeleteSelectedFile()
{
    QTableWidget *table = findChild<QTableWidget*>("tableFiles");
    if (!table)
        return;
    auto items = table->selectedItems();
    QSet<int> rows;
    for (auto *item : items) {
        rows.insert(item->row());
    }
    QList<int> rowList = rows.values();
    std::sort(rowList.begin(), rowList.end(), std::greater<int>());
    for (int row : rowList) {
        QString path = table->item(row, 0)->text();
        QFile::remove(path);
        table->removeRow(row);
    }
}
