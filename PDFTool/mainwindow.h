#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "ui_mainwindow.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow, public Ui::MainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void showWindow();

    void log( const QString strLog );
    void elog( const QString strLog );
    void wlog( const QString strLog );
    void dlog( const QString strLog );
    void write( const QString strLog, QColor cr = QColor(0x00, 0x00, 0x00) );

private slots:
    void clickFindSrcPath();
    void clickFindDstPath();
    void clickExtendC();

private:

};
#endif // MAINWINDOW_H
