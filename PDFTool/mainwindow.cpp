#include "mainwindow.h"
#include "qpdf/qpdf-c.h"
#include "JS_PDF.h"
#include "man_applet.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setupUi(this);

    connect( mExtendCBtn, SIGNAL(clicked()), this, SLOT(clickExtendC()));
}

MainWindow::~MainWindow()
{

}

void MainWindow::showWindow()
{
    showNormal();
    show();
    raise();
    activateWindow();
}

void MainWindow::clickExtendC()
{
    QString strSrcPath = mSrcPathText->text();

    if( strSrcPath.length() < 1 )
    {
        mSrcPathText->setFocus();
        return;
    }

    JS_PDF_extend_c( strSrcPath.toLocal8Bit().toStdString().c_str() );
}
