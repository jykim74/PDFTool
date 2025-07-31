#include <QDateTime>

#include "mainwindow.h"
#include "qpdf/qpdf-c.h"
#include "JS_PDF.h"
#include "man_applet.h"
#include "common.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setupUi(this);

    connect( mSrcFindBtn, SIGNAL(clicked()), this, SLOT(clickFindSrcPath()));
    connect( mDstFindBtn, SIGNAL(clicked()), this, SLOT(clickFindDstPath()));
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

void MainWindow::log( QString strLog )
{
    QDateTime date;
    date.setSecsSinceEpoch( time(NULL));
    QString strMsg;

    strMsg = QString("[I][%1] %2\n" ).arg( date.toString( "HH:mm:ss") ).arg( strLog );
    write( strMsg );
}

void MainWindow::elog( const QString strLog )
{
    QDateTime date;
    date.setSecsSinceEpoch( time(NULL));
    QString strMsg;

    strMsg = QString("[E][%1] %2\n" ).arg( date.toString( "HH:mm:ss") ).arg( strLog );
    write( strMsg, QColor(0xFF, 0x00, 0x00));
}

void MainWindow::wlog( const QString strLog )
{
    QDateTime date;
    date.setSecsSinceEpoch( time(NULL));
    QString strMsg;

    strMsg = QString("[W][%1] %2\n" ).arg( date.toString( "HH:mm:ss") ).arg( strLog );
    write( strMsg, QColor(0x66, 0x33, 0x00));
}

void MainWindow::dlog( const QString strLog )
{
    QDateTime date;
    date.setSecsSinceEpoch( time(NULL));
    QString strMsg;

    strMsg = QString("[D][%1] %2\n" ).arg( date.toString( "HH:mm:ss") ).arg( strLog );
    write( strMsg, QColor( 0x00, 0x00, 0xFF ));
}

void MainWindow::write( const QString strLog, QColor cr )
{
    QTextCursor cursor = mLogText->textCursor();

    QTextCharFormat format;
    format.setForeground( cr );
    cursor.mergeCharFormat(format);

    cursor.insertText( strLog );
    cursor.movePosition( QTextCursor::End );
    mLogText->setTextCursor( cursor );
    mLogText->repaint();
}


void MainWindow::clickFindSrcPath()
{
    QString strPath = mSrcPathText->text();
    QString strFilename = manApplet->findFile( this, JS_FILE_TYPE_PDF, strPath );
    mSrcPathText->setText( strFilename );
}

void MainWindow::clickFindDstPath()
{
    QString strPath = mDstPathText->text();
    QString strFilename = manApplet->findFile( this, JS_FILE_TYPE_PDF, strPath );
    mDstPathText->setText( strFilename );
}

void MainWindow::clickExtendC()
{
    int nPages = 0;
    QString strSrcPath = mSrcPathText->text();

    if( strSrcPath.length() < 1 )
    {
        manApplet->warningBox( tr( "Find a source pdf" ), this );
        mSrcPathText->setFocus();
        return;
    }

    JS_PDF_extend_c( strSrcPath.toLocal8Bit().toStdString().c_str(), &nPages );
    log( QString( "Pages: %1" ).arg( nPages ));
}
