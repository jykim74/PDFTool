#include <QDateTime>
#include <QFileInfo>

#include "mainwindow.h"
#include "qpdf/qpdf-c.h"
#include "JS_PDF.h"
#include <QSettings>

#include "man_applet.h"
#include "common.h"

const QString kSrcPath = "SrcPath";
const QString kCertPath = "CertPath";
const QString kPriKeyPath = "PriKeyPath";

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setupUi(this);

    connect( mSrcFindBtn, SIGNAL(clicked()), this, SLOT(clickFindSrcPath()));
    connect( mDstFindBtn, SIGNAL(clicked()), this, SLOT(clickFindDstPath()));
    connect( mSignedFindBtn, SIGNAL(clicked()), this, SLOT(clickFindSignedPath()));
    connect( mCertFindBtn, SIGNAL(clicked()), this, SLOT(clickFindCertPath()));
    connect( mPriKeyFindBtn, SIGNAL(clicked()), this, SLOT(clickFindPriKeyPath()));

    connect( mExtendCBtn, SIGNAL(clicked()), this, SLOT(clickExtendC()));
    connect( mMakeSignBtn, SIGNAL(clicked()), this, SLOT(clickMakeSign()));
    connect( mVerifySignBtn, SIGNAL(clicked()), this, SLOT(clickVerifySign()));
    connect( mTestBtn, SIGNAL(clicked()), this, SLOT(clickTest()));

    initialize();

#if defined(Q_OS_MAC)
    layout()->setSpacing(5);
#endif

    resize(minimumSizeHint().width(), minimumSizeHint().height());
}

MainWindow::~MainWindow()
{

}

void MainWindow::initialize()
{
    QString strSrcPath = getEnvSrc();
    mSrcPathText->setText( strSrcPath );
    mCertPathText->setText( getEnvCert() );
    mPriKeyPathText->setText( getEnvPriKey() );
}

void MainWindow::setEnvSrc( const QString strSrcPath )
{
    QSettings settings;
    settings.beginGroup( kEnvTempGroup );
    settings.setValue( kSrcPath, strSrcPath );
    settings.endGroup();
}

const QString MainWindow::getEnvSrc()
{
    QString strPath;

    QSettings settings;
    settings.beginGroup( kEnvTempGroup );
    strPath = settings.value( kSrcPath, "" ).toString();
    settings.endGroup();

    return strPath;
}

void MainWindow::setEnvCert( const QString strSrcPath )
{
    QSettings settings;
    settings.beginGroup( kEnvTempGroup );
    settings.setValue( kCertPath, strSrcPath );
    settings.endGroup();
}

const QString MainWindow::getEnvCert()
{
    QString strPath;

    QSettings settings;
    settings.beginGroup( kEnvTempGroup );
    strPath = settings.value( kCertPath, "cert.pem" ).toString();
    settings.endGroup();

    return strPath;
}

void MainWindow::setEnvPriKey( const QString strSrcPath )
{
    QSettings settings;
    settings.beginGroup( kEnvTempGroup );
    settings.setValue( kPriKeyPath, strSrcPath );
    settings.endGroup();
}

const QString MainWindow::getEnvPriKey()
{
    QString strPath;

    QSettings settings;
    settings.beginGroup( kEnvTempGroup );
    strPath = settings.value( kPriKeyPath, "prikey.pem" ).toString();
    settings.endGroup();

    return strPath;
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

    if( strFilename.length() > 0 )
    {
        mSrcPathText->setText( strFilename );
        setEnvSrc( strFilename );
    }
}

void MainWindow::clickFindDstPath()
{
    QString strPath = mDstPathText->text();
    QString strFilename = manApplet->findFile( this, JS_FILE_TYPE_PDF, strPath );

    if( strFilename.length() > 0 )
    {
        mDstPathText->setText( strFilename );
    }
}

void MainWindow::clickFindSignedPath()
{
    QString strPath = mSignedPathText->text();
    QString strFilename = manApplet->findFile( this, JS_FILE_TYPE_PDF, strPath );

    if( strFilename.length() > 0 )
    {
        mSignedPathText->setText( strFilename );
    }
}

void MainWindow::clickFindCertPath()
{
    QString strPath = mCertPathText->text();
    QString strFilename = manApplet->findFile( this, JS_FILE_TYPE_CERT, strPath );

    if( strFilename.length() > 0 )
    {
        mCertPathText->setText( strFilename );
        setEnvCert( strFilename );
    }
}

void MainWindow::clickFindPriKeyPath()
{
    QString strPath = mPriKeyPathText->text();
    QString strFilename = manApplet->findFile( this, JS_FILE_TYPE_PRIKEY, strPath );

    if( strFilename.length() > 0 )
    {
        mPriKeyPathText->setText( strFilename );
        setEnvPriKey( strFilename );
    }
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

void MainWindow::clickMakeSign()
{
    log( "Make Signature" );

    QString strSrcPath = mSrcPathText->text();
    QString strDstPath = mDstPathText->text();
    QString strSignedPath = mSignedPathText->text();
    QString strCertPath = mCertPathText->text();
    QString strPriKeyPath = mPriKeyPathText->text();

    if( strSrcPath.length() < 1 )
    {
        manApplet->warningBox( tr( "Find a source pdf" ), this );
        mSrcPathText->setFocus();
        return;
    }

    if( strCertPath.length() < 1 )
    {
        manApplet->warningBox( tr( "Find a certificate" ), this );
        mCertPathText->setFocus();
        return;
    }

    if( strPriKeyPath.length() < 1 )
    {
        manApplet->warningBox( tr( "Find a private key" ), this );
        mPriKeyPathText->setFocus();
        return;
    }

    if( strDstPath.length() < 1 )
    {
        QFileInfo fileInfo( strSrcPath );
        strDstPath = QString( "%1/%2_unsigned.pdf" ).arg( fileInfo.path() ).arg( fileInfo.baseName() );
        mDstPathText->setText( strDstPath );
    }

    if( strSignedPath.length() < 1 )
    {
        QFileInfo fileInfo( strSrcPath );
        strSignedPath = QString( "%1/%2_signed.pdf" ).arg( fileInfo.path() ).arg( fileInfo.baseName() );
        mSignedPathText->setText( strSignedPath );
    }
}

void MainWindow::clickVerifySign()
{
    log( "Verify Signature" );
}

void MainWindow::clickTest()
{
    int ret = 0;
    log( "Test" );

    ByteRangeInfo sInfo;
    memset( &sInfo, 0x00, sizeof(ByteRangeInfo));

    add_signature_field( INPUT_PDF, TEMP_PDF );
    ret = calculate_byte_range( TEMP_PDF, &sInfo );
    log( QString( "calculate_byte_range: %1").arg( ret ));

    log( QString( "range[0]: %1 range[1]: %2 range[2]: %3 range[3]: %4")
            .arg( sInfo.range[0] ).arg( sInfo.range[1] ).arg( sInfo.range[2] ).arg( sInfo.range[3] ) );

    log( QString( "contents_start: %1 contents_end: %2").arg( sInfo.contents_start ).arg( sInfo.contents_end ));


    ret = apply_byte_range( TEMP_PDF, &sInfo );
    log( QString( "apply_byte_range: %1").arg( ret ));

}
