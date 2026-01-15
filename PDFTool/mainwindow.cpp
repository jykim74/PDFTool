#include <QDateTime>
#include <QFileInfo>

#include "mainwindow.h"
#include "qpdf/qpdf-c.h"
#include "js_pdf_api.h"
#include <QSettings>

#include "man_applet.h"
#include "common.h"
#include "js_bin.h"
#include "js_pdf.h"

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
    connect( mTest2Btn, SIGNAL(clicked()), this, SLOT(clickTest2()));
    connect( mTest3Btn, SIGNAL(clicked()), this, SLOT(clickTest3()));
    connect( mEncTestBtn, SIGNAL(clicked()), this, SLOT(clickEncTest()));

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
    unsigned char *pCMS = NULL;
    size_t nCMSLen = 0;

    ByteRangeInfo sInfo;
    memset( &sInfo, 0x00, sizeof(ByteRangeInfo));

//    add_signature_field( INPUT_PDF, TEMP_PDF );
    add_signature_field_c( INPUT_PDF, TEMP_PDF );

    ret = calculate_byte_range( TEMP_PDF, &sInfo );
    log( QString( "calculate_byte_range: %1").arg( ret ));

    log( QString( "range[0]: %1 range[1]: %2 range[2]: %3 range[3]: %4")
            .arg( sInfo.range[0] ).arg( sInfo.range[1] ).arg( sInfo.range[2] ).arg( sInfo.range[3] ) );

    log( QString( "contents_start: %1 contents_end: %2").arg( sInfo.contents_start ).arg( sInfo.contents_end ));

    ret = apply_byte_range( TEMP_PDF, &sInfo );
    log( QString( "apply_byte_range: %1").arg( ret ));

    ret = create_pkcs7_signature( TEMP_PDF, sInfo.range, CERT_FILE, KEY_FILE, NULL, &pCMS, &nCMSLen );
    log( QString( "create_pkcs7_signature: %1" ).arg( ret ));

    ret = apply_contents_signature( TEMP_PDF, pCMS, nCMSLen );
    log( QString( "apply_contents_signature: %1" ).arg( ret ));

    if( pCMS )
    {
        JS_free( pCMS );
        pCMS = NULL;
        nCMSLen = 0;
    }

    ret = extract_pkcs7_der_from_pdf( TEMP_PDF, &pCMS, &nCMSLen );
    log( QString("extract_pkcs7_der_from_pdf: %1").arg(ret ));

    ret = verify_pkcs7_signature( TEMP_PDF, sInfo.range, pCMS, nCMSLen, CERT_FILE, NULL );
    log( QString("verify_pkcs7_signature: %1").arg(ret));

    if( pCMS )
    {
        JS_free( pCMS );
        pCMS = NULL;
        nCMSLen = 0;
    }
}

void MainWindow::clickTest2()
{
    int ret = 0;
    log( "Test2" );


    BIN binDst = {0,0};
    BIN binCMS = {0,0};

    ByteRangeInfo sInfo;
    memset( &sInfo, 0x00, sizeof(ByteRangeInfo));

    add_signature_field_c2( INPUT_PDF, &binDst );

    ret = calculate_byte_range2( &binDst, &sInfo );
    log( QString( "calculate_byte_range: %1").arg( ret ));

    log( QString( "range[0]: %1 range[1]: %2 range[2]: %3 range[3]: %4")
            .arg( sInfo.range[0] ).arg( sInfo.range[1] ).arg( sInfo.range[2] ).arg( sInfo.range[3] ) );

    log( QString( "contents_start: %1 contents_end: %2").arg( sInfo.contents_start ).arg( sInfo.contents_end ));

    ret = apply_byte_range2( &binDst, &sInfo );
    log( QString( "apply_byte_range: %1").arg( ret ));

    ret = create_pkcs7_signature2( &binDst, sInfo.range, CERT_FILE, KEY_FILE, NULL, &binCMS );
    log( QString( "create_pkcs7_signature: %1" ).arg( ret ));

    ret = apply_contents_signature2( &binDst, &binCMS );
    log( QString( "apply_contents_signature: %1" ).arg( ret ));

    JS_BIN_reset( &binCMS );

    ret = extract_pkcs7_der_from_pdf2( &binDst, &binCMS );
    log( QString("extract_pkcs7_der_from_pdf: %1").arg(ret ));

    ret = verify_pkcs7_signature2( &binDst, sInfo.range, &binCMS, CERT_FILE, NULL );
    log( QString("verify_pkcs7_signature: %1").arg(ret));

    JS_BIN_reset( &binCMS );
    JS_BIN_reset( &binDst );
}

void MainWindow::clickTest3()
{
    const char *pPasswd = NULL;
    time_t now_t = time(NULL);
    BIN binDst = {0,0};
    BIN binRead = {0,0};

    int ret = JS_PDF_makeUnsignedFile( INPUT_PDF, pPasswd, now_t, TEMP_PDF );

    ret = JS_PDF_makeUnsigned( INPUT_PDF, pPasswd, now_t, &binDst );

    JS_BIN_fileRead( TEMP_PDF, &binRead );

    log( QString( "FileSize: %1 BIN size: %2").arg( binRead.nLen ).arg( binDst.nLen ));

    ret = JS_BIN_cmp( &binRead, &binDst );
    if( ret == 0 )
        log( "File same" );
    else
        log( QString( "File different: %1").arg(ret ));

    JS_BIN_reset( &binDst );
    JS_BIN_reset( &binRead );
}

void MainWindow::clickEncTest()
{
    int ret = 0;
    const char *pPasswd = "test";

    log( "Enc Test" );

//    ret = pdf_encrypt_c( INPUT_PDF, ENC_PDF, pPasswd );
    ret = JS_PDF_encryptFile( INPUT_PDF, pPasswd, ENC_PDF );
    log( QString( "PDF encrypt: %1").arg( ret ));

//    ret = pdf_decrypt_c( ENC_PDF, pPasswd, DEC_PDF );
    ret = JS_PDF_decryptFile( ENC_PDF, pPasswd, DEC_PDF );
    log( QString( "PDF decrypt: %1").arg( ret ));
}
