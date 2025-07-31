#ifndef MAN_APPLET_H
#define MAN_APPLET_H

#include <QObject>
#include <QMessageBox>

class MainWindow;

class ManApplet : public QObject
{
    Q_OBJECT

public:
    ManApplet( QObject *parent = nullptr );

    void start();
    static QString getBrand();

    MainWindow* mainWindow() { return main_win_; };

    void messageBox(const QString& msg, QWidget *parent);
    void warningBox(const QString& msg, QWidget *parent);
    bool yesOrNoBox(const QString& msg, QWidget *parent, bool default_val=true);
    bool detailedYesOrNoBox(const QString& msg, const QString& detailed_text, QWidget *parent, bool default_val=true);
    QMessageBox::StandardButton yesNoCancelBox(const QString& msg,
                                               QWidget *parent,
                                               QMessageBox::StandardButton default_btn);
    bool yesOrCancelBox(const QString& msg, QWidget *parent, bool default_ok);

    QString curFilePath( const QString strPath = "" );
    QString curPath( const QString strPath = "" );

    QString findFile( QWidget *parent, int nType, const QString strPath, bool bSave = true );
    QString findFile( QWidget *parent, int nType, const QString strPath, QString& strSelected, bool bSave = true );
    QString findSaveFile( QWidget *parent, int nType, const QString strPath, bool bSave = true );
    QString findSaveFile( QWidget *parent, const QString strFilter, const QString strPath, bool bSave = true );
    QString findFolder( QWidget *parent, const QString strPath, bool bSave = true );

private:
    Q_DISABLE_COPY(ManApplet)

    MainWindow* main_win_;
    QString cur_file_;
};

extern ManApplet *manApplet;

#endif // MAN_APPLET_H
