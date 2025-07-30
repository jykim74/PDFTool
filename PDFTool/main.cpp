#include "mainwindow.h"

#include <QApplication>

#include "man_applet.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    QCoreApplication::setOrganizationName( "JS Inc" );
    QCoreApplication::setOrganizationDomain( "jssoft.com" );
    QCoreApplication::setApplicationName( "PDFTool" );

    ManApplet mApplet;
    manApplet = &mApplet;
    manApplet->start();

    return app.exec();
}
