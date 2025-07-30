#include "man_applet.h"
#include "mainwindow.h"

ManApplet *manApplet;

ManApplet::ManApplet(QObject *parent)
{

}

void ManApplet::start()
{
    main_win_ = new MainWindow;
    main_win_->show();
}
