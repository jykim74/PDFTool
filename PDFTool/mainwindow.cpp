#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "qpdf/qpdf-c.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    test();
}

MainWindow::~MainWindow()
{
    delete ui;
}

static char const* whoami = 0;

int
numPages(std::shared_ptr<QPDF> qpdf)
{
    return qpdf->getRoot().getKey("/Pages").getKey("/Count").getIntValueAsInt();
}


// Now we define the glue that makes our function callable using the C API.

// This is the C++ implementation of the C function.
QPDF_ERROR_CODE
num_pages(qpdf_data qc, int* npages)
{
    // Call qpdf_c_wrap to convert any exception our function might through to a QPDF_ERROR_CODE
    // and attach it to the qpdf_data object in the same way as other functions in the C API.
    return qpdf_c_wrap(qc, [&qc, &npages]() { *npages = numPages(qpdf_c_get_qpdf(qc)); });
}


int aaa( int argc, char* argv[] )
{
    char* infile = NULL;
    qpdf_data qpdf = qpdf_init();
    int warnings = 0;
    int errors = 0;
    char* p = NULL;

    if ((p = strrchr(argv[0], '/')) != NULL) {
        whoami = p + 1;
    } else if ((p = strrchr(argv[0], '\\')) != NULL) {
        whoami = p + 1;
    } else {
        whoami = argv[0];
    }

    infile = argv[1];

    if ((qpdf_read(qpdf, infile, NULL) & QPDF_ERRORS) == 0) {
        int npages;

        if ((num_pages(qpdf, &npages) & QPDF_ERRORS) == 0) {
            printf("num pages = %d\n", npages);
        }
    }
    if (qpdf_more_warnings(qpdf)) {
        warnings = 1;
    }
    if (qpdf_has_error(qpdf)) {
        errors = 1;
        printf("error: %s\n", qpdf_get_error_full_text(qpdf, qpdf_get_error(qpdf)));
    }
    qpdf_cleanup(&qpdf);
    if (errors) {
        return 2;
    } else if (warnings) {
        return 3;
    }

    return 0;
}

int MainWindow::test()
{
    char *argv[100];

    aaa( 1, argv );
    return 0;
}
