#include "JS_PDF.h"
#include "qpdf/qpdf-c.h"

#include <qpdf/QIntC.hh>
#include <qpdf/QPDF.hh>
#include <qpdf/QPDFPageDocumentHelper.hh>
#include <qpdf/QPDFWriter.hh>
#include <qpdf/QUtil.hh>

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

static char const* whoami = 0;

int JS_PDF_extend_c( const char *pPDFPath,  int *pnPages  )
{
    const char* infile = NULL;
    qpdf_data qpdf = qpdf_init();
    int warnings = 0;
    int errors = 0;
    char* p = NULL;

    infile = pPDFPath;

    if ((qpdf_read(qpdf, infile, NULL) & QPDF_ERRORS) == 0) {
        int npages;
        if ((num_pages(qpdf, &npages) & QPDF_ERRORS) == 0) {
            printf("num pages = %d\n", npages);
            *pnPages = npages;
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

static bool static_id = false;

int JS_PDF_process( const char* whoami, char const* infile, std::string outprefix )
{
    QPDF inpdf;
    inpdf.processFile(infile);
    std::vector<QPDFPageObjectHelper> pages = QPDFPageDocumentHelper(inpdf).getAllPages();
    int pageno_len = QIntC::to_int(std::to_string(pages.size()).length());
    int pageno = 0;
    for (auto& page: pages) {
        std::string outfile = outprefix + QUtil::int_to_string(++pageno, pageno_len) + ".pdf";
        QPDF outpdf;
        outpdf.emptyPDF();
        QPDFPageDocumentHelper(outpdf).addPage(page, false);
        QPDFWriter outpdfw(outpdf, outfile.c_str());
        if (static_id) {
            // For the test suite, uncompress streams and use static IDs.
            outpdfw.setStaticID(true); // for testing only
            outpdfw.setStreamDataMode(qpdf_s_uncompress);
        }
        outpdfw.write();
    }

    return 0;
}
