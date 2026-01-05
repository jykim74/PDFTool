#ifndef JS_PDF_H
#define JS_PDF_H

#include <iostream>

int JS_PDF_extend_c( const char *pPDFPath, int *pnPages );
int JS_PDF_process( const char* whoami, char const* infile, std::string outprefix );

void create_unsigned_pdf(const char* in, const char* out);
void sign_pdf(
    const char* unsigned_pdf,
    const char* signed_pdf,
    const char* cert,
    const char* key
    );


#endif // JS_PDF_H
