#ifndef JS_PDF_H
#define JS_PDF_H

#include <iostream>

int JS_PDF_extend_c( const char *pPDFPath, int *pnPages );
int JS_PDF_process( const char* whoami, char const* infile, std::string outprefix );

#endif // JS_PDF_H
