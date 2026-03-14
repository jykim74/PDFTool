#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SEARCH_WINDOW 2048

typedef struct
{
    long startxref;
    int size;
    int root_obj;
} pdf_info;

/* -------------------------------------------------- */
/* find startxref */
/* -------------------------------------------------- */

long find_startxref(FILE *f)
{
    long size;

    fseek(f,0,SEEK_END);
    size = ftell(f);

    long pos = size - SEARCH_WINDOW;
    if(pos < 0) pos = 0;

    fseek(f,pos,SEEK_SET);

    char buf[SEARCH_WINDOW+1];
    fread(buf,1,SEARCH_WINDOW,f);

    buf[SEARCH_WINDOW] = 0;

    char *p = strstr(buf,"startxref");
    if(!p) return -1;

    long offset;
    sscanf(p,"startxref %ld",&offset);

    return offset;
}

/* -------------------------------------------------- */
/* read trailer */
/* -------------------------------------------------- */

void read_trailer(FILE *f,long xref,char *out,int max)
{
    fseek(f,xref,SEEK_SET);

    fread(out,1,max,f);
}

/* -------------------------------------------------- */
/* extract /Size */
/* -------------------------------------------------- */

int extract_size(char *trailer)
{
    int size=0;

    char *p=strstr(trailer,"/Size");
    if(p)
        sscanf(p,"/Size %d",&size);

    return size;
}

/* -------------------------------------------------- */
/* extract /Root */
/* -------------------------------------------------- */

int extract_root(char *trailer)
{
    int obj=0;

    char *p=strstr(trailer,"/Root");
    if(p)
        sscanf(p,"/Root %d",&obj);

    return obj;
}

/* -------------------------------------------------- */
/* copy original pdf */
/* -------------------------------------------------- */

long copy_original(FILE *in,FILE *out)
{
    fseek(in,0,SEEK_END);
    long size=ftell(in);

    rewind(in);

    char buf[4096];
    long total=0;

    while(!feof(in))
    {
        int r=fread(buf,1,sizeof(buf),in);
        if(r<=0) break;

        fwrite(buf,1,r,out);
        total+=r;
    }

    return total;
}

/* -------------------------------------------------- */
/* write certificate stream */
/* -------------------------------------------------- */

long write_cert_stream(FILE *f,
                       int obj,
                       unsigned char *der,
                       int len)
{
    long offset=ftell(f);

    fprintf(f,"%d 0 obj\n",obj);
    fprintf(f,"<< /Length %d >>\n",len);
    fprintf(f,"stream\n");

    fwrite(der,1,len,f);

    fprintf(f,"\nendstream\n");
    fprintf(f,"endobj\n");

    return offset;
}

/* -------------------------------------------------- */
/* write DSS dictionary */
/* -------------------------------------------------- */

long write_dss(FILE *f,
               int obj,
               int cert_obj)
{
    long offset=ftell(f);

    fprintf(f,"%d 0 obj\n",obj);
    fprintf(f,"<<\n");
    fprintf(f, "/Type /DSS\n");
    fprintf(f, "/Certs [%d 0 R]\n",cert_obj);
    fprintf(f, ">>\n");
    fprintf(f, "endobj\n");

    return offset;
}

/* -------------------------------------------------- */
/* write xref */
/* -------------------------------------------------- */

long write_xref(FILE *f,
                int start_obj,
                int count,
                long *offsets)
{
    long xref_pos=ftell(f);

    fprintf(f,"xref\n");
    fprintf(f,"%d %d\n",start_obj,count);

    for(int i=0;i<count;i++)
    {
        fprintf(f,"%010ld 00000 n \n",offsets[i]);
    }

    return xref_pos;
}

/* -------------------------------------------------- */
/* write trailer */
/* -------------------------------------------------- */

void write_trailer(FILE *f,
                   int size,
                   int root,
                   long prev,
                   long xref_pos)
{
    fprintf(f,"trailer\n");
    fprintf(f,"<<\n");
    fprintf(f, "/Size %d\n",size);
    fprintf(f, "/Root %d 0 R\n",root);
    fprintf(f, "/Prev %ld\n",prev);
    fprintf(f, ">>\n" );

    fprintf(f, "startxref\n" );
    fprintf(f, "%ld\n",xref_pos );
    fprintf(f, "%%%%EOF\n" );
}

/* -------------------------------------------------- */
/* main DSS append */
/* -------------------------------------------------- */

int append_dss(const char *input,
               const char *output,
               unsigned char *cert,
               int cert_len)
{
    FILE *in=fopen(input,"rb");
    if(!in) return -1;

    FILE *out=fopen(output,"wb");
    if(!out) return -1;

    long startxref=find_startxref(in);

    char trailer_buf[4096];
    read_trailer(in,startxref,trailer_buf,sizeof(trailer_buf));

    int size=extract_size(trailer_buf);
    int root=extract_root(trailer_buf);

    copy_original(in,out);

    int dss_obj=size;
    int cert_obj=size+1;

    long offsets[2];

    offsets[0]=write_dss(out,dss_obj,cert_obj);
    offsets[1]=write_cert_stream(out,cert_obj,cert,cert_len);

    long xref_pos=write_xref(out,dss_obj,2,offsets);

    write_trailer(out,size+2,root,startxref,xref_pos);

    fclose(in);
    fclose(out);

    return 0;
}

/* -------------------------------------------------- */
/* test main */
/* -------------------------------------------------- */
#if 0
int main()
{
    unsigned char cert[256];

    memset(cert,0xAA,sizeof(cert));

    append_dss("signed.pdf",
               "ltv.pdf",
               cert,
               sizeof(cert));

    return 0;
}
#endif
