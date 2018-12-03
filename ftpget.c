/*
NAME
        Ftpget - Command line non-interactive FTP client

SYNOPSIS
        ftpget [URL] [OPTIONAL OUTPUT PATH]

DESCRIPTION
        Command line program to download files using FTP.

LICENSE
        Copyright 2018 Ivo van Kamp

        Ftpget is free software dual licensed under the GNU LGPL or
        MIT License.

        You can redistribute it and/or modify it under the terms of
        the GNU Lesser General Public License as published by the Free
        Software Foundation, either version 3 of the License, or (at your
        option) any later version,
        or the MIT License as specified in the file LICENSE.MIT
        that you should have received along with Ftpget.
*/
#define _FILE_OFFSET_BITS 64

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/select.h>

#define DEFAULT_FTP_USERNAME  "anonymous"
#define DEFAULT_FTP_PORT      "21"

#define MAX_SCHEME_SIZE       8
#define MAX_USERNAME_SIZE     32
#define MAX_PASSWORD_SIZE     32
#define MAX_HOST_SIZE         255
#define MAX_PORT_SIZE         5
#define MAX_DIRNAME_SIZE      1024
#define MAX_FILENAME_SIZE     1024
#define MAX_URLPATH_SIZE      (MAX_DIRNAME_SIZE+MAX_FILENAME_SIZE)
#define MAX_URL_SIZE          (MAX_SCHEME_SIZE+\
                              MAX_USERNAME_SIZE+\
                              MAX_PASSWORD_SIZE+\
                              MAX_HOST_SIZE+\
                              MAX_PORT_SIZE+\
                              MAX_URLPATH_SIZE)

#define MAX(a,b)              ((a) > (b) ? (a) : (b))
#define BUFSIZE               MAX(BUFSIZ, 8 * 1024)
#define FD_READ_LINE_MAX      (BUFSIZE<4096 ? BUFSIZE : 4096)
#define MAX_WAIT_RESPONSE     10 // seconds

/* RETURN_IF expression is true.
 * Do while to enforce ;
 */
#define RETURN_IF(exp) do { \
    if (exp) { \
        return false; \
    } \
} while (0)

// RETURN_IF expression is true, also print error.
#define RETURN_IF_ERR(str, exp, ...) do { \
    if (exp) { \
        fprintf(stderr, str, ##__VA_ARGS__); \
        fprintf(stderr, "\n"); \
        return false; \
    } \
} while (0)

int control_socket=-1;
int download_socket=-1;

typedef struct {
    char scheme[MAX_SCHEME_SIZE+1];
    char username[MAX_USERNAME_SIZE+1];
    char password[MAX_PASSWORD_SIZE+1];
    char host[MAX_HOST_SIZE+1];
    char port[MAX_PORT_SIZE+1];
    char dirname[MAX_DIRNAME_SIZE+1];
    char filename[MAX_FILENAME_SIZE+1];
    char urlpath[MAX_URLPATH_SIZE+1];
} UrlData;

/* RFC 959 par.4.2. FTP REPLIES
 * Thus the format for multi-line replies is that the first line will begin with
 * the exact required reply code, followed immediately by a Hyphen, "-" (also
 * known as Minus), followed by text.  The last line will begin with the same
 * code, followed immediately by Space <SP>, optionally some text, and the
 * Telnet end-of-line code.
 */
static int getFtpReply(int control_socket, char *buf)
{
    fd_set rfds;
    struct timeval interval;
    char *chunk=buf+4; // Leave room for 4-byte stopcode
    char *tmp;
    int byte_count=0;
    int chunk_counter=0;
    int nr_of_fds=0;

    while((byte_count=read(control_socket, chunk, FD_READ_LINE_MAX))>0) 
    {
        fwrite(chunk, 1, byte_count, stderr);

        if (chunk_counter==0) {
            // Store stop code in front of buffer
            strncpy(buf, chunk, 3);
            *(buf+3)=' ';
        }

        // Check for multi-line chunk
        *(chunk+byte_count)='\0';
        tmp=strrchr(chunk, '\n');
        *(tmp)='\0';
        tmp=strrchr(chunk, '\n');

        // If the last line of the chunk starts with the stop code then break.
        if (strncmp(buf, (tmp==NULL ? chunk : tmp+1), 4)==0) break;

        chunk=buf+4; // Don't overwrite reply/stop code e.g. '230 '
        ++chunk_counter;

        interval.tv_sec = MAX_WAIT_RESPONSE;
        interval.tv_usec = 0;
        nr_of_fds = select(control_socket+1, &rfds, NULL, NULL, &interval);
        RETURN_IF_ERR("Socket error: %s", (nr_of_fds<0), strerror(errno));
        RETURN_IF_ERR("Download timed out after %d seconds", (nr_of_fds==0), MAX_WAIT_RESPONSE);
    }
    return byte_count;
}

static struct addrinfo* getHost(char *host, char *portstr)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sfd, s, j;
    size_t len;
    ssize_t nread;
    char buf[BUFSIZE];
    char fqdn[256];

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    hints.ai_flags = AI_CANONNAME;
    hints.ai_protocol = 0;          /* Any protocol */

    s = getaddrinfo(host, portstr, &hints, &result);
    if (s!=0) {
        fprintf(stderr, "Getaddrinfo: %s\n", gai_strerror(s));
        return NULL;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) 
    {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) continue;
        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1) break; /* Success */
        close(sfd);
    }

    if (rp == NULL) { /* No address succeeded */
        fprintf(stderr, "Could not connect\n");
        exit(EXIT_FAILURE);
    }
    return rp;
}

static int socketSend(int fd, char *format, ...)
{
    char buf[1024];
    va_list args;
    va_start(args, format);
    vsprintf(buf, format, args);
    va_end(args);
    fprintf(stdout, "> %s", buf);
    fflush(stdout);
    return(write(fd, buf, strlen(buf)));
}

static bool download(
        FILE * output_file,
        int read_socket,
        int size,
        long *byte_counter_ptr
        )
{
    char buf[BUFSIZE+1];
    fd_set rfds;
    struct timeval interval;
    char *str;
    size_t bytes_read;
    size_t byte_count=0;
    int nr_of_fds=0;
    bool shouldContinue=true;

    FD_ZERO(&rfds);
    FD_SET(read_socket, &rfds);

    while(true) {

        interval.tv_sec = MAX_WAIT_RESPONSE;
        interval.tv_usec = 0;
        nr_of_fds = select(read_socket+1, &rfds, NULL, NULL, &interval);
        RETURN_IF_ERR("Socket error: %s", (nr_of_fds<0), strerror(errno));
        RETURN_IF_ERR("Download timed out after %d seconds", (nr_of_fds==0), MAX_WAIT_RESPONSE);

        bytes_read = read(read_socket, buf, BUFSIZE);
        if (bytes_read==0) break;
        RETURN_IF_ERR("Socket read error: %s", (bytes_read<0), strerror(errno));

        str = buf;
        if(bytes_read>0) {
            byte_count += bytes_read;
            fprintf(stdout, "\rBytecount: %d (%ld%%)", byte_count, (byte_count*100)/size);
            RETURN_IF_ERR("\nError writing file", 
                (bytes_read != fwrite(str, 1, bytes_read, output_file)));
        }
    }

    fprintf(stdout, "\n");
    *byte_counter_ptr = byte_count;
    return true;
}

/* Connect non-blocking to prevent long timeouts. 
 * https://stackoverflow.com/questions/2597608/c-socket-connection-timeout
 * https://stackoverflow.com/questions/10204134/tcp-connect-error-115-operation-in-progress-what-is-the-cause
 * https://stackoverflow.com/questions/21031717/so-error-vs-errno
 * https://www.gnu.org/software/libc/manual/html_node/Socket_002dLevel-Options.html
 */
bool connectToSocket(int sockfd, struct sockaddr *serv_addr) {

    int opts = fcntl(sockfd,F_GETFL);
    fcntl(sockfd, F_SETFL, opts|O_NONBLOCK);
    connect(sockfd, serv_addr, sizeof(*serv_addr));

    fd_set fdset;
    struct timeval tv;

    FD_ZERO(&fdset);
    FD_SET(sockfd, &fdset);
    tv.tv_sec = 10;
    tv.tv_usec = 0;

    RETURN_IF_ERR("Can't connect to server%s", 
            (select(sockfd+ 1, NULL, &fdset, NULL, &tv) != 1), 
            (errno==115 ? ": timeout occurred" : ""));

    int so_error;
    socklen_t len = sizeof so_error;
    getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
    RETURN_IF_ERR("Socket error: %s", (so_error!=0), strerror(so_error));
    fcntl(sockfd, F_SETFL, opts);
    return true;
}

static bool ftpDownloadFile(UrlData *url, char *output_filename) {

    char   buf[BUFSIZE+4]; // +ftp stop string size
    char   newhost[32];
    FILE * output_file;
    struct hostent *he=NULL;
    struct hostent *hp=NULL;
    struct addrinfo *serv_addr_info;
    char  *serv_ip;
    int    ip[4];
    int    port[2];
    size_t bytes_read;
    long   byte_count;
    int    opts;
    int    size=-1;
    unsigned short newport;
    char newportstr[6];
 
    control_socket = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr_info = getHost(url->host, url->port);
    RETURN_IF(serv_addr_info==NULL);

    serv_ip = inet_ntoa(((struct sockaddr_in *)serv_addr_info->ai_addr)->sin_addr);
    fprintf(stdout, "Connecting to %s (%s)\n", serv_addr_info->ai_canonname, serv_ip);

    RETURN_IF(!connectToSocket(control_socket, serv_addr_info->ai_addr));
    freeaddrinfo(serv_addr_info);
    fprintf(stdout, "Connection established\n");

    bytes_read = getFtpReply(control_socket, buf);
    RETURN_IF_ERR("Unhandled FTP reply after establishing connection", strncmp(buf, "220", 3));

    socketSend(control_socket, "USER %s\r\n", url->username);
    bytes_read = getFtpReply(control_socket, buf);
    RETURN_IF_ERR("Access denied", !strncmp(buf, "530", 3));

    if(!strncmp(buf, "331"/* Password required */, 3)) 
    {
        socketSend(control_socket, "PASS %s\r\n", url->password);
        bytes_read = getFtpReply(control_socket, buf);
        RETURN_IF_ERR("Username or password incorrect", !strncmp(buf, "530"/* Login incorrect */, 3));
        RETURN_IF_ERR("Unhandled FTP reply to PASS", strncmp(buf, "230", 3));
    }
    RETURN_IF_ERR("Unhandled FTP reply to USER", strncmp(buf, "230", 3));

    socketSend(control_socket, "PASV\r\n");
    bytes_read = getFtpReply(control_socket, buf);
    RETURN_IF_ERR("Unhandled FTP reply to PASV", strncmp(buf, "227", 3));

    /* E.g. 227 Entering Passive Mode (192,168,0,100,92,89). */
    RETURN_IF_ERR("Error parsing server PASV reply",
            (6 != sscanf(buf, "%*[^(](%d,%d,%d,%d,%d,%d)", &ip[0], &ip[1], &ip[2], &ip[3], &port[0], &port[1])));

    sprintf(newhost, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);

    newport = port[0]*256 + port[1];
    snprintf(newportstr, 6, "%d", newport);
    serv_addr_info = getHost(newhost, newportstr);
    RETURN_IF(serv_addr_info==NULL);
    download_socket = socket(AF_INET, SOCK_STREAM, 0);

    RETURN_IF(!connectToSocket(download_socket, serv_addr_info->ai_addr));
    freeaddrinfo(serv_addr_info);

    socketSend(control_socket, "TYPE I\r\n");
    bytes_read = getFtpReply(control_socket, buf);
    RETURN_IF_ERR("Can't set data type to image (binary)", strncmp(buf, "200", 3));

    socketSend(control_socket, "RETR /%s\r\n", url->urlpath);
    bytes_read = getFtpReply(control_socket, buf);
    RETURN_IF_ERR("Can't initiate file transfer: %s", strncmp(buf, "150", 3), buf);

    sscanf(buf, "%*[^(](%d", &size);

    output_file = fopen(output_filename, "wb");
    RETURN_IF_ERR("Can't open output file %s", (!output_file), output_filename);

    fprintf(stdout, "Downloading %s (%d bytes)\n", url->filename, size);
    download(output_file, download_socket, size, &byte_count);
    fclose(output_file);
    RETURN_IF_ERR("Error during transfer. Download incomplete.", ((-1 != size) && (size != byte_count)));
    return true;
}

bool isPortNr(char *port_str)
{
    char *tmp;
    int port_nr;
    unsigned long lng;

    errno = 0;
    lng = strtoul(port_str, &tmp, 10);

    if (errno != 0 || tmp == port_str || *tmp != '\0') {
        return false;
    } 
    port_nr = (lng > 65535 || lng==0) ? -1 : (int)lng;

    return port_nr!=-1;
} // source: https://stackoverflow.com/questions/437802/how-to-portably-convert-a-string-into-an-uncommon-integer-type


static bool splitUrlParams(const char **url_str, char end_delimiter, char var_delimiter, char * var1, int max1, char *var2, int max2)
{
    const char *url_ptr=NULL;
    const char *url_ptr2=NULL;
    int var1_length = 0;
    int var2_length = 0;

    // Get var1[DELIMITER]var2[END_DELIMITER]
    if ((url_ptr = strchr (*url_str, end_delimiter)) != NULL) 
    {
        var1_length = url_ptr - *url_str;
        var2_length = 0;

        // Get var2
        if ((url_ptr2 = strchr (*url_str, var_delimiter)) != NULL &&
                url_ptr2 < url_ptr /*not beyond end_delimiter */ ) 
        {
            var1_length = url_ptr2 - *url_str;
            var2_length = url_ptr - url_ptr2 - 1;
            RETURN_IF(var2_length > max2);
            strncpy(var2, url_ptr2+1, var2_length);
            var2[var2_length] = '\0';
        }

        // Get var1
        RETURN_IF(var1_length > max1);
        strncpy(var1, *url_str, var1_length);
        var1[var1_length] = '\0';
        if (var1_length) *url_str += var1_length;
        if (var2_length) *url_str += var2_length;
        // Plus one or two delimiters
        *url_str += (url_ptr2!=NULL && url_ptr2 < url_ptr ? 2 : 1);
    }
    return true;
}

/*
   RFC 1738
   URLs are written as:  <scheme>:<scheme-specific-part>
   Scheme-specific data: //<user>:<password>@<host>:<port>/<url-path>
 */
static bool parseUrl(const char *url_str, UrlData *url)
{
    const char *url_ptr;
    const char *url_ptr2;

    int scheme_length = 0;
    int username_length = 0;
    int passwd_length = 0;
    int host_length = 0;
    int port_length = 0;
    int dirname_length = 0;
    int filename_length = 0;

    url->scheme[0] = '\0';
    url->username[0] = '\0';
    url->password[0] = '\0';
    url->host[0] = '\0';
    url->port[0] = '\0';
    url->urlpath[0] = '\0';
    url->dirname[0] = '\0';
    url->filename[0] = '\0';

    int i=0;
    const char *c=url_str-1;

    for (;i < MAX_URL_SIZE; i++) {
        if (*++c=='\0') break;
    }
    RETURN_IF_ERR("URL error: URL too large", *c!='\0');

    // Get scheme
    if ((url_ptr = strchr (url_str, ':')) != NULL && 
            (strncmp (url_ptr, "://", 3) == 0))
    {
        scheme_length = url_ptr - url_str;
        RETURN_IF_ERR("URL Error: Scheme too large", scheme_length > MAX_SCHEME_SIZE);
        strncpy (url->scheme, url_str, scheme_length);
        url->scheme[scheme_length] = '\0';
        url_str = url_ptr+3;
    }

    RETURN_IF_ERR("URL Error: Username or password too long", 
            !splitUrlParams(&url_str, '@', ':', url->username, MAX_USERNAME_SIZE, url->password, MAX_PASSWORD_SIZE));

    RETURN_IF_ERR("URL Error: Invalid port or hostname", 
            !splitUrlParams(&url_str, '/', ':', url->host, MAX_HOST_SIZE, url->port, MAX_PORT_SIZE));

    RETURN_IF_ERR("URL Error: Invalid port number", 
            strlen(url->port) > 0 && !isPortNr(url->port));

    // Get urlpath
    RETURN_IF_ERR("URL Error: Urlpath too large", strlen(url_str)+1> MAX_URLPATH_SIZE);
    strncpy(url->urlpath, url_str, MAX_URLPATH_SIZE);
    url->urlpath[MAX_URLPATH_SIZE] = '\0';

    RETURN_IF_ERR("URL Error: Invalid filename", (url_ptr = strrchr (url_str-1, '/')) == NULL);
    filename_length = url_str+strlen(url_str)-url_ptr;
    RETURN_IF_ERR("URL Error: Filename too large", filename_length > MAX_FILENAME_SIZE);
    strncpy(url->filename, url_ptr+1, filename_length);
    url->filename[MAX_FILENAME_SIZE] = '\0';

    dirname_length = (url_ptr - url_str)+1;
    RETURN_IF_ERR("URL Error: Dirname too large", dirname_length > MAX_DIRNAME_SIZE);
    strncpy(url->dirname, url_str-1, dirname_length);
    url->dirname[dirname_length] = '\0';

    return true;
}

int main (int argc, char *argv[])
{
    UrlData url;

    if (argc<2||argc>3) {
        printf("Usage: ftpget [URL] [OUTPUT PATH]\n");
        exit(0);
    }

    if (parseUrl(argv[1], &url)<0) {
        exit(1);
    }

    if (strlen(url.username)==0) {
        strncpy(url.username, DEFAULT_FTP_USERNAME, strlen(DEFAULT_FTP_USERNAME)+1);
    }

    if (strlen(url.port)==0) {
        strncpy(url.port, DEFAULT_FTP_PORT, strlen(DEFAULT_FTP_PORT)+1);
    }

    if(!ftpDownloadFile(&url, (argc==3 ? argv[2] : url.filename))) exit(1);

    fprintf(stdout, "Download complete.\n");
    fflush(stdout);
}
