/*
 * Copyright (C) 2011 Tildeslash Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

#include <config.h>

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_SETJMP_H
#include <setjmp.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#include "processor.h"
#include "base64.h"


/**
 *  A naive quasi HTTP Processor module that can handle HTTP requests
 *  received from a client, and return responses based on those
 *  requests.
 *
 *  This Processor delegates the actual handling of the request and
 *  reponse to so called cervlets, which must implement two methods;
 *  doGet and doPost. We call them cervlets because they are small
 *  C-modules closely resembling Java Servlets.
 *
 *  NOTES
 *    This Processor is command oriented and if a second slash '/' is
 *    found in the URL it's asumed to be the PATHINFO. In other words
 *    this processor perceive an URL as:
 *
 *                      /COMMAND?QUERYSTRING/PATHINFO
 *
 *     The doGet/doPost routines act's on the COMMAND. See the
 *     cervlet.c code in this dir. for an example. 
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Christian Hopp, <chopp@iei.tu-clausthal.de>
 *
 *  @file
 */


/* -------------------------------------------------------------- Prototypes */


static void do_service(Socket_T);
static void destroy_entry(void *);
static char *get_date(char *, int);
static char *get_server(char *, int); 
static void create_headers(HttpRequest);
static void send_response(HttpResponse);
static int basic_authenticate(HttpRequest);
static void done(HttpRequest, HttpResponse);
static void destroy_HttpRequest(HttpRequest);
static void reset_response(HttpResponse res);
static HttpParameter parse_parameters(char *);
static int create_parameters(HttpRequest req);
static void destroy_HttpResponse(HttpResponse);
static HttpRequest create_HttpRequest(Socket_T);
static void internal_error(Socket_T, int, char *);
static HttpResponse create_HttpResponse(Socket_T);
static int is_authenticated(HttpRequest, HttpResponse);
static int get_next_token(char *s, int *cursor, char **r);


/* ------------------------------------------------------------------ Public */


/**
 * Process a HTTP request. This is done by dispatching to the service
 * function. 
 * @param s A Socket_T representing the client connection
 */
void *http_processor(Socket_T s) {

  if(! can_read(socket_get_socket(s), REQUEST_TIMEOUT)) {
    internal_error(s, SC_REQUEST_TIMEOUT, "Time out when handling the Request");
  } else {
    do_service(s);
  }
  socket_free(&s);

  return NULL;

}


/**
 * Callback for implementors of cervlet functions.
 * @param doGetFunc doGet function
 * @param doPostFunc doPost function 
 */
void add_Impl(void(*doGet)(HttpRequest, HttpResponse), void(*doPost)(HttpRequest, HttpResponse)) {
  Impl.doGet= doGet;
  Impl.doPost= doPost;
}


/**
 * Send an error message
 * @param res HttpResponse object
 * @param code Error Code to lookup and send
 * @param msg Optional error message (may be NULL)
 */
void send_error(HttpResponse res, int code, const char *msg) {
  char server[STRLEN];
  const char *err= get_status_string(code);

  reset_response(res);
  set_content_type(res, "text/html");
  set_status(res, code);
  out_print(res,
	   "<html><head><title>%d %s</title></head>"\
	   "<body bgcolor=#FFFFFF><h2>%s</h2>%s<p>"\
	   "<hr><a href='%s'><font size=-1>%s</font></a>"\
	   "</body></html>\r\n",
	    code, err, err, msg?msg:"", SERVER_URL, get_server(server, STRLEN));
	DEBUG("HttpRequest error: %s %d %s\n", SERVER_PROTOCOL, code, msg ? msg : err);
}


/**
 * Prints a string into the given HttpResponse output buffer. The
 * actual response to the client is done in the service function,
 * which will call the private function send_response.  Cervlets
 * should use this function (i.e. out_print) for sending a response,
 * and never use the HttpResponse Socket directly to send data.
 *
 * Despite the above warning, IF the HttpResponse.socket was used
 * directly by a cervlet THEN the cervlet MUST set the is_committed
 * flag in the HttpResponse object and is responsible for sending all
 * HTTP headers and content by itself.
 * @param res HttpResponse object
 * @param m A formated string to be sent to the client
 */
void out_print(HttpResponse res, const char *m, ...) {
  if(m) {
    char *buf;
    va_list ap;
    long need= 0;
    ssize_t have= 0;

    ASSERT(res);

    va_start(ap, m);
    buf= Util_formatString(m, ap, &need);
    va_end(ap);
    have= res->bufsize - res->bufused;
    if(have <= need) {
      res->bufsize += need + RES_STRLEN;
      res->outputbuffer= xresize(res->outputbuffer, res->bufsize);
    }
    memcpy(&res->outputbuffer[res->bufused], buf, need); 
    res->bufused+= need;
    FREE(buf);
  }
}


/* -------------------------------------------------------------- Properties */


/**
 * Adds a response header with the given name and value. If the header
 * had already been set the new value overwrites the previous one.
 * @param res HttpResponse object
 * @param name Header key name
 * @param value Header key value
 */
void set_header(HttpResponse res, const char *name, const char *value) {
  HttpHeader h= NULL;

  ASSERT(res);
  ASSERT(name);

  NEW(h);
  h->name= xstrdup(name);
  h->value= xstrdup(value);
  if(res->headers) {
    HttpHeader n, p;
    for( n= p= res->headers; p; n= p, p= p->next) {
      if(!strcasecmp(p->name, name)) {
	FREE(p->value);
	p->value= xstrdup(value);
	destroy_entry(h);
	return;
      }
    }
    n->next= h;
  } else {
    res->headers= h;
  }
}


/**
 * Sets the status code for the response
 * @param res HttpResponse object
 * @param code A HTTP status code <100-510>
 * @param msg The status code string message 
 */
void set_status(HttpResponse res, int code) {
  res->status= code;
  res->status_msg= get_status_string(code);
}


/**
 * Set the response content-type
 * @param res HttpResponse object
 * @param mime Mime content type, e.g. text/html
 */
void set_content_type(HttpResponse res, const char *mime) {
  set_header(res, "Content-Type", mime);
}


/**
 * Returns the value of the specified header
 * @param req HttpRequest object
 * @param name Header name to lookup the value for
 * @return The value of the specified header, NULL if not found
 */
const char *get_header(HttpRequest req, const char *name) {
  HttpHeader p;

  for(p= req->headers; p; p= p->next) {
    if(!strcasecmp(p->name, name)) {
      return (p->value);
    }
  }
  return NULL;
}


/**
 * Returns the value of the specified parameter
 * @param req HttpRequest object
 * @param name The request parameter key to lookup the value for
 * @return The value of the specified parameter, or NULL if not found
 */
const char *get_parameter(HttpRequest req, const char *name) {
  HttpParameter p;

  for(p= req->params; p; p= p->next) {
    if(!strcasecmp(p->name, name)) {
      return (p->value);
    }
  }
  return NULL;
}


/**
 * Returns a string containing all (extra) headers found in the
 * response.  The headers are newline separated in the returned
 * string.
 * @param res HttpResponse object
 * @return A String containing all headers set in the Response object
 */
char *get_headers(HttpResponse res) {
  HttpHeader p;
  char buf[RES_STRLEN];
  char *b= buf;

  *buf=0;
  for(p= res->headers; (((b-buf) + STRLEN) < RES_STRLEN) && p; p= p->next) {
    b+= snprintf(b, STRLEN,"%s: %s\r\n", p->name, p->value);
  }
  return buf[0]?xstrdup(buf):NULL;
}


/**
 * Lookup the corresponding HTTP status string for the given status
 * code
 * @param status A HTTP status code
 * @return A default status message for the specified HTTP status
 * code.
 */
const char *get_status_string(int status) {
  switch (status) {
  case SC_OK:
      return "OK";
  case SC_ACCEPTED:
      return "Accepted";
  case SC_BAD_GATEWAY:
      return "Bad Gateway";
  case SC_BAD_REQUEST:
      return "Bad Request";
  case SC_CONFLICT:
      return "Conflict";
  case SC_CONTINUE:
      return "Continue";
  case SC_CREATED:
      return "Created";
  case SC_EXPECTATION_FAILED:
      return "Expectation Failed";
  case SC_FORBIDDEN:
      return "Forbidden";
  case SC_GATEWAY_TIMEOUT:
      return "Gateway Timeout";
  case SC_GONE:
      return "Gone";
  case SC_VERSION_NOT_SUPPORTED:
      return "HTTP Version Not Supported";
  case SC_INTERNAL_SERVER_ERROR:
      return "Internal Server Error";
  case SC_LENGTH_REQUIRED:
      return "Length Required";
  case SC_METHOD_NOT_ALLOWED:
      return "Method Not Allowed";
  case SC_MOVED_PERMANENTLY:
      return "Moved Permanently";
  case SC_MOVED_TEMPORARILY:
      return "Moved Temporarily";
  case SC_MULTIPLE_CHOICES:
      return "Multiple Choices";
  case SC_NO_CONTENT:
      return "No Content";
  case SC_NON_AUTHORITATIVE:
      return "Non-Authoritative Information";
  case SC_NOT_ACCEPTABLE:
      return "Not Acceptable";
  case SC_NOT_FOUND:
      return "Not Found";
  case SC_NOT_IMPLEMENTED:
      return "Not Implemented";
  case SC_NOT_MODIFIED:
      return "Not Modified";
  case SC_PARTIAL_CONTENT:
      return "Partial Content";
  case SC_PAYMENT_REQUIRED:
      return "Payment Required";
  case SC_PRECONDITION_FAILED:
      return "Precondition Failed";
  case SC_PROXY_AUTHENTICATION_REQUIRED:
      return "Proxy Authentication Required";
  case SC_REQUEST_ENTITY_TOO_LARGE:
      return "Request Entity Too Large";
  case SC_REQUEST_TIMEOUT:
      return "Request Timeout";
  case SC_REQUEST_URI_TOO_LARGE:
      return "Request URI Too Large";
  case SC_RANGE_NOT_SATISFIABLE:
      return "Requested Range Not Satisfiable";
  case SC_RESET_CONTENT:
      return "Reset Content";
  case SC_SEE_OTHER:
      return "See Other";
  case SC_SERVICE_UNAVAILABLE:
      return "Service Unavailable";
  case SC_SWITCHING_PROTOCOLS:
      return "Switching Protocols";
  case SC_UNAUTHORIZED:
      return "Unauthorized";
  case SC_UNSUPPORTED_MEDIA_TYPE:
      return "Unsupported Media Type";
  case SC_USE_PROXY:
      return "Use Proxy";
  default: {
      return "Unknown HTTP status";
    } 
  }
}


/* ----------------------------------------------------------------- Private */


/**
 * Receives standard HTTP requests from a client socket and dispatches
 * them to the doXXX methods defined in a cervlet module.
 */
static void do_service(Socket_T s) {
  volatile HttpResponse res= create_HttpResponse(s);
  volatile HttpRequest req= create_HttpRequest(s);
  
  if(res && req) {
    if(is_authenticated(req, res)) {
      if(IS(req->method, METHOD_GET)) {
	Impl.doGet(req, res);
      } else if(IS(req->method, METHOD_POST)) {
	Impl.doPost(req, res);
      } else {
	send_error(res, SC_NOT_IMPLEMENTED, "Method not implemented");
      }
    }
    send_response(res);
  }
  done(req, res);
}


/**
 * Return a (RFC1123) Date string
 */
static char *get_date(char *result, int size) {
  time_t now;
  
  time(&now);
  if(strftime(result, size, DATEFMT, gmtime(&now)) <= 0) {
    *result= 0;
  }
  return result;
}


/**
 * Return this server name + version
 */
static char *get_server(char *result, int size) {
  snprintf(result, size, "%s %s", SERVER_NAME, Run.httpdsig?SERVER_VERSION:"");
  return result;
}


/**
 * Send the response to the client. If the response has already been
 * commited, this function does nothing.
 */
static void send_response(HttpResponse res) {
  Socket_T S= res->S;

  if(!res->is_committed) {
    char date[STRLEN];
    char server[STRLEN];
    char *headers= get_headers(res);

    res->is_committed= TRUE;
    get_date(date, STRLEN);
    get_server(server, STRLEN);
    socket_print(S, "%s %d %s\r\n", res->protocol, res->status,
		 res->status_msg);
    socket_print(S, "Date: %s\r\n", date);
    socket_print(S, "Server: %s\r\n", server);
    socket_print(S, "Content-Length: %d\r\n", res->bufused);
    socket_print(S, "Connection: close\r\n");
    if(headers)
	socket_print(S, "%s", headers);
    socket_print(S, "\r\n");
    if(res->bufused)
	socket_write(S, res->outputbuffer, res->bufused);
    FREE(headers);
  }
}


/* --------------------------------------------------------------- Factories */


/**
 * Returns a new HttpRequest object wrapping the client request
 */
static HttpRequest create_HttpRequest(Socket_T S) {
  HttpRequest req= NULL;
  char url[REQ_STRLEN];
  char line[REQ_STRLEN];
  char protocol[STRLEN]; 
  char method[REQ_STRLEN];

  if(socket_readln(S, line, REQ_STRLEN) == NULL) {
    internal_error(S, SC_BAD_REQUEST, "No request found");
    return NULL;
  }
  Util_chomp(line);
  if(sscanf(line, "%1023s %1023s HTTP/%3[1.0]", method, url, protocol) != 3) {
    internal_error(S, SC_BAD_REQUEST, "Cannot parse request");
    return NULL;
  }
  if(strlen(url) >= MAX_URL_LENGTH) {
    internal_error(S, SC_BAD_REQUEST, "[error] URL too long");
    return NULL;
  }
  NEW(req);
  req->S= S;
  Util_urlDecode(url);
  req->url= xstrdup(url);
  req->method= xstrdup(method);
  req->protocol= xstrdup(protocol); 
  create_headers(req);
  if(!create_parameters(req)) {
    destroy_HttpRequest(req);
    internal_error(S, SC_BAD_REQUEST, "Cannot parse Request parameters");
    return NULL;
  }
  return req;
}


/**
 * Returns a new HttpResponse object wrapping a default response. Use
 * the set_XXX methods to change the object.
 */
static HttpResponse create_HttpResponse(Socket_T S) {
  HttpResponse res= NULL;

  NEW(res);
  res->S= S;
  res->bufsize= 0;
  res->bufused= 0;
  res->status= SC_OK;
  res->outputbuffer= NULL;
  res->is_committed= FALSE;
  res->protocol= SERVER_PROTOCOL;
  res->status_msg= get_status_string(SC_OK);
  return res;
}


/**
 * Create HTTP headers for the given request
 */
static void create_headers(HttpRequest req) {
  Socket_T S;
  char *value;
  HttpHeader header= NULL;
  char line[REQ_STRLEN];

  S= req->S;
  while(1) {
    if(! socket_readln(S, line, sizeof(line)))
	break;
    if(!strcasecmp(line, "\r\n") || !strcasecmp(line, "\n"))
	break;
    if(NULL != (value= strchr(line, ':'))) {
      NEW(header);
      *value++= 0;
      Util_trim(line);
      Util_trim(value);
      Util_chomp(value);
      header->name= xstrdup(line);
      header->value= xstrdup(value);
      header->next= req->headers;
      req->headers= header;
    }
  }
}


/**
 * Create parameters for the given request. Returns FALSE if an error
 * occurs.
 */
static int create_parameters(HttpRequest req) {
  char query_string[REQ_STRLEN]= {0};

  if(IS(req->method, METHOD_POST) && get_header(req, "Content-Length")) {
    int n;
    int len; 
    Socket_T S = req->S;
    const char *cl = get_header(req, "Content-Length");
    if(! cl || sscanf(cl, "%d", &len) != 1) {
      return FALSE;
    }
    if(len < 0 || len >= REQ_STRLEN)
      return FALSE;
    if(len==0)
      return TRUE;
    if(((n= socket_read(S, query_string, len)) <= 0) || (n != len)) {
      return FALSE;
    }
    query_string[n]= 0;
  } else if(IS(req->method, METHOD_GET)) {
    char *p;
    if(NULL != (p= strchr(req->url, '?'))) {
      *p++= 0;
      strncpy(query_string, p, sizeof(query_string) - 1);
      query_string[sizeof(query_string) - 1] = 0;
    }
  }
  if(*query_string) {
    char *p;
    if(NULL != (p= strchr(query_string, '/'))) {
      *p++= 0;
      req->pathinfo= xstrdup(p);
    }
    req->params= parse_parameters(query_string);
  }
  return TRUE;
}


/* ----------------------------------------------------------------- Cleanup */


/**
 * Clear the response output buffer and headers
 */
static void reset_response(HttpResponse res) {
  if(res->headers)
    destroy_entry(res->headers);
  memset(res->outputbuffer, 0, res->bufsize);
  res->bufused= 0;
  res->headers= NULL; /* Release Pragma */
}


/**
 * Finalize the request and response object.
 */
static void done(HttpRequest req, HttpResponse res) {
  destroy_HttpRequest(req);
  destroy_HttpResponse(res);
}


/**
 * Free a HttpRequest object
 */
static void destroy_HttpRequest(HttpRequest req) {
  if(req) {
    FREE(req->method);
    FREE(req->url); 
    FREE(req->pathinfo);
    FREE(req->protocol);
    FREE(req->remote_user);
    if(req->headers)
      destroy_entry(req->headers);
    if(req->params)
      destroy_entry(req->params);
    FREE(req);
  }
}


/**
 * Free a HttpResponse object
 */
static void destroy_HttpResponse(HttpResponse res) {
  if(res) {
    FREE(res->outputbuffer);
    if(res->headers) 
      destroy_entry(res->headers);
    FREE(res);
  }
}


/**
 * Free a (linked list of) http entry object(s). Both HttpHeader and
 * HttpParameter are of this type.
 */
static void destroy_entry(void *p) {
  struct entry *h= p; 
  
  if(h->next) {
    destroy_entry(h->next);
  }
  FREE(h->name);
  FREE(h->value);
  FREE(h);
}


/* ----------------------------------------------------- Checkers/Validators */


/**
 * Do Basic Authentication if this auth. style is allowed. 
 */
static int is_authenticated(HttpRequest req, HttpResponse res) {
  if(Run.credentials!=NULL) {
    if(! basic_authenticate(req)) {
      send_error(res, SC_UNAUTHORIZED,
		 "You are <b>not</b> authorized to access <i>monit</i>. "
		 "Either you supplied the wrong credentials (e.g. bad "
		 "password), or your browser doesn't understand how to supply "
		 "the credentials required");
      set_header(res, "WWW-Authenticate", "Basic realm=\"monit\"");
      return FALSE;
    }
  }
  return TRUE;
}


/**
 * Authenticate the basic-credentials (uname/password) submitted by
 * the user.
 */
static int basic_authenticate(HttpRequest req) {
  int n;
  char *password;
  char buf[STRLEN];
  char uname[STRLEN];
  const char *credentials= get_header(req, "Authorization");

  if(! (credentials && Util_startsWith(credentials, "Basic "))) {
    return FALSE;
  }
  strncpy(buf, &credentials[6], sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = 0;
  if((n= decode_base64((unsigned char*)uname, buf))<=0) {
    return FALSE;
  }
  uname[n]= 0;
  password= strchr(uname, ':');
  if(password==NULL) {
    return FALSE;
  }
  *password++= 0;
  if(*uname==0 || *password==0) {
    return FALSE;
  }
  /* Check if user exist */
  if(NULL==Util_getUserCredentials(uname)) {
    LogError("Warning: Client '%s' supplied unknown user '%s'"
	" accessing monit httpd\n", socket_get_remote_host(req->S), uname); 
    return FALSE;
  }
  /* Check if user has supplied the right password */
  if(! Util_checkCredentials(uname,  password)) {
    LogError("Warning: Client '%s' supplied wrong password for user '%s'"
	" accessing monit httpd\n", socket_get_remote_host(req->S), uname); 
    return FALSE;
  }
  req->remote_user= xstrdup(uname);
  return TRUE;
}


/* --------------------------------------------------------------- Utilities */


/**
 * Send an error message to the client. This is a helper function,
 * used internal if the service function fails to setup the framework
 * properly; i.e. with a valid HttpRequest and a valid HttpResponse.
 */
static void internal_error(Socket_T S, int status, char *msg) {
  char date[STRLEN];
  char server[STRLEN];
  const char *status_msg= get_status_string(status);
  
  get_date(date, STRLEN);
  get_server(server, STRLEN);
  socket_print(S, 
	       "%s %d %s\r\n"
	       "Date: %s\r\n"
	       "Server: %s\r\n"
	       "Content-Type: text/html\r\n"
	       "Connection: close\r\n"
	       "\r\n"
	       "<html><head><title>%s</title></head>"
	       "<body bgcolor=#FFFFFF><h2>%s</h2>%s<p>"
	       "<hr><a href='%s'><font size=-1>%s</font></a>"
	       "</body></html>\r\n",
	       SERVER_PROTOCOL, status, status_msg, date, server,
	       status_msg, status_msg, msg, SERVER_URL, server);
  DEBUG("HttpRequest error: %s %d %s\n", SERVER_PROTOCOL, status, msg ? msg : status_msg);
}


/**
 * Parse request parameters from the given query string and return a
 * linked list of HttpParameters
 */
static HttpParameter parse_parameters(char *query_string) {
#define KEY 1
#define VALUE 2
  int token;
  int cursor= 0;
  char *key= NULL;
  char *value= NULL;
  HttpParameter head= NULL;

  while((token= get_next_token(query_string, &cursor, &value))) {
    if(token==KEY)
      key= value;
    else if(token==VALUE) {
      HttpParameter p= NULL;
      if(!key) goto error;
      NEW(p);
      p->name= key;
      p->value= value;
      p->next= head;
      head= p;
      key= NULL;
    }
  }
  return head;
error:
  FREE(key);
  FREE(value);
  if ( head != NULL ) {
    destroy_entry(head);
  }
  return NULL;
}


/**
 * A mini-scanner for tokenizing a query string
 */
static int get_next_token(char *s, int *cursor, char **r) {
  int i= *cursor;

  while(s[*cursor]) {
    if(s[*cursor+1]=='=') {
      *cursor+= 1;
      *r= xstrndup(&s[i], (*cursor-i));
      return KEY;
    } 
    if(s[*cursor]=='=') {
      while(s[*cursor] && s[*cursor]!='&') *cursor+= 1;
      if(s[*cursor]=='&') {
	*r= xstrndup(&s[i+1], (*cursor-i)-1);
	*cursor+= 1;
      }  else
	*r= xstrndup(&s[i+1], (*cursor-i));
      return VALUE;
    }
    *cursor+= 1;
  }
  return FALSE;
}
