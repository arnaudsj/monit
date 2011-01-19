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


#ifndef PROCESSOR_H
#define PROCESSOR_H

#include <config.h>
#include <stdio.h>

#include "monitor.h"
#include "net.h"
#include "socket.h"
#include "httpstatus.h"

/* Server masquerade */
#define SERVER_NAME        "monit" 
#define SERVER_VERSION     VERSION
#define SERVER_URL         "http://mmonit.com/monit/"
#define SERVER_PROTOCOL    "HTTP/1.0"
#define DATEFMT             "%a, %d %b %Y %H:%M:%S GMT"

/* Protocol methods supported */
#define METHOD_GET         "GET"
#define METHOD_POST        "POST"


/* Initial buffer sizes */
#define STRLEN             256
#define REQ_STRLEN         1024
#define RES_STRLEN         2048
#define MAX_URL_LENGTH     512

/* Request timeout in seconds */
#define REQUEST_TIMEOUT    30 

#define TRUE               1
#define FALSE              0

struct entry {
  char *name;
  char *value;
  /* For internal use */
  struct entry *next;
};
typedef struct entry *HttpHeader;
typedef struct entry *HttpParameter;

typedef struct request {
  char *url;
  Socket_T S;
  char *method;
  char *protocol;
  char *pathinfo;
  char *remote_user;
  HttpHeader headers;
  ssl_connection *ssl;
  HttpParameter params;
} *HttpRequest;

typedef struct response {
  int status;
  Socket_T S;
  const char *protocol;
  size_t bufsize;
  size_t bufused;
  int is_committed;
  HttpHeader headers;
  ssl_connection *ssl;
  const char *status_msg; 
  unsigned char *outputbuffer;
} *HttpResponse;


struct  ServiceImpl {
  void(*doGet)(HttpRequest, HttpResponse);
  void(*doPost)(HttpRequest, HttpResponse);
};

/*
 * An object for implementors of the service functions; doGet and
 * doPost. Implementing modules i.e. CERVLETS, must implement the
 * doGet and doPost functions and the engine will call the add_Impl
 * function to setup the callback to these functions.
 */
struct ServiceImpl Impl;

/* Public prototypes */
void *http_processor(Socket_T);
char *get_headers(HttpResponse res);
void set_status(HttpResponse res, int status);
const char *get_status_string(int status_code);
void add_Impl(void(*doGet)(HttpRequest, HttpResponse), void(*doPost)(HttpRequest, HttpResponse));
void out_print(HttpResponse res,  const char *, ...);
void set_content_type(HttpResponse res, const char *mime);
const char *get_header(HttpRequest req, const char *header_name);
void send_error(HttpResponse, int status, const char *message);
const char *get_parameter(HttpRequest req, const char *parameter_name);
void set_header(HttpResponse res, const char *name, const char *value);

#endif
