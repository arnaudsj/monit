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


%{
  
/*
 * DESCRIPTION
 *   Simple context-free grammar for parsing the control file. 
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Olivier Beyssac, <ob@r14.freenix.org>
 *  @author Kianusch Sayah Karadji <kianusch.sayah.karadji@sk-tech.net>
 *  @author Martin Pala <martinp@tildeslash.com>
 *  @author Christian Hopp <chopp@iei.tu-clausthal.de>
 *  @author Rory Toma <rory@digeo.com>
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

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif 

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif 

#ifdef HAVE_GRP_H
#include <grp.h>
#endif 
  
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
  
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
  
#ifdef HAVE_TIME_H
#include <time.h>
#endif
  
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_ASM_PARAM_H
#include <asm/param.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifndef HAVE_SOL_IP
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_IP_ICMP_H
#include <netinet/ip_icmp.h>
#endif

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif
  
#include "net.h"
#include "monitor.h"
#include "protocol.h"
#include "engine.h"
#include "alert.h"
#include "process.h"
#include "ssl.h"
#include "device.h"


/* ------------------------------------------------------------- Definitions */

  struct IHavePrecedence {
    int daemon;
    int logfile;
    int pidfile;
  }; 

  struct myrate {
    unsigned count;
    unsigned cycles;
  }; 

  /* yacc interface */
  void  yyerror(const char *,...);
  void  yyerror2(const char *,...);
  void  yywarning(const char *,...);
  void  yywarning2(const char *,...);

  /* lexer interface */
  int yylex(void);
  extern FILE *yyin;
  extern int lineno;
  extern int arglineno;
  extern char *yytext;
  extern char *argyytext;
  extern char *currentfile;
  extern char *argcurrentfile;
  extern int buffer_stack_ptr;

  /* Local variables */
  static int cfg_errflag = FALSE;
  static Service_T tail = NULL;
  static Service_T current = NULL;
  static unsigned int eventset;
  static Request_T urlrequest = NULL;
  static Command_T command = NULL;
  static Command_T command1 = NULL;
  static Command_T command2 = NULL;
  static Service_T depend_list = NULL;
  static struct mygid gidset;
  static struct myuid uidset;
  static struct myperm permset;
  static struct mysize sizeset;
  static struct mymatch matchset;
  static struct myicmp icmpset;
  static struct mymail mailset;
  static struct myport portset;
  static struct mymailserver mailserverset;
  static struct myfilesystem filesystemset;
  static struct myresource resourceset;
  static struct mychecksum checksumset;
  static struct mytimestamp timestampset;
  static struct myactionrate actionrateset;
  static struct IHavePrecedence ihp = {FALSE, FALSE, FALSE};
  static struct myrate rate1 = {1, 1};
  static struct myrate rate2 = {1, 1};
  static char * htpasswd_file = NULL;
  static int    digesttype = DIGEST_CLEARTEXT;
  static int    hassystem = FALSE;

#define BITMAP_MAX (sizeof(long long) * 8)

  
/* -------------------------------------------------------------- Prototypes */

  static void  preparse();
  static void  postparse();
  static void  addservice(Service_T);
  static void  addmail(char *, Mail_T, Mail_T *, unsigned int, unsigned int);
  static void  createservice(int, char *, char *, int (*)(Service_T));
  static void  adddependant(char *);
  static void  addservicegroup(char *);
  static void  addport(Port_T);
  static void  addresource(Resource_T);
  static void  addtimestamp(Timestamp_T, int);
  static void  addactionrate(ActionRate_T);
  static void  addsize(Size_T);
  static void  addfilesystem(Filesystem_T);
  static void  addicmp(Icmp_T);
  static void *addprotocol(int);
  static void  addgeneric(Port_T, char*, char*);
  static void  addcommand(int, unsigned);
  static void  addargument(char *);
  static void  addmmonit(URL_T, int, int, char *);
  static void  addmailserver(MailServer_T);
  static int   addcredentials(char *, char *, int, int);
#ifdef HAVE_LIBPAM
  static void  addpamauth(char *, int);
#endif
  static void  addhtpasswdentry(char *, char *, int);
  static uid_t get_uid(char *, uid_t);
  static gid_t get_gid(char *, gid_t);
  static void  addchecksum(Checksum_T);
  static void  addperm(Perm_T);
  static void  addmatch(Match_T, int, int);
  static void  addmatchpath(Match_T, int);
  static void  adduid(Uid_T);
  static void  addgid(Gid_T);
  static void  addeuid(uid_t);
  static void  addegid(gid_t);
  static void  addeventaction(EventAction_T *, int, int);
  static void  seteventaction(EventAction_T *, int, int);
  static void  prepare_urlrequest(URL_T U);
  static void  seturlrequest(int, char *);
  static void  setlogfile(char *);
  static void  setpidfile(char *);
  static void  reset_mailset();
  static void  reset_mailserverset();
  static void  reset_portset();
  static void  reset_resourceset();
  static void  reset_timestampset();
  static void  reset_actionrateset();
  static void  reset_sizeset();
  static void  reset_checksumset();
  static void  reset_permset();
  static void  reset_uidset();
  static void  reset_gidset();
  static void  reset_filesystemset();
  static void  reset_icmpset();
  static void  reset_rateset();
  static void  check_name(char *);
  static void  check_every(int);
  static int   check_perm(int);
  static void  check_hostname (char *);
  static void  check_exec(char *);
  static int   cleanup_hash_string(char *);
  static void  check_depend();
  static void  setsyslog(char *);
  static Command_T copycommand(Command_T);
  static int verifyMaxForward(int);  

%}

%union {
  URL_T url;
  float real;
  int   number;
  char *string;
}

%token IF ELSE THEN OR FAILED
%token SET LOGFILE FACILITY DAEMON SYSLOG MAILSERVER HTTPD ALLOW ADDRESS INIT
%token READONLY CLEARTEXT MD5HASH SHA1HASH CRYPT DELAY
%token PEMFILE ENABLE DISABLE HTTPDSSL CLIENTPEMFILE ALLOWSELFCERTIFICATION
%token IDFILE STATEFILE SEND EXPECT EXPECTBUFFER CYCLE COUNT REMINDER
%token PIDFILE START STOP PATHTOK
%token HOST HOSTNAME PORT TYPE UDP TCP TCPSSL PROTOCOL CONNECTION
%token ALERT NOALERT MAILFORMAT UNIXSOCKET SIGNATURE
%token TIMEOUT RESTART CHECKSUM EVERY 
%token DEFAULT HTTP APACHESTATUS FTP SMTP POP IMAP CLAMAV NNTP NTP3 MYSQL DNS
%token SSH DWP LDAP2 LDAP3 RDATE RSYNC TNS PGSQL POSTFIXPOLICY SIP LMTP GPS RADIUS MEMCACHE
%token <string> STRING PATH MAILADDR MAILFROM MAILREPLYTO MAILSUBJECT
%token <string> MAILBODY SERVICENAME STRINGNAME
%token <number> NUMBER PERCENT LOGLIMIT CLOSELIMIT DNSLIMIT KEEPALIVELIMIT 
%token <number> REPLYLIMIT REQUESTLIMIT STARTLIMIT WAITLIMIT GRACEFULLIMIT 
%token <number> CLEANUPLIMIT 
%token <real> REAL
%token CHECKPROC CHECKFILESYS CHECKFILE CHECKDIR CHECKHOST CHECKSYSTEM CHECKFIFO CHECKSTATUS
%token CHILDREN SYSTEM
%token RESOURCE MEMORY TOTALMEMORY LOADAVG1 LOADAVG5 LOADAVG15 SWAP
%token MODE ACTIVE PASSIVE MANUAL CPU TOTALCPU CPUUSER CPUSYSTEM CPUWAIT
%token GROUP REQUEST DEPENDS BASEDIR SLOT EVENTQUEUE SECRET HOSTHEADER
%token UID GID MMONIT INSTANCE USERNAME PASSWORD
%token TIMESTAMP CHANGED SECOND MINUTE HOUR DAY
%token SSLAUTO SSLV2 SSLV3 TLSV1 CERTMD5
%token BYTE KILOBYTE MEGABYTE GIGABYTE
%token INODE SPACE PERMISSION SIZE MATCH NOT IGNORE ACTION
%token EXEC UNMONITOR ICMP ICMPECHO NONEXIST EXIST INVALID DATA RECOVERED PASSED SUCCEEDED
%token URL CONTENT PID PPID FSFLAG
%token REGISTER CREDENTIALS 
%token <url> URLOBJECT
%token <string> TARGET
%token <number> MAXFORWARD
%token FIPS

%left GREATER LESS EQUAL NOTEQUAL


%%
cfgfile         : /* EMPTY */
                | statement_list
                ;

statement_list  : statement
                | statement_list statement
                ;

statement       : setalert
                | setdaemon
                | setlog
                | seteventqueue
                | setmmonits
                | setmailservers
                | setmailformat
                | sethttpd
                | setpid
                | setidfile
                | setstatefile
                | setexpectbuffer
                | setinit
                | setfips
                | checkproc optproclist
                | checkfile optfilelist
                | checkfilesys optfilesyslist
                | checkdir optdirlist
                | checkhost opthostlist
                | checksystem optsystemlist
                | checkfifo optfifolist
                | checkstatus optstatuslist
                ;

optproclist     : /* EMPTY */
                | optproclist optproc
                ;

optproc         : start
                | stop
                | exist
                | pid
                | ppid
                | connection
                | connectionunix
                | actionrate
                | alert
                | every
                | mode
                | group
                | depend
                | resourceprocess
                ;

optfilelist      : /* EMPTY */
                | optfilelist optfile
                ;

optfile         : start
                | stop
                | exist
                | timestamp
                | actionrate
                | every
                | alert
                | permission
                | uid
                | gid
                | checksum
                | size
                | match
                | mode
                | group
                | depend
                ;

optfilesyslist  : /* EMPTY */
                | optfilesyslist optfilesys
                ;

optfilesys      : start
                | stop
                | exist
                | actionrate
                | every
                | alert
                | permission
                | uid
                | gid
                | mode
                | group
                | depend
                | inode
                | space
                | fsflag
                ;

optdirlist      : /* EMPTY */
                | optdirlist optdir
                ;

optdir          : start
                | stop
                | exist
                | timestamp
                | actionrate
                | every
                | alert
                | permission
                | uid
                | gid
                | mode
                | group
                | depend
                ;

opthostlist     : opthost
                | opthostlist opthost
                ;

opthost         : start
                | stop
                | exist
                | connection
                | icmp
                | actionrate
                | alert
                | every
                | mode
                | group
                | depend
                ;

optsystemlist   : /* EMPTY */
                | optsystemlist optsystem
                ;

optsystem       : start
                | stop
                | actionrate
                | alert
                | every
                | group
                | depend
                | resourcesystem
                ;

optfifolist     : /* EMPTY */
                | optfifolist optfifo
                ;

optfifo         : start
                | stop
                | exist
                | timestamp
                | actionrate
                | every
                | alert
                | permission
                | uid
                | gid
                | mode
                | group
                | depend
                ;

optstatuslist   : /* EMPTY */
                | optstatuslist optstatus
                ;
               
optstatus       : actionrate
                | exist
                | alert
                | every
                | group
                | depend
                ; 

setalert        : SET alertmail '{' eventoptionlist '}' formatlist reminder {
                    addmail($<string>2, &mailset, &Run.maillist, eventset, $<number>7);
                  }
                | SET alertmail formatlist reminder {
                    addmail($<string>2, &mailset, &Run.maillist, Event_All, $<number>4);
                  }
                | SET alertmail NOT '{' eventoptionlist '}' formatlist reminder {
                   addmail($<string>2, &mailset, &Run.maillist, ~eventset, $<number>8);
                  }
                ;

setdaemon       : SET DAEMON NUMBER startdelay {
                    if (!Run.isdaemon || ihp.daemon) {
                      ihp.daemon     = TRUE;
                      Run.isdaemon   = TRUE;
                      Run.polltime   = $3;
                      Run.startdelay = $<number>4;
                    }
                  }
                ;

startdelay      : /* EMPTY */        { $<number>$ = START_DELAY; }
                | START DELAY NUMBER { $<number>$ = $3; }
                ;

setexpectbuffer : SET EXPECTBUFFER NUMBER unit {
                    Run.expectbuffer = $3 * $<number>4;
                  }
                ;

setinit         : SET INIT {
                    Run.init = TRUE;
                  }
                ;

setfips         : SET FIPS {
                  #ifdef OPENSSL_FIPS
                    Run.fipsEnabled = TRUE;
                  #endif
                  }
                ;

setlog          : SET LOGFILE PATH   {
                   if (!Run.logfile || ihp.logfile) {
                     ihp.logfile = TRUE;
                     setlogfile($3);
                     Run.use_syslog = FALSE;
                     Run.dolog =TRUE;
                   }
                  }
                | SET LOGFILE SYSLOG {
                    setsyslog(NULL);
                  }
                | SET LOGFILE SYSLOG FACILITY STRING {
                    setsyslog($5); FREE($5);
                  }
                ;

seteventqueue   : SET EVENTQUEUE BASEDIR PATH {
                    Run.eventlist_dir = $4;
                  }
                | SET EVENTQUEUE BASEDIR PATH SLOT NUMBER {
                    Run.eventlist_dir = $4;
                    Run.eventlist_slots = $6;
                  }
                | SET EVENTQUEUE SLOT NUMBER {
                    Run.eventlist_dir = xstrdup(MYEVENTLISTBASE);
                    Run.eventlist_slots = $4;
                  }
                ;

setidfile       : SET IDFILE PATH {
                    Run.idfile = $3;
                  }
                ;

setstatefile    : SET STATEFILE PATH {
                    Run.statefile = $3;
                  }
                ;

setpid          : SET PIDFILE PATH {
                   if (!Run.pidfile || ihp.pidfile) {
                     ihp.pidfile = TRUE;
                     setpidfile($3);
                   }
                 }
                ;

setmmonits      : SET MMONIT mmonitlist
                ;

mmonitlist      : mmonit credentials
                | mmonitlist mmonit credentials
                ;

mmonit          : URLOBJECT nettimeout sslversion certmd5 {
                    check_hostname(($<url>1)->hostname);
                    addmmonit($<url>1, $<number>2, $<number>3, $<string>4); 
                  }
                ;

credentials     : /* EMPTY */
                | REGISTER CREDENTIALS {
                    Run.dommonitcredentials = FALSE;
                  }
                ;

setmailservers  : SET MAILSERVER mailserverlist nettimeout hostname {
                   Run.mailserver_timeout = $<number>4;
                   Run.mail_hostname = $<string>5;
                  }
                ;

setmailformat   : SET MAILFORMAT '{' formatoptionlist '}' {
                   Run.MailFormat.from    = mailset.from    ?  mailset.from    : xstrdup(ALERT_FROM);
                   Run.MailFormat.replyto = mailset.replyto ?  mailset.replyto : NULL;
                   Run.MailFormat.subject = mailset.subject ?  mailset.subject : xstrdup(ALERT_SUBJECT);
                   Run.MailFormat.message = mailset.message ?  mailset.message : xstrdup(ALERT_MESSAGE);
                   reset_mailset();
                 }
                ;

sethttpd        : SET HTTPD PORT NUMBER httpdlist {
                   Run.dohttpd = TRUE;
                   Run.httpdport = $4;
                 }
                ;

mailserverlist  : mailserver
                | mailserverlist mailserver
                ;

mailserver      : STRING username password sslversion certmd5 {
                    /* Restore the current text overriden by lookahead */
                    FREE(argyytext);
                    argyytext = xstrdup($1);

                    check_hostname($1);
                    mailserverset.host = $1;
                    mailserverset.username = $<string>2;
                    mailserverset.password = $<string>3;
                    mailserverset.ssl.version = $<number>4;
                    if (mailserverset.ssl.version != SSL_VERSION_NONE) {
                      mailserverset.ssl.use_ssl = TRUE;
                      if (mailserverset.ssl.version == SSL_VERSION_SSLV2 ||
                         mailserverset.ssl.version == SSL_VERSION_SSLV3)
                         mailserverset.port = PORT_SMTPS;
                      mailserverset.ssl.certmd5 = $<string>5;
                    }
                    addmailserver(&mailserverset);
                  }
                | STRING PORT NUMBER username password sslversion certmd5 {
                    /* Restore the current text overriden by lookahead */
                    FREE(argyytext);
                    argyytext = xstrdup($1);

                    check_hostname($1);
                    mailserverset.host = $1;
                    mailserverset.port = $<number>3;
                    mailserverset.username = $<string>4;
                    mailserverset.password = $<string>5;
                    mailserverset.ssl.version = $<number>6;
                    if (mailserverset.ssl.version != SSL_VERSION_NONE) {
                      mailserverset.ssl.use_ssl = TRUE;
                      mailserverset.ssl.certmd5 = $<string>7;
                    }
                    addmailserver(&mailserverset);
                  }
                ;

httpdlist       : /* EMPTY */
                | httpdlist httpdoption
                ; 

httpdoption     : ssl
                | signature
                | bindaddress
                | allow
                ;

ssl             : ssldisable { Run.httpdssl = FALSE; }
                | sslenable pemfile clientpemfile allowselfcert { 
                    Run.httpdssl = TRUE;                   
                    if (!have_ssl())
                      yyerror("SSL is not supported");
                  }
                ;

sslenable       : HTTPDSSL
                | HTTPDSSL ENABLE
                | ENABLE HTTPDSSL
                ;

ssldisable      : HTTPDSSL DISABLE
                | DISABLE HTTPDSSL
                | ssldisable PEMFILE PATH { FREE($3); }
                | ssldisable CLIENTPEMFILE PATH { FREE($3); }
                | ssldisable ALLOWSELFCERTIFICATION
                ;

signature       : sigenable  { Run.httpdsig = TRUE; }
                | sigdisable { Run.httpdsig = FALSE; }
                ;

sigenable       : SIGNATURE ENABLE
                | ENABLE SIGNATURE
                ;

sigdisable      : SIGNATURE DISABLE
                | DISABLE SIGNATURE
                ;

bindaddress     : ADDRESS STRING { Run.bind_addr = $2; }
                ;

pemfile         : PEMFILE PATH {
                    Run.httpsslpem = $2;
                    if (!File_checkStat(Run.httpsslpem, "SSL server PEM file", S_IRWXU))
                      yyerror2("SSL server PEM file has too loose permissions");
                  }
                ;

clientpemfile   : /* EMPTY */ 
                | CLIENTPEMFILE PATH {
                    Run.httpsslclientpem = $2; 
                    Run.clientssl = TRUE;
                    if (!File_checkStat(Run.httpsslclientpem, "SSL client PEM file", S_IRWXU | S_IRGRP | S_IROTH))
                      yyerror2("SSL client PEM file has too loose permissions");
                  }
                ;

allowselfcert   : /* EMPTY */ { 
                   Run.allowselfcert = FALSE; 
                   config_ssl(Run.allowselfcert); 
                 }
                | ALLOWSELFCERTIFICATION {   
                    Run.allowselfcert = TRUE;
                    config_ssl(Run.allowselfcert); 
                  }
                ;

allow           : ALLOW STRING':'STRING readonly {
                    addcredentials($2,$4, DIGEST_CLEARTEXT, $<number>5);
                  }
                | ALLOW '@'STRING readonly {
#ifdef HAVE_LIBPAM
                    addpamauth($3, $<number>4);
#else
                    yyerror("PAM is not supported");
                    FREE($3);
#endif
                  }
                | ALLOW PATH {
                    addhtpasswdentry($2, NULL, DIGEST_CLEARTEXT);
                    FREE($2);
                  }
                | ALLOW CLEARTEXT PATH {
                    addhtpasswdentry($3, NULL, DIGEST_CLEARTEXT);
                    FREE($3);
                  }
                | ALLOW MD5HASH PATH {
                    addhtpasswdentry($3, NULL, DIGEST_MD5);
                    FREE($3);
                  }
                | ALLOW CRYPT PATH {
                    addhtpasswdentry($3, NULL, DIGEST_CRYPT);
                    FREE($3);
                  }
                | ALLOW PATH {
                    htpasswd_file = $2;
                    digesttype = CLEARTEXT;
                  }
                  allowuserlist {
                    FREE(htpasswd_file);
                  }
                | ALLOW CLEARTEXT PATH {
                    htpasswd_file = $3;
                    digesttype = DIGEST_CLEARTEXT;
                  }
                  allowuserlist {
                    FREE(htpasswd_file);
                  }
                | ALLOW MD5HASH PATH {
                    htpasswd_file = $3;
                    digesttype = DIGEST_MD5;
                  }
                  allowuserlist {
                    FREE(htpasswd_file);
                  }
                | ALLOW CRYPT PATH {
                    htpasswd_file = $3;
                    digesttype = DIGEST_CRYPT;
                  }
                  allowuserlist {
                    FREE(htpasswd_file);
                  }
                | ALLOW STRING {
                    if (! (add_net_allow($2) || add_host_allow($2))) {
                      yyerror2("erroneous network or host identifier %s", $2); 
                    }
                    FREE($2);
                  }
                ;

allowuserlist   : allowuser
                | allowuserlist allowuser
                ;

allowuser       : STRING { addhtpasswdentry(htpasswd_file, $1, digesttype);
                           FREE($1); }
                ;

readonly        : /* EMPTY */ { $<number>$ = FALSE; }
                | READONLY { $<number>$ = TRUE; }
                ;

checkproc       : CHECKPROC SERVICENAME PIDFILE PATH {
                    createservice(TYPE_PROCESS, $<string>2, $4, check_process);
                  }
                | CHECKPROC SERVICENAME PATHTOK PATH {
                    createservice(TYPE_PROCESS, $<string>2, $4, check_process);
                  }
                | CHECKPROC SERVICENAME MATCH STRING {
                    createservice(TYPE_PROCESS, $<string>2, $4, check_process);
                    matchset.ignore = FALSE;
                    matchset.match_path = NULL;
                    matchset.match_string = xstrdup($4);
                    addmatch(&matchset, ACTION_IGNORE, 0);
                  }
                | CHECKPROC SERVICENAME MATCH PATH {
                    createservice(TYPE_PROCESS, $<string>2, $4, check_process);
                    matchset.ignore = FALSE;
                    matchset.match_path = NULL;
                    matchset.match_string = xstrdup($4);
                    addmatch(&matchset, ACTION_IGNORE, 0);
                  }
                ;

checkfile       : CHECKFILE SERVICENAME PATHTOK PATH {
                    createservice(TYPE_FILE, $<string>2, $4, check_file);
                  }
                ;

checkfilesys    : CHECKFILESYS SERVICENAME PATHTOK PATH {
                    createservice(TYPE_FILESYSTEM, $<string>2, $4, check_filesystem);
                  }
                ;

checkdir        : CHECKDIR SERVICENAME PATHTOK PATH {
                    createservice(TYPE_DIRECTORY, $<string>2, $4, check_directory);
                  }
                ;

checkhost       : CHECKHOST SERVICENAME ADDRESS STRING {
                    check_hostname($4); 
                    createservice(TYPE_HOST, $<string>2, $4, check_remote_host);
                  }
                ;

checksystem     : CHECKSYSTEM SERVICENAME {
                    createservice(TYPE_SYSTEM, $<string>2, xstrdup(""), check_system);
                    hassystem = TRUE;
                  }
                ;

checkfifo       : CHECKFIFO SERVICENAME PATHTOK PATH {
                    createservice(TYPE_FIFO, $<string>2, $4, check_fifo);
                  }
                ;

checkstatus     : CHECKSTATUS SERVICENAME PATHTOK PATH {
                    createservice(TYPE_STATUS, $<string>2, $4, check_status);
                  }
                ;

start           : START argumentlist exectimeout {
                    addcommand(START, $<number>3);
                  }
                | START argumentlist useroptionlist exectimeout {
                    addcommand(START, $<number>4);
                  }
                ;

stop            : STOP argumentlist exectimeout {
                    addcommand(STOP, $<number>3);
                  }
                | STOP argumentlist useroptionlist exectimeout {
                    addcommand(STOP, $<number>4);
                  }
                ;

argumentlist    : argument
                | argumentlist argument
                ;

useroptionlist  : useroption
                | useroptionlist useroption
                ;

argument        : STRING { addargument($1); }
                | PATH   { addargument($1); }
                ;

useroption      : UID STRING { addeuid( get_uid($2, 0) ); FREE($2); }
                | GID STRING { addegid( get_gid($2, 0) ); FREE($2); }
                | UID NUMBER { addeuid( get_uid(NULL, $2) ); }
                | GID NUMBER { addegid( get_gid(NULL, $2) ); }
                ;

username        : /* EMPTY */     { $<string>$ = NULL; }
                | USERNAME MAILADDR { $<string>$ = $2; }
                | USERNAME STRING { $<string>$ = $2; }
                ;

password        : /* EMPTY */     { $<string>$ = NULL; }
                | PASSWORD STRING { $<string>$ = $2; }
                ;

hostname        : /* EMPTY */     { $<string>$ = NULL; }
                | HOSTNAME STRING { $<string>$ = $2; }
                ;

connection      : IF FAILED host port type protocol nettimeout rate1
                  THEN action1 recovery {
                    portset.timeout = $<number>7;
                    addeventaction(&(portset).action, $<number>10, $<number>11);
                    addport(&portset);
                  }
                | IF FAILED URL URLOBJECT urloption nettimeout rate1
                  THEN action1 recovery { 
                    prepare_urlrequest($<url>4);
                    portset.timeout = $<number>6;
                    addeventaction(&(portset).action, $<number>9, $<number>10);
                    addport(&portset);
                  }
                ;

connectionunix  : IF FAILED unixsocket type protocol nettimeout rate1
                  THEN action1 recovery {
                   portset.timeout = $<number>6;
                   addeventaction(&(portset).action, $<number>9, $<number>10);
                   addport(&portset);
                  }
                ;

icmp            : IF FAILED ICMP icmptype icmpcount nettimeout rate1
                  THEN action1 recovery {
                   icmpset.type = $<number>4;
                   icmpset.count = $<number>5;
                   icmpset.timeout = $<number>6;
                   addeventaction(&(icmpset).action, $<number>9, $<number>10);
                   addicmp(&icmpset);
                  }
                ;

host            : /* EMPTY */ {
                    if (current->type == TYPE_HOST)
                      portset.hostname = xstrdup(current->path);
                    else
                      portset.hostname = xstrdup(LOCALHOST);
                  }
                | HOST STRING { check_hostname($2); portset.hostname = $2; }
		;

port            : PORT NUMBER { portset.port = $2; portset.family = AF_INET; }
                ;

unixsocket      : UNIXSOCKET PATH {
                    portset.pathname = $2; portset.family = AF_UNIX;
                  }
                ;

type            : /* EMPTY */ {
                    portset.type = SOCK_STREAM;
                  }
                | TYPE TCP {
                    portset.type = SOCK_STREAM;
                  }
                | TYPE TCPSSL sslversion certmd5  {
                    portset.type = SOCK_STREAM;
                    portset.SSL.use_ssl = TRUE;
                    portset.SSL.version = $<number>3;
                    if (portset.SSL.version == SSL_VERSION_NONE)
                      portset.SSL.version = SSL_VERSION_AUTO;
                    portset.SSL.certmd5 = $<string>4;
                  }
                | TYPE UDP {
                    portset.type = SOCK_DGRAM;
                  }
                ;

certmd5         : /* EMPTY */    { $<string>$ = NULL; }
                | CERTMD5 STRING { $<string>$ = $2; }
                ;

sslversion      : /* EMPTY */  { $<number>$ = SSL_VERSION_NONE; }
                | SSLV2        { $<number>$ = SSL_VERSION_SSLV2; }
                | SSLV3        { $<number>$ = SSL_VERSION_SSLV3; }
                | TLSV1        { $<number>$ = SSL_VERSION_TLS; }
                | SSLAUTO      { $<number>$ = SSL_VERSION_AUTO; }
                ;

protocol        : /* EMPTY */  {
                    portset.protocol = addprotocol(P_DEFAULT);
                  }
                | PROTOCOL APACHESTATUS apache_stat_list {
                    portset.protocol = addprotocol(P_APACHESTATUS);
                  }
                | PROTOCOL DEFAULT {
                    portset.protocol = addprotocol(P_DEFAULT);
                  }
                | PROTOCOL DNS {
                    portset.protocol = addprotocol(P_DNS);
                  }
                | PROTOCOL DWP  {
                    portset.protocol = addprotocol(P_DWP);
                  }
                | PROTOCOL FTP {
                    portset.protocol = addprotocol(P_FTP);
                  }
                | PROTOCOL HTTP request {
                    portset.protocol = addprotocol(P_HTTP);
                  }
                | PROTOCOL IMAP {
                    portset.protocol = addprotocol(P_IMAP);
                  }
                | PROTOCOL CLAMAV {
                    portset.protocol = addprotocol(P_CLAMAV);
                  }
                | PROTOCOL LDAP2 {
                    portset.protocol = addprotocol(P_LDAP2);
                  }
                | PROTOCOL LDAP3 {
                    portset.protocol = addprotocol(P_LDAP3);
                  }
                | PROTOCOL MYSQL {
                    portset.protocol = addprotocol(P_MYSQL);
                  }
                | PROTOCOL SIP target maxforward {
                    portset.protocol = addprotocol(P_SIP);
                  }
                | PROTOCOL NNTP {
                    portset.protocol = addprotocol(P_NNTP);
                  }
                | PROTOCOL NTP3  {
                    portset.protocol = addprotocol(P_NTP3);
                    portset.type = SOCK_DGRAM;
                  }
                | PROTOCOL POSTFIXPOLICY {
                    portset.protocol = addprotocol(P_POSTFIXPOLICY);
                  }
                | PROTOCOL POP {
                    portset.protocol = addprotocol(P_POP);
                  }
                | PROTOCOL SMTP {
                    portset.protocol = addprotocol(P_SMTP);
                  }
                | PROTOCOL SSH  {
                    portset.protocol = addprotocol(P_SSH);
                  }
                | PROTOCOL RDATE {
                    portset.protocol = addprotocol(P_RDATE);
                  }
                | PROTOCOL RSYNC {
                    portset.protocol = addprotocol(P_RSYNC);
                  }
                | PROTOCOL TNS {
                    portset.protocol = addprotocol(P_TNS);
                  }
                | PROTOCOL PGSQL {
                    portset.protocol = addprotocol(P_PGSQL);
                  }
                | PROTOCOL LMTP {
                    portset.protocol = addprotocol(P_LMTP);
                  }
                | PROTOCOL GPS {
                    portset.protocol = addprotocol(P_GPS);
                  }
                | PROTOCOL RADIUS secret {
                    portset.protocol = addprotocol(P_RADIUS);
                  }
                | PROTOCOL MEMCACHE {
                    portset.protocol = addprotocol(P_MEMCACHE);
                  }
                | sendexpectlist {
                    portset.protocol = addprotocol(P_GENERIC);
                  }
                ;     

sendexpectlist  : sendexpect
                | sendexpectlist sendexpect
                ;

sendexpect      : SEND STRING { addgeneric(&portset, $2, NULL); FREE($2);}
                | EXPECT STRING { addgeneric(&portset, NULL, $2); FREE($2);}
                ;

target          : /* EMPTY */
                | TARGET MAILADDR {
                    portset.request = $2;
                  }
                | TARGET STRING {
                    portset.request = $2;
                  }
                ;
                
maxforward      : /* EMPTY */ 
                |  MAXFORWARD NUMBER {
                     portset.maxforward = verifyMaxForward($2); 
                   }
                ;

request         : /* EMPTY */
                | REQUEST PATH hostheader { 
                    portset.request = Util_urlEncode($2); 
                    FREE($2); 
                  }
                | REQUEST PATH CHECKSUM STRING hostheader {
                    portset.request = Util_urlEncode($2);
                    FREE($2);
                    portset.request_checksum = $4;
                  }
                ;

hostheader      : /* EMPTY */
                | HOSTHEADER STRING {
                    portset.request_hostheader = $2;
                  }
                ;

secret          : SECRET STRING { 
                    portset.request = $2; 
                  }
                ;

apache_stat_list: apache_stat
                | apache_stat_list OR apache_stat
                ;

apache_stat     : LOGLIMIT operator NUMBER PERCENT { 
                    portset.ApacheStatus.loglimitOP = $<number>2; 
                    portset.ApacheStatus.loglimit = (int)$3; 
                  }
                | CLOSELIMIT operator NUMBER PERCENT { 
                    portset.ApacheStatus.closelimitOP = $<number>2; 
                    portset.ApacheStatus.closelimit = (int)($3); 
                  }
                | DNSLIMIT operator NUMBER PERCENT { 
                    portset.ApacheStatus.dnslimitOP = $<number>2; 
                    portset.ApacheStatus.dnslimit = (int)($3); 
                  }
                | KEEPALIVELIMIT operator NUMBER PERCENT { 
                    portset.ApacheStatus.keepalivelimitOP = $<number>2; 
                    portset.ApacheStatus.keepalivelimit = (int)($3); 
                  }
                | REPLYLIMIT operator NUMBER PERCENT { 
                    portset.ApacheStatus.replylimitOP = $<number>2; 
                    portset.ApacheStatus.replylimit = (int)($3); 
                  }
                | REQUESTLIMIT operator NUMBER PERCENT { 
                    portset.ApacheStatus.requestlimitOP = $<number>2; 
                    portset.ApacheStatus.requestlimit = (int)($3); 
                  }
                | STARTLIMIT operator NUMBER PERCENT { 
                    portset.ApacheStatus.startlimitOP = $<number>2; 
                    portset.ApacheStatus.startlimit = (int)($3); 
                  }
                | WAITLIMIT operator NUMBER PERCENT { 
                    portset.ApacheStatus.waitlimitOP = $<number>2; 
                    portset.ApacheStatus.waitlimit = (int)($3); 
                  }
                | GRACEFULLIMIT operator NUMBER PERCENT { 
                    portset.ApacheStatus.gracefullimitOP = $<number>2; 
                    portset.ApacheStatus.gracefullimit = (int)($3); 
                  }
                | CLEANUPLIMIT operator NUMBER PERCENT { 
                    portset.ApacheStatus.cleanuplimitOP = $<number>2; 
                    portset.ApacheStatus.cleanuplimit = (int)($3); 
                  }
                ;

exist           : IF NOT EXIST rate1 THEN action1 recovery {
                    seteventaction(&(current)->action_NONEXIST, $<number>6, $<number>7);
                  }
                ;


pid             : IF CHANGED PID rate1 THEN action1 {
                    seteventaction(&(current)->action_PID, $<number>6, ACTION_IGNORE);
                  }
                ;

ppid            : IF CHANGED PPID rate1 THEN action1 {
                    seteventaction(&(current)->action_PPID, $<number>6, ACTION_IGNORE);
                  }
                ;

icmpcount       : /* EMPTY */ {
                   $<number>$ = ICMP_ATTEMPT_COUNT;
                  }
                | COUNT NUMBER {    
                   $<number>$ = $2;
                  }
                ;

exectimeout     : /* EMPTY */ {
                   $<number>$ = EXEC_TIMEOUT;
                  }
                | TIMEOUT NUMBER SECOND {
                   $<number>$ = $2;
                  }
                ;

nettimeout      : /* EMPTY */ {
                   $<number>$ = NET_TIMEOUT;
                  }
                | TIMEOUT NUMBER SECOND {
                   $<number>$ = $2;
                  }
                ;

actionrate      : IF NUMBER RESTART NUMBER CYCLE THEN action1 {
                   actionrateset.count = $2;
                   actionrateset.cycle = $4;
                   addeventaction(&(actionrateset).action, $<number>7, ACTION_IGNORE);
                   addactionrate(&actionrateset);
                 }
                | IF NUMBER RESTART NUMBER CYCLE THEN TIMEOUT {
                   actionrateset.count = $2;
                   actionrateset.cycle = $4;
                   addeventaction(&(actionrateset).action, ACTION_UNMONITOR, ACTION_IGNORE);
                   addactionrate(&actionrateset);
                 }
                ;

urloption       : /* EMPTY */
                | CONTENT urloperator STRING {
                    seturlrequest($<number>2, $<string>3);
                    FREE($3);
                  }
                ;

urloperator     : EQUAL    { $<number>$ = OPERATOR_EQUAL; }
                | NOTEQUAL { $<number>$ = OPERATOR_NOTEQUAL; }
                ;

alert           : alertmail '{' eventoptionlist '}' formatlist reminder {
                   addmail($<string>1, &mailset, &current->maillist, eventset, $<number>6);
                  }
                | alertmail formatlist reminder {
                   addmail($<string>1, &mailset, &current->maillist, Event_All, $<number>3);
                  }
                | alertmail NOT '{' eventoptionlist '}' formatlist reminder {
                   addmail($<string>1, &mailset, &current->maillist, ~eventset, $<number>7);
                  }
                | noalertmail {
                   addmail($<string>1, &mailset, &current->maillist, Event_Null, 0);
                  }
                ;

alertmail       : ALERT MAILADDR { $<string>$ = $2; }
                ;

noalertmail     : NOALERT MAILADDR { $<string>$ = $2; }
                ;

eventoptionlist : eventoption
                | eventoptionlist eventoption
                ;

eventoption     : ACTION          { eventset |= Event_Action; }
                | CHECKSUM        { eventset |= Event_Checksum; }
                | CONNECTION      { eventset |= Event_Connection; }
                | CONTENT         { eventset |= Event_Content; }
                | DATA            { eventset |= Event_Data; }
                | EXEC            { eventset |= Event_Exec; }
                | FSFLAG          { eventset |= Event_Fsflag; }
                | GID             { eventset |= Event_Gid; }
                | ICMP            { eventset |= Event_Icmp; }
                | INSTANCE        { eventset |= Event_Instance; }
                | INVALID         { eventset |= Event_Invalid; }
                | NONEXIST        { eventset |= Event_Nonexist; }
                | PERMISSION      { eventset |= Event_Permission; }
                | PID             { eventset |= Event_Pid; }
                | PPID            { eventset |= Event_PPid; }
                | RESOURCE        { eventset |= Event_Resource; }
                | SIZE            { eventset |= Event_Size; }
                | TIMEOUT         { eventset |= Event_Timeout; }
                | TIMESTAMP       { eventset |= Event_Timestamp; }
                | UID             { eventset |= Event_Uid; }
                ;

formatlist      : /* EMPTY */
                | MAILFORMAT '{' formatoptionlist '}'
                ;

formatoptionlist: formatoption
                | formatoptionlist formatoption
                ;

formatoption    : MAILFROM { mailset.from = $1; }
                | MAILREPLYTO { mailset.replyto = $1; }
                | MAILSUBJECT { mailset.subject = $1; }
                | MAILBODY { mailset.message = $1; }
                ;

every           : EVERY NUMBER CYCLE {
                   check_every($2);
                   current->def_every = TRUE;
                   current->every = $2;
                 }
                ;

mode            : MODE ACTIVE  {
                    current->mode = MODE_ACTIVE;
                  }
                | MODE PASSIVE {
                    current->mode = MODE_PASSIVE;
                  }
                | MODE MANUAL  {
                    current->mode = MODE_MANUAL;
                    current->monitor = MONITOR_NOT;
                  }
                ;

group           : GROUP STRINGNAME { addservicegroup($2); FREE($2);}
                ;


depend          : DEPENDS dependlist
                ;

dependlist      : dependant
                | dependlist dependant
                ;
 
dependant       : SERVICENAME { adddependant($<string>1); }
                ;

resourceprocess : IF resourceprocesslist rate1 THEN action1 recovery {
                     addeventaction(&(resourceset).action, $<number>5, $<number>6);
                     addresource(&resourceset);
                   }
                ;

resourceprocesslist : resourceprocessopt
                    | resourceprocesslist resourceprocessopt
                    ;

resourceprocessopt  : resourcecpuproc
                    | resourcemem
                    | resourcechild
                    | resourceload
                    ;

resourcesystem  : IF resourcesystemlist rate1 THEN action1 recovery {
                     addeventaction(&(resourceset).action, $<number>5, $<number>6);
                     addresource(&resourceset);
                   }
                ;

resourcesystemlist : resourcesystemopt
                   | resourcesystemlist resourcesystemopt
                   ;

resourcesystemopt  : resourceload
                   | resourcemem
                   | resourceswap
                   | resourcecpu
                   ;

resourcecpuproc : CPU operator NUMBER PERCENT {
                    resourceset.resource_id = RESOURCE_ID_CPU_PERCENT;
                    resourceset.operator = $<number>2;
                    resourceset.limit = ($3 * 10); 
                  }
                | TOTALCPU operator NUMBER PERCENT {
                    resourceset.resource_id = RESOURCE_ID_TOTAL_CPU_PERCENT;
                    resourceset.operator = $<number>2;
                    resourceset.limit = ($3 * 10); 
                  }
                ;

resourcecpu     : resourcecpuid operator NUMBER PERCENT {
                    resourceset.resource_id = $<number>1;
                    resourceset.operator = $<number>2;
                    resourceset.limit = ($3 * 10); 
                  }
                ;

resourcecpuid   : CPUUSER   { $<number>$ = RESOURCE_ID_CPUUSER; }
                | CPUSYSTEM { $<number>$ = RESOURCE_ID_CPUSYSTEM; }
                | CPUWAIT   { $<number>$ = RESOURCE_ID_CPUWAIT; }
                ;

resourcemem     : MEMORY operator value unit {
                    resourceset.resource_id = RESOURCE_ID_MEM_KBYTE;
                    resourceset.operator = $<number>2;
                    resourceset.limit = (int) ($<real>3 * ($<number>4 / 1024.0)); 
                  }
                | MEMORY operator NUMBER PERCENT {
                    resourceset.resource_id = RESOURCE_ID_MEM_PERCENT;
                    resourceset.operator = $<number>2;
                    resourceset.limit = ($3 * 10); 
                  }
                | TOTALMEMORY operator value unit {
                    resourceset.resource_id = RESOURCE_ID_TOTAL_MEM_KBYTE;
                    resourceset.operator = $<number>2;
                    resourceset.limit = (int) ($<real>3 * ($<number>4 / 1024.0));
                  }
                | TOTALMEMORY operator NUMBER PERCENT  {
                    resourceset.resource_id = RESOURCE_ID_TOTAL_MEM_PERCENT;
                    resourceset.operator = $<number>2;
                    resourceset.limit = ($3 * 10);
                  }
                ;

resourceswap    : SWAP operator value unit {
                    resourceset.resource_id = RESOURCE_ID_SWAP_KBYTE;
                    resourceset.operator = $<number>2;
                    resourceset.limit = (int) ($<real>3 * ($<number>4 / 1024.0));
                  }
                | SWAP operator NUMBER PERCENT {
                    resourceset.resource_id = RESOURCE_ID_SWAP_PERCENT;
                    resourceset.operator = $<number>2;
                    resourceset.limit = ($3 * 10);
                  }
                ;

resourcechild   : CHILDREN operator NUMBER { 
                    resourceset.resource_id = RESOURCE_ID_CHILDREN;
                    resourceset.operator = $<number>2;
                    resourceset.limit = (int) $3; 
                  }
                ;

resourceload    : resourceloadavg operator value { 
                    resourceset.resource_id = $<number>1;
                    resourceset.operator = $<number>2;
                    resourceset.limit = (int) ($<real>3 * 10.0); 
                  }
                ;

resourceloadavg : LOADAVG1  { $<number>$ = RESOURCE_ID_LOAD1; }
                | LOADAVG5  { $<number>$ = RESOURCE_ID_LOAD5; }
                | LOADAVG15 { $<number>$ = RESOURCE_ID_LOAD15; }
                ;

value           : REAL { $<real>$ = $1; }
                | NUMBER { $<real>$ = (float) $1; }
                ;

timestamp       : IF TIMESTAMP operator NUMBER time rate1 THEN action1 recovery {
                    timestampset.operator = $<number>3;
                    timestampset.time = ($4 * $<number>5);
                    addeventaction(&(timestampset).action, $<number>8, $<number>9);
                    addtimestamp(&timestampset, FALSE);
                  }
                | IF CHANGED TIMESTAMP rate1 THEN action1 {
                    timestampset.test_changes = TRUE;
                    addeventaction(&(timestampset).action, $<number>6, ACTION_IGNORE);
                    addtimestamp(&timestampset, TRUE);
                  }
                ;

operator        : /* EMPTY */ { $<number>$ = OPERATOR_EQUAL; }
                | GREATER     { $<number>$ = OPERATOR_GREATER; }
                | LESS        { $<number>$ = OPERATOR_LESS; }
                | EQUAL       { $<number>$ = OPERATOR_EQUAL; }
                | NOTEQUAL    { $<number>$ = OPERATOR_NOTEQUAL; }
                | CHANGED     { $<number>$ = OPERATOR_NOTEQUAL; }
                ;

time            : /* EMPTY */ { $<number>$ = TIME_SECOND; }
                | SECOND      { $<number>$ = TIME_SECOND; }
                | MINUTE      { $<number>$ = TIME_MINUTE; }
                | HOUR        { $<number>$ = TIME_HOUR; }
                | DAY         { $<number>$ = TIME_DAY; }
                ;

action          : ALERT                            { $<number>$ = ACTION_ALERT; }
                | EXEC argumentlist                { $<number>$ = ACTION_EXEC; }
                | EXEC argumentlist useroptionlist { $<number>$ = ACTION_EXEC; }
                | RESTART                          { $<number>$ = ACTION_RESTART; }
                | START                            { $<number>$ = ACTION_START; }
                | STOP                             { $<number>$ = ACTION_STOP; }
                | UNMONITOR                        { $<number>$ = ACTION_UNMONITOR; }
                ;

action1         : action {
                    $<number>$ = $<number>1;
                    if ($<number>1 == ACTION_EXEC && command) {
                      command1 = command;
                      command = NULL;
                    }
                  }
                ;

action2         : action {
                    $<number>$ = $<number>1;
                    if ($<number>1 == ACTION_EXEC && command) {
                      command2 = command;
                      command = NULL;
                    }
                  }
                ;

rate1           : /* EMPTY */
                | NUMBER CYCLE {
                    rate1.count  = $<number>1;
                    rate1.cycles = $<number>1;
                    if (rate1.cycles < 1 || rate1.cycles > BITMAP_MAX)
                      yyerror2("the number of cycles must be between 1 and %d", BITMAP_MAX);
                  }
                | NUMBER NUMBER CYCLE {
                    rate1.count  = $<number>1;
                    rate1.cycles = $<number>2;
                    if (rate1.cycles < 1 || rate1.cycles > BITMAP_MAX)
                      yyerror2("the number of cycles must be between 1 and %d", BITMAP_MAX);
                    if (rate1.count < 1 || rate1.count > rate1.cycles)
                      yyerror2("the number of events must be bigger then 0 and less than poll cycles");
                  }
                ;

rate2           : /* EMPTY */
                | NUMBER CYCLE {
                    rate2.count  = $<number>1;
                    rate2.cycles = $<number>1;
                    if (rate2.cycles < 1 || rate2.cycles > BITMAP_MAX)
                      yyerror2("the number of cycles must be between 1 and %d", BITMAP_MAX);
                  }
                | NUMBER NUMBER CYCLE {
                    rate2.count  = $<number>1;
                    rate2.cycles = $<number>2;
                    if (rate2.cycles < 1 || rate2.cycles > BITMAP_MAX)
                      yyerror2("the number of cycles must be between 1 and %d", BITMAP_MAX);
                    if (rate2.count < 1 || rate2.count > rate2.cycles)
                      yyerror2("the number of events must be bigger then 0 and less than poll cycles");
                  }
                ;

recovery        : /* EMPTY */ {
                    $<number>$ = ACTION_ALERT;
                  }
                | ELSE IF RECOVERED rate2 THEN action2 {
                    $<number>$ = $<number>6;
                  }
                | ELSE IF PASSED rate2 THEN action2 {
                    $<number>$ = $<number>6;
                  }
                | ELSE IF SUCCEEDED rate2 THEN action2 {
                    $<number>$ = $<number>6;
                  }
                ;

checksum        : IF FAILED hashtype CHECKSUM rate1 THEN action1 recovery {
                    addeventaction(&(checksumset).action, $<number>7, $<number>8);
                    addchecksum(&checksumset);
                  }
                | IF FAILED hashtype CHECKSUM EXPECT STRING rate1 THEN action1
                  recovery {
                    snprintf(checksumset.hash, sizeof(checksumset.hash), "%s", $6);
                    FREE($6);
                    addeventaction(&(checksumset).action, $<number>9, $<number>10);
                    addchecksum(&checksumset);
                  }
                | IF CHANGED hashtype CHECKSUM rate1 THEN action1 {
                    checksumset.test_changes = TRUE;
                    addeventaction(&(checksumset).action, $<number>7, ACTION_IGNORE);
                    addchecksum(&checksumset);
                  }
                ;
hashtype        : /* EMPTY */ { checksumset.type = HASH_UNKNOWN; }
                | MD5HASH     { checksumset.type = HASH_MD5; }
                | SHA1HASH    { checksumset.type = HASH_SHA1; }
                ;

inode           : IF INODE operator NUMBER rate1 THEN action1 recovery {
                    filesystemset.resource = RESOURCE_ID_INODE;
                    filesystemset.operator = $<number>3;
                    filesystemset.limit_absolute = $4;
                    addeventaction(&(filesystemset).action, $<number>7, $<number>8);
                    addfilesystem(&filesystemset);
                  }
                | IF INODE operator NUMBER PERCENT rate1 THEN action1 recovery {
                    filesystemset.resource = RESOURCE_ID_INODE;
                    filesystemset.operator = $<number>3;
                    filesystemset.limit_percent = (int)($4 * 10);
                    addeventaction(&(filesystemset).action, $<number>8, $<number>9);
                    addfilesystem(&filesystemset);
                  }
                ;

space           : IF SPACE operator value unit rate1 THEN action1 recovery {
                    if (!filesystem_usage(current->inf, current->path))
                      yyerror2("cannot read usage of filesystem %s", current->path);
                    filesystemset.resource = RESOURCE_ID_SPACE;
                    filesystemset.operator = $<number>3;
                    filesystemset.limit_absolute = (int)((float)$<real>4 / (float)current->inf->priv.filesystem.f_bsize * (float)$<number>5);
                    addeventaction(&(filesystemset).action, $<number>8, $<number>9);
                    addfilesystem(&filesystemset);
                  }
                | IF SPACE operator NUMBER PERCENT rate1 THEN action1 recovery {
                    filesystemset.resource = RESOURCE_ID_SPACE;
                    filesystemset.operator = $<number>3;
                    filesystemset.limit_percent = (int)($4 * 10);
                    addeventaction(&(filesystemset).action, $<number>8, $<number>9);
                    addfilesystem(&filesystemset);
                  }
                ;

fsflag          : IF CHANGED FSFLAG rate1 THEN action1 {
                    seteventaction(&(current)->action_FSFLAG, $<number>6, ACTION_IGNORE);
                  }
                ;

unit            : /* empty */  { $<number>$ = UNIT_BYTE; }
                | BYTE         { $<number>$ = UNIT_BYTE; }
                | KILOBYTE     { $<number>$ = UNIT_KILOBYTE; }
                | MEGABYTE     { $<number>$ = UNIT_MEGABYTE; }
                | GIGABYTE     { $<number>$ = UNIT_GIGABYTE; }
                ;

permission      : IF FAILED PERMISSION NUMBER rate1 THEN action1 recovery {
                    permset.perm = check_perm($4);
                    addeventaction(&(permset).action, $<number>7, $<number>8);
                    addperm(&permset);
                  }
                ;

match           : IF matchflagnot MATCH PATH rate1 THEN action1 {
                    matchset.ignore = FALSE;
                    matchset.match_path = $4;
                    matchset.match_string = NULL;
                    addmatchpath(&matchset, $<number>7);
                    FREE($4); 
                  }
                | IF matchflagnot MATCH STRING rate1 THEN action1 {
                    matchset.ignore = FALSE;
                    matchset.match_path = NULL;
                    matchset.match_string = $4;
                    addmatch(&matchset, $<number>7, 0);
                  }
                | IGNORE matchflagnot MATCH PATH {
                    matchset.ignore = TRUE;
                    matchset.match_path = $4;
                    matchset.match_string = NULL;
                    addmatchpath(&matchset, ACTION_IGNORE);
                    FREE($4); 
                  }
                | IGNORE matchflagnot MATCH STRING {
                    matchset.ignore = TRUE;
                    matchset.match_path = NULL;
                    matchset.match_string = $4;
                    addmatch(&matchset, ACTION_IGNORE, 0);
                  }
                ;

matchflagnot    : /* EMPTY */ {
                    matchset.not = FALSE;
                  }
                | NOT {
                    matchset.not = TRUE;
                  }
                ;


size            : IF SIZE operator NUMBER unit rate1 THEN action1 recovery {
                    sizeset.operator = $<number>3;
                    sizeset.size = ((unsigned long long)$4 * $<number>5);
                    addeventaction(&(sizeset).action, $<number>8, $<number>9);
                    addsize(&sizeset);
                  }
                | IF CHANGED SIZE rate1 THEN action1 {
                    sizeset.test_changes = TRUE;
                    addeventaction(&(sizeset).action, $<number>6, ACTION_IGNORE);
                    addsize(&sizeset);
                  }
                ;

uid             : IF FAILED UID STRING rate1 THEN action1 recovery {
                    uidset.uid = get_uid($4, 0);
                    addeventaction(&(uidset).action, $<number>7, $<number>8);
                    adduid(&uidset);
                    FREE($4);
                  }
                | IF FAILED UID NUMBER rate1 THEN action1 recovery {
                    uidset.uid = get_uid(NULL, $4);
                    addeventaction(&(uidset).action, $<number>7, $<number>8);
                    adduid(&uidset);
                  }
                ;

gid             : IF FAILED GID STRING rate1 THEN action1 recovery {
                    gidset.gid = get_gid($4, 0);
                    addeventaction(&(gidset).action, $<number>7, $<number>8);
                    addgid(&gidset);
                    FREE($4);
                  }
                | IF FAILED GID NUMBER rate1 THEN action1 recovery {
                    gidset.gid = get_gid(NULL, $4);
                    addeventaction(&(gidset).action, $<number>7, $<number>8);
                    addgid(&gidset);
                  }
                ;

icmptype        : TYPE ICMPECHO { $<number>$ = ICMP_ECHO; }
                ;

reminder        : /* EMPTY */           { $<number>$ = 0; }
                | REMINDER NUMBER       { $<number>$ = $2; }
                | REMINDER NUMBER CYCLE { $<number>$ = $2; }
                ;

%%


/* -------------------------------------------------------- Parser interface */


/**
 * Syntactic error routine
 *
 * This routine is automatically called by the lexer!
 */
void yyerror(const char *s, ...) {
  
  long len;
  va_list ap;
  char *msg = NULL;

  ASSERT(s);
  
  va_start(ap,s);
  msg = Util_formatString(s, ap, &len);
  va_end(ap);
  
  LogError("%s:%i: Error: %s '%s'\n", currentfile, lineno, msg, yytext);
  cfg_errflag++;
 
  FREE(msg);
  
}

/**
 * Syntactical warning routine
 */
void yywarning(const char *s, ...) {
  
  long len;
  va_list ap;
  char *msg = NULL;

  ASSERT(s);
  
  va_start(ap,s);
  msg = Util_formatString(s, ap, &len);
  va_end(ap);
  
  LogWarning("%s:%i: Warning: %s '%s'\n", currentfile, lineno, msg, yytext);
 
  FREE(msg);
  
}

/**
 * Argument error routine
 */
void yyerror2(const char *s, ...) {
  
  long len;
  va_list ap;
  char *msg = NULL;

  ASSERT(s);
  
  va_start(ap,s);
  msg = Util_formatString(s, ap, &len);
  va_end(ap);
  
  LogError("%s:%i: Error: %s '%s'\n", argcurrentfile, arglineno, msg, argyytext);
  cfg_errflag++;
 
  FREE(msg);
  
}

/**
 * Argument warning routine
 */
void yywarning2(const char *s, ...) {
  
  long len;
  va_list ap;
  char *msg = NULL;

  ASSERT(s);
  
  va_start(ap,s);
  msg = Util_formatString(s, ap, &len);
  va_end(ap);
  
  LogWarning("%s:%i: Warning: %s '%s'\n", argcurrentfile, arglineno, msg, argyytext);
 
  FREE(msg);
  
}

/*
 * The Parser hook - start parsing the control file
 * Returns TRUE if parsing succeeded, otherwise FALSE
 */
int parse(char *controlfile) {

  ASSERT(controlfile);

  servicelist = tail = current = NULL;

  /*
   * Secure check the monitrc file. The run control file must have the
   * same uid as the REAL uid of this process, it must have permissions
   * no greater than 700 and it must not be a symbolic link.
   */
  if (! File_checkStat(controlfile, "control file", S_IRUSR|S_IWUSR|S_IXUSR))
    return FALSE;

  if ((yyin = fopen(controlfile,"r")) == (FILE *)NULL) {
    LogError("%s: Error: cannot open the control file '%s' -- %s\n", prog, controlfile, STRERROR);
    return FALSE;
  }

  currentfile = xstrdup(controlfile);

  /* 
   * Creation of the global service list is synchronized  
   */
  LOCK(Run.mutex)
    preparse();
    yyparse();
    fclose(yyin);
    /* Add the default general system service if not specified explicitly */
    if (!hassystem) {
      char *name = Util_getString("system_%s", Run.localhostname);
      if (Util_existService(name) || (current && IS(name, current->name))) {
        LogError("'check system' not defined in control file, failed to add automatic configuration (service name %s is used already) -- please add 'check system <name>' manually\n", name, name);
        FREE(name);
        cfg_errflag++;
      } else {
        createservice(TYPE_SYSTEM, name, xstrdup(""), check_system);
      }
    }
    /* If defined - add the last service to the service list */
    if (current) {
      addservice(current);
      FREE(current);
    }
    postparse();
  END_LOCK;

  FREE(currentfile);

  if (argyytext != NULL)
    FREE(argyytext);

  return(cfg_errflag == 0);
}


/* ----------------------------------------------------------------- Private */


/**
 * Initialize objects used by the parser.
 */
static void preparse() {
  int i;
  char localhost[STRLEN];

  /*
   * Get the localhost name
   */
  if (Util_getfqdnhostname(localhost, sizeof(localhost)))
    snprintf(localhost, STRLEN, "%s", LOCALHOST);

  /* Set instance incarnation ID */
  time(&Run.incarnation);
  /* Reset lexer */
  buffer_stack_ptr        = 0;
  lineno                  = 1;
  arglineno               = 1;
  argcurrentfile          = NULL;
  argyytext               = NULL;
  /* Reset parser */
  Run.stopped             = FALSE;
  Run.dolog               = FALSE;
  Run.dohttpd             = FALSE;
  Run.doaction            = FALSE;
  Run.httpdsig            = TRUE;
  Run.dommonitcredentials = TRUE;
  Run.mmonitcredentials   = NULL;
  Run.credentials         = NULL;
  Run.httpdssl            = FALSE;
  Run.httpsslpem          = NULL;
  Run.httpsslclientpem    = NULL;
  Run.clientssl           = FALSE;
  Run.mailserver_timeout  = NET_TIMEOUT;
  Run.bind_addr           = NULL;
  Run.eventlist           = NULL;
  Run.eventlist_dir       = NULL;
  Run.eventlist_slots     = -1;
  Run.system              = NULL;
  Run.expectbuffer        = STRLEN;
  Run.mmonits             = NULL;
  Run.maillist            = NULL;
  Run.mailservers         = NULL;
  Run.MailFormat.from     = NULL;
  Run.MailFormat.replyto  = NULL;
  Run.MailFormat.subject  = NULL;
  Run.MailFormat.message  = NULL;
  Run.localhostname       = xstrdup(localhost);
  depend_list             = NULL;
  Run.handler_init        = TRUE;
#ifdef OPENSSL_FIPS  
  Run.fipsEnabled         = FALSE;
#endif
  for (i = 0; i <= HANDLER_MAX; i++)
    Run.handler_queue[i] = 0;
  /* 
   * Initialize objects
   */
  reset_uidset();
  reset_gidset();
  reset_sizeset();
  reset_mailset();
  reset_mailserverset();
  reset_portset();
  reset_permset();
  reset_icmpset();
  reset_rateset();
  reset_filesystemset();
  reset_resourceset();
  reset_checksumset();
  reset_timestampset();
  reset_actionrateset();
}


/*
 * Check that values are reasonable after parsing
 */
static void postparse() {
  Service_T s;

  if (cfg_errflag || ! servicelist)
    return;

  /* Check the sanity of any dependency graph */
  check_depend();

  /* Check that we do not start monit in daemon mode without having a
   * poll time */
  if (!Run.polltime && (Run.isdaemon || Run.init)) {
    LogError("%s: Error: Poll time not defined. Please define poll time in the\n control file or use the -d option when starting monit\n", prog);
    cfg_errflag++;
  }

  if (Run.logfile)
    Run.dolog = TRUE;

  for (s = servicelist; s; s = s->next) {
    /* Set the general system service shortcut */
    if (s->type == TYPE_SYSTEM)
      Run.system = s;
    if (s->type != TYPE_HOST)
	continue;
    /* Verify that a remote service has a port or an icmp list */
    if (!s->portlist && !s->icmplist) {
      LogError("%s: Error: 'check host' statement is incomplete; Please specify a port number to test\n or an icmp test at the remote host: '%s'\n", prog, s->name);
      cfg_errflag++;
    }
  }

  if (Run.mmonits) {
    if (Run.dohttpd) {
      if (Run.dommonitcredentials) {
        Auth_T c;
        for (c = Run.credentials; c; c = c->next) {
          if (c->digesttype == DIGEST_CLEARTEXT && ! c->is_readonly) {
              Run.mmonitcredentials = c;
              break;
          }
        }
        if (! Run.mmonitcredentials)
          LogWarning("%s: Warning: M/Monit registration with credentials enabled, but no suitable credentials found in monit configuration file -- please add 'allow user:password' option to 'set httpd' statement\n", prog);
      }
    } else
        LogWarning("%s: Warning: M/Monit enabled but no httpd allowed -- please add 'set httpd' statement\n", prog);
  }
}


/*
 * Create a new service object and add any current objects to the
 * service list.
 */
static void createservice(int type, char *name, char *value, int (*check)(Service_T s)) {

  ASSERT(name);
  ASSERT(value);

  check_name(name);

  if (current) {
    addservice(current);
    memset(current, 0, sizeof(*current));
  } else {
    NEW(current);
  }

  current->type = type;

  NEW(current->inf);
  Util_resetInfo(current);

  /* Set default values */
  current->monitor = MONITOR_INIT;
  current->mode    = MODE_ACTIVE;
  current->name    = name;
  current->check   = check;
  current->path    = value;

  /* Initialize general event handlers */
  addeventaction(&(current)->action_DATA,     ACTION_ALERT,     ACTION_ALERT);
  addeventaction(&(current)->action_EXEC,     ACTION_ALERT,     ACTION_ALERT);
  addeventaction(&(current)->action_INVALID,  ACTION_RESTART,   ACTION_ALERT);
  addeventaction(&(current)->action_NONEXIST, ACTION_RESTART,   ACTION_ALERT);
  addeventaction(&(current)->action_PID,      ACTION_ALERT,     ACTION_IGNORE);
  addeventaction(&(current)->action_PPID,     ACTION_ALERT,     ACTION_IGNORE);
  addeventaction(&(current)->action_FSFLAG,   ACTION_ALERT,     ACTION_IGNORE);

  /* Initialize internal event handlers */
  addeventaction(&(current)->action_MONIT_START,  ACTION_START, ACTION_IGNORE);
  addeventaction(&(current)->action_MONIT_STOP,   ACTION_STOP,  ACTION_IGNORE);
  addeventaction(&(current)->action_MONIT_RELOAD, ACTION_START, ACTION_IGNORE);
  addeventaction(&(current)->action_ACTION,       ACTION_ALERT, ACTION_IGNORE);
  
  gettimeofday(&current->collected, NULL);
}


/*
 * Add a service object to the servicelist
 */
static void addservice(Service_T s) {
  Service_T n;

  ASSERT(s);
 
  NEW(n);
  memcpy(n, s, sizeof(*s));
  /* Add the service to the end of the service list */
  if (tail != NULL) {
    tail->next = n;
    tail->next_conf = n;
  } else {
    servicelist = n;
    servicelist_conf = n;
  }
  tail = n;
}


/* 
 * Add entry to service group list
 */
static void addservicegroup(char *name) {
  ServiceGroup_T g;
  ServiceGroupMember_T m;

  ASSERT(name);
 
  /* Check if service group with the same name is defined already */
  for (g = servicegrouplist; g; g = g->next)
    if (! strcasecmp(g->name, name))
      break;

  if (! g) {
    NEW(g);
    g->name = xstrdup(name);
    g->next = servicegrouplist;
    servicegrouplist = g;
  }

  NEW(m);
  m->name = xstrdup(current->name);
  m->next = g->members;
  g->members = m;
}


/* 
 * Add a dependant entry to the current service dependant list
 *
 */
static void adddependant(char *dependant) {
  Dependant_T d; 

  ASSERT(dependant);
  
  NEW(d);
  
  if (current->dependantlist != NULL)
    d->next = current->dependantlist;

  d->dependant = dependant;
  current->dependantlist = d;

}


/*
 * Add the given mailaddress with the apropriate alert notification
 * values and mail attributes to the given mailinglist.
 */
static void addmail(char *mailto, Mail_T f, Mail_T *l, unsigned int events, unsigned int reminder) {
  Mail_T m;

  ASSERT(mailto);

  NEW(m);
  m->events   = events;
  m->to       = mailto;
  m->from     = f->from;
  m->subject  = f->subject;
  m->message  = f->message;
  m->reminder = reminder;
  
  m->next = *l;
  *l = m;

  reset_mailset();
}


/*
 * Add the given portset to the current service's portlist
 */
static void addport(Port_T port) {
  Port_T p;
  
  ASSERT(port);

  NEW(p);
  p->port               = port->port;
  p->type               = port->type;
  p->socket             = port->socket;
  p->family             = port->family;
  p->action             = port->action;
  p->timeout            = port->timeout;
  p->request            = port->request;
  p->generic            = port->generic;
  p->protocol           = port->protocol;
  p->pathname           = port->pathname;
  p->hostname           = port->hostname;
  p->url_request        = port->url_request;
  p->request_checksum   = port->request_checksum;
  p->request_hostheader = port->request_hostheader;
  memcpy(&p->ApacheStatus, &port->ApacheStatus, sizeof(struct apache_status));

  if (p->request_checksum) {
    cleanup_hash_string(p->request_checksum);
    if (strlen(p->request_checksum) == 32)
      p->request_hashtype = HASH_MD5;
    else if (strlen(p->request_checksum) == 40)
      p->request_hashtype = HASH_SHA1;
    else
      yyerror2("invalid checksum [%s]", p->request_checksum);
  } else
    p->request_hashtype = 0;

  if (port->SSL.use_ssl == TRUE) {
    if (!have_ssl()) {
      yyerror("ssl check cannot be activated. SSL is not supported");
    } else {
      if (port->SSL.certmd5 != NULL) {
	p->SSL.certmd5 = port->SSL.certmd5;
	cleanup_hash_string(p->SSL.certmd5);
      }
      p->SSL.use_ssl = TRUE;
      p->SSL.version = port->SSL.version;
    }
  }
  p->maxforward = port->maxforward;
  p->next = current->portlist;
  current->portlist = p;
  
  reset_portset();

}


/*
 * Add a new resource object to the current service resource list
 */
static void addresource(Resource_T rr) {
  Resource_T r;

  ASSERT(rr);

  NEW(r);
  if (! Run.doprocess)
    yyerror("Cannot activate service check. The process status engine was disabled. On certain systems you must run monit as root to utilize this feature)\n");
  r->resource_id = rr->resource_id;
  r->limit       = rr->limit;
  r->action      = rr->action;
  r->operator    = rr->operator;
  r->next        = current->resourcelist;

  current->resourcelist = r;
  reset_resourceset();
}


/*
 * Add a new file object to the current service timestamp list
 */
static void addtimestamp(Timestamp_T ts, int notime) {
  Timestamp_T t;

  ASSERT(ts);

  NEW(t);
  t->operator     = ts->operator;
  t->time         = ts->time;
  t->action       = ts->action;
  t->test_changes = ts->test_changes;
  
  if (t->test_changes || notime) {
    if (! File_exist(current->path)) {
      DEBUG("%s: Debug: the path '%s' used in the TIMESTAMP statement refer to a non-existing object\n", prog, current->path);
    } else if (!(t->timestamp = File_getTimestamp(current->path, S_IFDIR|S_IFREG))) {
      yyerror2("cannot get the timestamp for '%s'", current->path);
    }
  }
  
  t->next = current->timestamplist;
  current->timestamplist = t;

  reset_timestampset();
}


/*
 * Add a new object to the current service actionrate list
 */
static void addactionrate(ActionRate_T ar) {
  ActionRate_T a;

  ASSERT(ar);

  if (ar->count > ar->cycle)
    yyerror2("the number of restarts must be less than poll cycles");
  if (ar->count <= 0 || ar->cycle <= 0)
    yyerror2("zero or negative values not allowed in a action rate statement");

  NEW(a);
  a->count  = ar->count;
  a->cycle  = ar->cycle;
  a->action = ar->action;

  a->next = current->actionratelist;
  current->actionratelist = a;

  reset_actionrateset();
}



/*
 * Add a new Size object to the current service size list
 */
static void addsize(Size_T ss) {
  Size_T s;
  struct stat buf;

  ASSERT(ss);

  NEW(s);
  s->operator     = ss->operator;
  s->size         = ss->size;
  s->action       = ss->action;
  s->test_changes = ss->test_changes;
  /* Get the initial size for future comparision, if the file exists */
  if (s->test_changes) {
    s->test_changes_ok = !stat(current->path, &buf);
    if (s->test_changes_ok)
      s->size = (unsigned long long)buf.st_size;
  }
 
  s->next = current->sizelist;
  current->sizelist = s;

  reset_sizeset();
}


/*
 * Set Checksum object in the current service
 */
static void addchecksum(Checksum_T cs) {

  int len;
  Checksum_T c;

  ASSERT(cs);

  cs->test_changes_ok = TRUE;

  if (! *cs->hash) {
    if (cs->type == HASH_UNKNOWN)
      cs->type = DEFAULT_HASH;
    if ( !(Util_getChecksum(current->path, cs->type, cs->hash, sizeof(cs->hash)))) {
      if (cs->test_changes == TRUE) {
        /* If the file doesn't exist and we're checking for checksum changes, set dummy value */
        cs->test_changes_ok = FALSE;
        snprintf(cs->hash, sizeof(cs->hash), "00000000000000000000000000000000");
      } else {
        yyerror2("cannot compute a checksum for file %s", current->path);
        reset_checksumset();
        return;
      }
    }
  }

  len = cleanup_hash_string(cs->hash);

  if (cs->type == HASH_UNKNOWN) {
    if (len == 32) {
      cs->type = HASH_MD5;
    } else if (len == 40) {
      cs->type = HASH_SHA1;
    } else {
      yyerror2("invalid checksum [%s] for file %s", cs->hash, current->path);
      reset_checksumset();
      return;
    }
  } else if (( cs->type == HASH_MD5 && len!=32 ) || ( cs->type == HASH_SHA1 && len != 40 )) {
    yyerror2("invalid checksum [%s] for file %s", cs->hash, current->path);
    reset_checksumset();
    return;
  }

  NEW(c);

  c->type            = cs->type;
  c->test_changes    = cs->test_changes;
  c->test_changes_ok = cs->test_changes_ok;
  c->action          = cs->action;
  snprintf(c->hash, sizeof(c->hash), "%s", cs->hash);
 
  current->checksum = c;

  reset_checksumset();

}


/*
 * Set Perm object in the current service
 */
static void addperm(Perm_T ps) {
  Perm_T p;

  ASSERT(ps);

  NEW(p);
  p->perm       = ps->perm;
  p->action     = ps->action;
  current->perm = p;
  reset_permset();

}

/*
 * Set Match object in the current service
 */
static void addmatch(Match_T ms, int actionnumber, int linenumber) {
  Match_T m;
  Match_T ml;
  int     reg_return;
  
  ASSERT(ms);

  NEW(m);
#ifdef HAVE_REGEX_H
  NEW(m->regex_comp);
#endif

  m->match_string = ms->match_string;
  m->match_path   = ms->match_path ? xstrdup(ms->match_path) : NULL;
  m->action       = ms->action;
  m->not          = ms->not;
  m->ignore       = ms->ignore;
  m->next         = NULL;

  addeventaction(&(m->action), actionnumber, ACTION_IGNORE);

#ifdef HAVE_REGEX_H
  reg_return = regcomp(m->regex_comp, ms->match_string, REG_NOSUB|REG_EXTENDED);

  if (reg_return != 0) {
    char errbuf[STRLEN];
    regerror(reg_return, ms->regex_comp, errbuf, STRLEN);
    if (m->match_path != NULL) 
      yyerror2("regex parsing error:%s on line %i of", errbuf, linenumber);
    else
      yyerror2("regex parsing error:%s", errbuf);
  }
#endif

  if (current->matchlist) {
    /* Find the end of the list */
    for (ml = current->matchlist; ml->next; ml = ml->next)
      ;

    ml->next = m;
    
  } else
    current->matchlist = m;
}


static void addmatchpath(Match_T ms, int actionnumber) {

  FILE *handle;
  Command_T savecommand = NULL;
  char buf[2048];
  int linenumber = 0;

  ASSERT(ms->match_path);

  handle = fopen(ms->match_path, "r");
  if (handle == NULL) {
    yyerror2("cannot read regex match file (%s)", ms->match_path);
    return;
  }
  
  while (!feof(handle)) {
    int len;

    linenumber++;
    
    if (! fgets(buf, 2048, handle))
      continue;

    len = strlen(buf);

    if (len == 0 || buf[0] == '\n')
      continue;

    if (buf[len-1] == '\n')
      buf[len-1] = 0;

    ms->match_string = xstrdup(buf);

    /* The addeventaction() called from addmatch() will reset the
     * command1 to NULL, but we need to duplicate the command for
     * each line, thus need to save it here */
    if (actionnumber == ACTION_EXEC) {
      if (command1 == NULL) {
        ASSERT(savecommand);
        command1 = savecommand;
      }
      savecommand = copycommand(command1);
    }

    addmatch(ms, actionnumber, linenumber);
  }

  if (actionnumber == ACTION_EXEC && savecommand)
    gccmd(&savecommand);

  fclose(handle);
}


/*
 * Set Uid object in the current service
 */
static void adduid(Uid_T us) {
  Uid_T u;

  ASSERT(us);

  NEW(u);
  u->uid       = us->uid;
  u->action    = us->action;
  current->uid = u;
  reset_uidset();
}


/*
 * Set Gid object in the current service
 */
static void addgid(Gid_T gs) {
  Gid_T g;

  ASSERT(gs);

  NEW(g);
  g->gid       = gs->gid;
  g->action    = gs->action;
  current->gid = g;
  reset_gidset();
}


/*
 * Add a new filesystem to the current service's filesystem list
 */
static void addfilesystem(Filesystem_T ds) {
  Filesystem_T dev;

  ASSERT(ds);
  
  NEW(dev);
  dev->resource           = ds->resource;
  dev->operator           = ds->operator;
  dev->limit_absolute     = ds->limit_absolute;
  dev->limit_percent      = ds->limit_percent;
  dev->action             = ds->action;

  dev->next               = current->filesystemlist;
  current->filesystemlist = dev;

  reset_filesystemset();

}


/*
 * Add a new icmp object to the current service's icmp list
 */
static void addicmp(Icmp_T is) {
  Icmp_T icmp;

  ASSERT(is);

  NEW(icmp);
  icmp->type         = is->type;      
  icmp->count        = is->count;
  icmp->timeout      = is->timeout;
  icmp->action       = is->action;
  icmp->is_available = FALSE;
  icmp->response     = -1;
  
  icmp->next         = current->icmplist;
  current->icmplist  = icmp;

  reset_icmpset();
}


/*
 * Set EventAction object
 */
static void addeventaction(EventAction_T *_ea, int failed, int succeeded) {
  EventAction_T ea;

  ASSERT(_ea);

  NEW(ea);
  NEW(ea->failed);
  NEW(ea->succeeded);

  ea->failed->id     = failed;
  ea->failed->count  = rate1.count;
  ea->failed->cycles = rate1.cycles;
  if (failed == ACTION_EXEC) {
    ASSERT(command1);
    ea->failed->exec = command1;
    command1 = NULL;
  }

  ea->succeeded->id     = succeeded;
  ea->succeeded->count  = rate2.count;
  ea->succeeded->cycles = rate2.cycles;
  if (succeeded == ACTION_EXEC) {
    ASSERT(command2);
    ea->succeeded->exec = command2;
    command2 = NULL;
  }
  *_ea = ea;
  reset_rateset();
}


/*
 * Redefine EventAction object (used for default action overloading)
 */
static void seteventaction(EventAction_T *_ea, int failed, int succeeded) {
  EventAction_T ea = *_ea;

  ASSERT(ea);
  ASSERT(ea->failed);
  ASSERT(ea->succeeded);

  ea->failed->id     = failed;
  ea->failed->count  = rate1.count;
  ea->failed->cycles = rate1.cycles;
  if (failed == ACTION_EXEC) {
    ASSERT(command1);
    ea->failed->exec = command1;
    command1 = NULL;
  }

  ea->succeeded->id     = succeeded;
  ea->succeeded->count  = rate2.count;
  ea->succeeded->cycles = rate2.cycles;
  if (succeeded == ACTION_EXEC) {
    ASSERT(command2);
    ea->succeeded->exec = command2;
    command2 = NULL;
  }
}


/*
 * Return a protocol object for the given protocol
 */
static void *addprotocol(int protocol) {

  switch (protocol) {
  case P_APACHESTATUS:  return create_apache_status();
  case P_DNS:           return create_dns();
  case P_DWP:           return create_dwp();
  case P_FTP:           return create_ftp();
  case P_GENERIC:       return create_generic();
  case P_HTTP:          return create_http();
  case P_IMAP:          return create_imap();
  case P_CLAMAV:        return create_clamav();
  case P_LDAP2:         return create_ldap2();
  case P_LDAP3:         return create_ldap3();
  case P_MYSQL:         return create_mysql();
  case P_NNTP:          return create_nntp();
  case P_NTP3:          return create_ntp3();
  case P_POSTFIXPOLICY: return create_postfix_policy();
  case P_POP:           return create_pop();
  case P_SMTP:          return create_smtp();
  case P_SSH:           return create_ssh();
  case P_RDATE:         return create_rdate();
  case P_RSYNC:         return create_rsync();
  case P_TNS:           return create_tns();
  case P_PGSQL:         return create_pgsql();
  case P_SIP:           return create_sip();
  case P_LMTP:          return create_lmtp();
  case P_GPS:           return create_gps();
  case P_RADIUS:        return create_radius();
  case P_MEMCACHE:      return create_memcache();
  }

  return create_default();
   
}


/*
 * Add a generic protocol handler to 
 */
static void addgeneric(Port_T port, char *send, char *expect) {
  Generic_T g = port->generic;
  
  if (g == NULL) {
    NEW(g);
    port->generic = g;
  } else {
    while (g->next != NULL)
      g = g->next;
    NEW(g->next);
    g = g->next;
  }
  
  if (send != NULL) {
    g->send = xstrdup(send);
    g->expect = NULL;
  } else if (expect != NULL) {
#ifdef HAVE_REGEX_H
    
    int   reg_return;
    NEW(g->expect);
    reg_return = regcomp(g->expect, expect, REG_NOSUB|REG_EXTENDED);
    if (reg_return != 0) {
      char errbuf[STRLEN];
      regerror(reg_return, g->expect, errbuf, STRLEN);
      yyerror2("regex parsing error:%s", errbuf);
    }
#else
    g->expect = xstrdup(expect);
#endif
    g->send = NULL;
  } 
}


/*
 * Add the current command object to the current service object's
 * start or stop program.
 */
static void addcommand(int what, unsigned timeout) {

  switch(what) {
  case START: current->start = command; break;
  case STOP:  current->stop = command; break;
  }

  command->timeout = timeout;
  
  command = NULL;
  
}

  
/*
 * Add a new argument to the argument list
 */
static void addargument(char *argument) {

  ASSERT(argument);

  if (! command) {
    
    NEW(command);
    check_exec(argument);
    
  }
  
  command->arg[command->length++] = argument;
  command->arg[command->length] = NULL;
  
  if (command->length >= ARGMAX)
    yyerror("exceeded maximum number of program arguments");
  
}


/*
 * Setup a url request for the current port object
 */
static void prepare_urlrequest(URL_T U) {

  ASSERT(U);
  
  portset.protocol = addprotocol(P_HTTP);

  if (urlrequest == NULL)
    NEW(urlrequest);
  urlrequest->url = U;
  portset.hostname = xstrdup(U->hostname);
  check_hostname(portset.hostname);
  portset.port = U->port;
  portset.url_request = urlrequest;
  portset.type = SOCK_STREAM;
  portset.request = Util_getString("%s%s%s", U->path, U->query ? "?" : "", U->query ? U->query : "");
  /* Only the HTTP protocol is supported for URLs.
     See also the lexer if this is to be changed in
     the future */
  portset.protocol = addprotocol(P_HTTP);
  if (IS(U->protocol, "https"))
    portset.SSL.use_ssl = TRUE;
  
}


/*
 * Set the url request for a port
 */
static void  seturlrequest(int operator, char *regex) {
  
  ASSERT(regex);

  if (! urlrequest)
    NEW(urlrequest);
  urlrequest->operator = operator;
#ifdef HAVE_REGEX_H
  {    
    int reg_return;
    NEW(urlrequest->regex);
    reg_return = regcomp(urlrequest->regex, regex, REG_NOSUB|REG_EXTENDED);
    if (reg_return != 0) {
      char errbuf[STRLEN];
      regerror(reg_return, urlrequest->regex, errbuf, STRLEN);
      yyerror2("regex parsing error: %s", errbuf);
    }
  }
#else
  urlrequest->regex = xstrdup(regex);
#endif

}


/*
 * Add a new data recipient server to the mmonit server list
 */
static void addmmonit(URL_T url, int timeout, int sslversion, char *certmd5) {
  Mmonit_T c;
  
  ASSERT(url);

  NEW(c);
  c->url = url;
  if (!strcmp(c->url->protocol, "https")) {
    if (!have_ssl()) {
      yyerror("ssl check cannot be activated. SSL is not supported");
    } else {
      c->ssl.use_ssl = TRUE;
      c->ssl.version = (sslversion == SSL_VERSION_NONE) ? SSL_VERSION_AUTO : sslversion;
      if (certmd5) {
	c->ssl.certmd5 = certmd5;
	cleanup_hash_string(c->ssl.certmd5);
      }
    }
  }
  c->timeout = timeout;
  c->next = NULL;

  if (Run.mmonits) {
    Mmonit_T C;
    for (C = Run.mmonits; C->next; C = C->next)
      /* Empty */ ;
    C->next = c;
  } else {
    Run.mmonits = c;
  }
}


/*
 * Add a new smtp server to the mail server list
 */
static void addmailserver(MailServer_T mailserver) {

  MailServer_T s;
  
  ASSERT(mailserver->host);

  NEW(s);
  s->host        = mailserver->host;
  s->port        = mailserver->port;
  s->username    = mailserver->username;
  s->password    = mailserver->password;
  s->ssl.use_ssl = mailserver->ssl.use_ssl;
  s->ssl.version = mailserver->ssl.version;
  s->ssl.certmd5 = mailserver->ssl.certmd5;

  s->next = NULL;

  if (Run.mailservers) {
    MailServer_T l;
    for (l = Run.mailservers; l->next; l = l->next) /* empty */;
    l->next = s;
  } else {
    Run.mailservers = s;
  }
  
  reset_mailserverset();
}


/*
 * Return uid if found on the system. If the parameter user is NULL
 * the uid parameter is used for looking up the user id on the system,
 * otherwise the user parameter is used.
 */
static uid_t get_uid(char *user, uid_t uid) {
  struct passwd *pwd;

  if (user) {
    pwd = getpwnam(user);

    if (pwd == NULL) {
      yyerror2("requested user not found on the system");
      return(0);
    }

  } else {

    if ( (pwd = getpwuid(uid)) == NULL ) {
      yyerror2("requested uid not found on the system");
      return(0);
    }
  }

  return(pwd->pw_uid);

}


/*
 * Return gid if found on the system. If the parameter group is NULL
 * the gid parameter is used for looking up the group id on the system,
 * otherwise the group parameter is used.
 */
static gid_t get_gid(char *group, gid_t gid) {
  struct group *grd;

  if (group) {
    grd = getgrnam(group);

    if (grd == NULL) {
      yyerror2("requested group not found on the system");
      return(0);
    }

  } else {

    if ( (grd = getgrgid(gid)) == NULL ) {
      yyerror2("requested gid not found on the system");
      return(0);
    }

  }

  return(grd->gr_gid);

}


/*
 * Add a new user id to the current command object.
 */
static void addeuid(uid_t uid) {
  if (!getuid()) {
    command->has_uid = TRUE;
    command->uid = uid;
  } else
    yyerror("uid statement requires root privileges");
}


/*
 * Add a new group id to the current command object.
 */
static void addegid(gid_t gid) {
  if (!getuid()) {
    command->has_gid = TRUE;
    command->gid = gid;
  } else
    yyerror("gid statement requires root privileges");
}


/*
 * Reset the logfile if changed
 */
static void setlogfile(char *logfile) {
  if (Run.logfile) {
    if (IS(Run.logfile, logfile)) {
      FREE(logfile);
      return;
    } else
      FREE(Run.logfile);
  }
  Run.logfile = logfile;
}


/*
 * Reset the pidfile if changed
 */
static void setpidfile(char *pidfile) {
  if (Run.pidfile) {
    if (IS(Run.pidfile, pidfile)) {
      FREE(pidfile);
      return;
    } else
      FREE(Run.pidfile);
  }
  Run.pidfile = pidfile;
}


/*
 * Read a apache htpasswd file and add credentials found for username
 */
static void addhtpasswdentry(char *filename, char *username, int dtype) {
  char *ht_username = NULL;
  char *ht_passwd = NULL;
  char buf[STRLEN];
  FILE *handle = NULL;
  int credentials_added = 0;
  
  ASSERT(filename);

  handle = fopen(filename, "r");

  if ( handle == NULL ) {
    if (username != NULL)
      yyerror2("cannot read htpasswd (%s)", filename);
    else
      yyerror2("cannot read htpasswd", filename);
    return;
  }
  
  while (!feof(handle)) {
    char *colonindex = NULL;
    int i;
    
    if (! fgets(buf, STRLEN, handle))
      continue;

    /* strip trailing non visible characters */
    for (i = strlen(buf)-1; i >= 0; i--) {
      if ( buf[i] == ' '  || buf[i] == '\r' || buf[i] == '\n' || buf[i] == '\t' )
        buf[i] ='\0';
      else
        break;
    }

    if ( NULL == (colonindex = strchr(buf, ':')))
      continue;

    ht_passwd = xstrdup(colonindex+1);
    *colonindex = '\0';

    /* In case we have a file in /etc/passwd or /etc/shadow style we
     *  want to remove ":.*$" and Crypt and MD5 hashed dont have a colon
     */ 
    
    if ( (NULL != (colonindex = strchr(ht_passwd, ':'))) && ( dtype != DIGEST_CLEARTEXT) )
      *colonindex = '\0';

    ht_username = xstrdup(buf);

    if (username == NULL) {
      if (addcredentials(ht_username, ht_passwd, dtype, FALSE))
        credentials_added++;
    } else if (strcmp(username, ht_username) == 0)  {
      if (addcredentials(ht_username, ht_passwd, dtype, FALSE))
        credentials_added++;
    } else {
      FREE(ht_passwd);
      FREE(ht_username);
    }
  }

  if (credentials_added == 0) {
    if ( username == NULL )
      yywarning2("htpasswd file (%s) has no usable credentials", filename);
    else
      yywarning2("htpasswd file (%s) has no usable credentials for user %s", filename, username);
  }
  fclose(handle);
}


#ifdef HAVE_LIBPAM
static void addpamauth(char* groupname, int readonly) {
  Auth_T c = NULL;
  Auth_T prev = NULL;

  ASSERT(groupname);

  if (Run.credentials == NULL)
    NEW(Run.credentials);

  c = Run.credentials;
  do {
    if (c->groupname != NULL && IS(c->groupname, groupname)) {
      yywarning2("PAM group %s was added already, entry ignored", groupname);
      FREE(groupname);
      return;
    }
    prev = c;
    c = c->next;
  } while (c != NULL);

  NEW(prev->next);
  c = prev->next;

  c->next        = NULL;
  c->uname       = NULL;
  c->passwd      = NULL;
  c->groupname   = groupname;
  c->digesttype  = DIGEST_PAM;
  c->is_readonly = readonly;
  
  DEBUG("%s: Adding PAM group '%s'.\n", prog, groupname); 

  return;
}
#endif


/*
 * Add Basic Authentication credentials
 */
static int addcredentials(char *uname, char *passwd, int dtype, int readonly) {
  Auth_T c;

  ASSERT(uname);
  ASSERT(passwd);

  if (Run.credentials == NULL) {
    NEW(Run.credentials);
    c = Run.credentials;
  } else {

    if (Util_getUserCredentials(uname) != NULL) {
      yywarning2("credentials for user %s were already added, entry ignored", uname);
      FREE(uname);
      FREE(passwd);
      return FALSE;
    }

    c = Run.credentials;

    while ( c->next != NULL )
      c = c->next;

    NEW(c->next);
    c = c->next;
        
  }
  
  c->next        = NULL;
  c->uname       = uname;
  c->passwd      = passwd;
  c->groupname   = NULL;
  c->digesttype  = dtype;
  c->is_readonly = readonly;
  
  DEBUG("%s: Debug: Adding credentials for user '%s'.\n", prog, uname); 
  
  return TRUE;
  
}


/*
 * Set the syslog and the facilities to be used
 */
static void setsyslog(char *facility) {

  if (!Run.logfile || ihp.logfile) {
    ihp.logfile = TRUE;
    setlogfile(xstrdup("syslog"));
    Run.use_syslog = TRUE;
    Run.dolog = TRUE;
  }

  if (facility) {
    if (IS(facility,"log_local0"))
      Run.facility = LOG_LOCAL0;
    else if (IS(facility, "log_local1"))
      Run.facility = LOG_LOCAL1;
    else if (IS(facility, "log_local2"))
      Run.facility = LOG_LOCAL2;
    else if (IS(facility, "log_local3"))
      Run.facility = LOG_LOCAL3;
    else if (IS(facility, "log_local4"))
      Run.facility = LOG_LOCAL4;
    else if (IS(facility, "log_local5"))
      Run.facility = LOG_LOCAL5;
    else if (IS(facility, "log_local6"))
      Run.facility = LOG_LOCAL6;
    else if (IS(facility, "log_local7"))
      Run.facility = LOG_LOCAL7;
    else if (IS(facility, "log_daemon"))
      Run.facility = LOG_DAEMON;
    else
      yyerror2("invalid syslog facility");
  } else {
    Run.facility = LOG_USER;
  }
  
}


/*
 * Reset the current mailset, eventset and reminder for reuse
 */
static void reset_mailset() {
  memset(&mailset, 0, sizeof(struct mymail));
  eventset = Event_Null;
}


/*
 * Reset the mailserver set to default values
 */
static void reset_mailserverset() {
  memset(&mailserverset, 0, sizeof(struct mymailserver));
  mailserverset.port = PORT_SMTP;
  mailserverset.ssl.use_ssl = FALSE;
  mailserverset.ssl.version = SSL_VERSION_AUTO;
}


/*
 * Reset the Port set to default values
 */
static void reset_portset() {
  memset(&portset, 0, sizeof(struct myport));
  portset.socket = -1;
  portset.type = SOCK_STREAM;
  portset.family = AF_INET;
  portset.SSL.version = SSL_VERSION_AUTO;
  portset.timeout = NET_TIMEOUT;
  portset.maxforward = 70;
  urlrequest = NULL;
}


/*
 * Reset the Proc set to default values
 */
static void reset_resourceset() {
  resourceset.resource_id = 0;
  resourceset.limit = 0;
  resourceset.action = NULL;
  resourceset.operator = OPERATOR_EQUAL;
}


/*
 * Reset the Timestamp set to default values
 */
static void reset_timestampset() {
  timestampset.operator = OPERATOR_EQUAL;
  timestampset.time = 0;
  timestampset.test_changes = FALSE;
  timestampset.action = NULL;
}


/*
 * Reset the ActionRate set to default values
 */
static void reset_actionrateset() {
  actionrateset.count = 0;
  actionrateset.cycle = 0;
  actionrateset.action = NULL;
}


/*
 * Reset the Size set to default values
 */
static void reset_sizeset() {
  sizeset.operator = OPERATOR_EQUAL;
  sizeset.size = 0;
  sizeset.test_changes = FALSE;
  sizeset.action = NULL;
}


/*
 * Reset the Checksum set to default values
 */
static void reset_checksumset() {
  checksumset.type         = HASH_UNKNOWN;
  checksumset.test_changes = FALSE;
  checksumset.action       = NULL;
  *checksumset.hash        = 0;
}


/*
 * Reset the Perm set to default values
 */
static void reset_permset() {
  permset.perm = 0;
  permset.action = NULL;
}


/*
 * Reset the Uid set to default values
 */
static void reset_uidset() {
  uidset.uid = 0;
  uidset.action = NULL;
}


/*
 * Reset the Gid set to default values
 */
static void reset_gidset() {
  gidset.gid = 0;
  gidset.action = NULL;
}


/*
 * Reset the Filesystem set to default values
 */
static void reset_filesystemset() {
  filesystemset.resource = 0;
  filesystemset.operator = OPERATOR_EQUAL;
  filesystemset.limit_absolute = -1;
  filesystemset.limit_percent = -1;
  filesystemset.action = NULL;
}


/*
 * Reset the ICMP set to default values
 */
static void reset_icmpset() {
  icmpset.type = ICMP_ECHO;
  icmpset.count = ICMP_ATTEMPT_COUNT;
  icmpset.timeout = NET_TIMEOUT;
  icmpset.action = NULL;
}


/*
 * Reset the Rate set to default values
 */
static void reset_rateset() {
  rate1.count  = 1;
  rate1.cycles = 1;

  rate2.count  = 1;
  rate2.cycles = 1;
}


/* ---------------------------------------------------------------- Checkers */


/*
 * Check for unique service name
 */
static void check_name(char *name) {
  ASSERT(name);

  if (Util_existService(name) || (current && IS(name, current->name)))
    yyerror2("service name conflict, %s already defined", name);
  if (name && *name == '/')		
          yyerror2("service name '%s' must not start with '/' -- ", name);	
}


/*
 * Permission statement semantic check
 */
static int check_perm(int perm) {
  long result;
  char *status;
  char buf[STRLEN];

  snprintf(buf, STRLEN, "%d", perm);

  result = strtol(buf, &status, 8);

  if ( *status != '\0' || result < 0 || result > 07777 )
    yyerror2("permission statements must have an octal value between 0 and 7777");

  return result;
}


/*
 * Every statement semantic check
 */
static void check_every(int every) {
  if (every <= 1)
    yyerror2("an EVERY statement must have a value greater than 1");
}


/*
 * Check hostname 
 */
static void check_hostname(char *hostname) {

  ASSERT(hostname);

  if (!check_host(hostname))
    yywarning2("hostname did not resolve");
}

/*
 * Check the dependency graph for errors
 * by doing a topological sort, thereby finding any cycles.
 * Assures that graph is a Directed Acyclic Graph (DAG).
 */
static void check_depend() {
  Service_T s;
  Service_T depends_on = NULL;
  Service_T* dlt = &depend_list; /* the current tail of it                                 */
  int done;                      /* no unvisited nodes left?                               */
  int found_some;                /* last iteration found anything new ?                    */
  depend_list = NULL;            /* depend_list will be the topological sorted servicelist */

  do { 
    done = TRUE;
    found_some = FALSE; 
    for (s = servicelist; s; s = s->next) {
        Dependant_T d;
      if (s->visited)
	  continue;
      done = FALSE; // still unvisited nodes
      depends_on = NULL;
      for (d = s->dependantlist; d; d = d->next) {
        Service_T dp = Util_getService(d->dependant);
        if (!dp) {
          LogError("%s: Error: Depend service '%s' is not defined in the control file\n", prog, d->dependant);
          exit(1);
        }
        if (!dp->visited) {
          depends_on = dp;
        }
      }

      if (!depends_on) {
        s->visited = TRUE;
        found_some = TRUE;
        *dlt = s;
        dlt = &s->next_depend;
      }
    }
  } while (found_some && !done);
	
  if (!done) {
        ASSERT(depends_on);
	LogError("%s: Error: Found a depend loop in the control file involving the service '%s'\n", prog, depends_on->name);
	exit(1);
   } 

  ASSERT(depend_list);
  servicelist = depend_list;
    
  for (s = depend_list; s; s = s->next_depend)
    s->next = s->next_depend;
    
  reset_depend();
}


/*
 * Check if the executable exist
 */
static void check_exec(char *exec) {
  if (! File_exist(exec))
    yywarning2("the executable does not exist");
}
 
 
/* Return a valid max forward value for SIP header */
static int verifyMaxForward(int mf) { 
  int max = 70;
  
  if (mf >= 0 && mf <= 255)
    max = mf;
  else
    yywarning2("SIP max forward is outside the range [0..255]. Setting max forward to 70");
  
  return max;
}


/* -------------------------------------------------------------------- Misc */


/*
 * Cleans up an md5 string, tolower and remove byte separators
 */
static int cleanup_hash_string(char *hashstring) {
  int i = 0, j = 0;

  ASSERT(hashstring);

  while (hashstring[i] != '\0') {
    if (isxdigit((int) hashstring[i])) {
      hashstring[j] = tolower((int)hashstring[i]);
      j++;
    } 
    i++;
  }
  hashstring[j] = '\0';
  return j;
}


/* Return deep copy of the command */
static Command_T copycommand(Command_T source) {
  int i;
  Command_T copy = NULL;

  NEW(copy);
  copy->length = source->length;
  copy->has_uid = source->has_uid;
  copy->uid = source->uid;
  copy->has_gid = source->has_gid;
  copy->gid = source->gid;
  copy->timeout = source->timeout;
  for (i = 0; i < copy->length; i++)
     copy->arg[i] = xstrdup(source->arg[i]);
  copy->arg[copy->length] = NULL;

  return copy;
}

