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


%option noyywrap


%{
  
/*
 * DESCRIPTION
 *   Lexical grammar for tokenizing the control file. 
 *
 *  AUTHOR
 *   Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *   Olivier Beyssac, <ob@r14.freenix.org>
 *   Christian Hopp, <chopp@iei.tu-clausthal.de>
 *   Martin Pala, <martinp@tildeslash.com>
 *
 */

#include <config.h>
  
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_GLOB_H
#include <glob.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "monitor.h"
#include "tokens.h"

#define MAX_STACK_DEPTH 128

  int buffer_stack_ptr=0;

  struct buffer_stack_s {
    int             lineno;
    char           *currentfile;
    YY_BUFFER_STATE buffer;
  } buffer_stack[MAX_STACK_DEPTH];
  
  
  int lineno= 1;
  int arglineno= 1;
  char *currentfile=NULL;
  char *argcurrentfile=NULL;
  char *argyytext=NULL;

  
  /* Prototypes */
  extern void yyerror(const char*,...);
	extern void  yywarning(const char *,...);
  static void steplinenobycr(char *);
  static void save_arg(void);
  static void include_file(char *);
  static char *handle_quoted_string(char *);
  static void push_buffer_state(YY_BUFFER_STATE, char*);
  static int  pop_buffer_state(void);
  static URL_T create_URL(char *proto);
  
%}

ws          [ \r\t]+
wws         [ \r\t;,()]+
number      [0-9]+
real        [0-9]+([.][0-9]+)?
str         [^\000-\041@:{}"';(),%]+
hostname    {str}(\.{str})*
greater     ("greater"|"gt"|">")
less        ("less"|"lt"|"<")
equal       ("equal"|"eq"|"=="|"=")
notequal    ("notequal"|"ne"|"!=")
loadavg1    load(avg)[ ]*(\([ ]*1[ ]*(m|min)?[ ]*\))?
loadavg5    load(avg)[ ]*\([ ]*5[ ]*(m|min)?[ ]*\)
loadavg15   load(avg)[ ]*\([ ]*15[ ]*(m|min)?[ ]*\)
cpuuser     cpu[ ]*(usage)*[ ]*\([ ]*(us|usr|user)?[ ]*\)
cpusyst     cpu[ ]*(usage)*[ ]*\([ ]*(sy|sys|system)?[ ]*\)
cpuwait     cpu[ ]*(usage)*[ ]*\([ ]*(wa|wait)?[ ]*\)
startarg    start{ws}?(program)?{ws}?([=]{ws})?["]
stoparg     stop{ws}?(program)?{ws}?([=]{ws})?["]
execarg     exec(ute)?{ws}?["]
percent     ("percent"|"%")
byte        ("byte"|"b")
kilobyte    ("kilobyte"|"kb")
megabyte    ("megabyte"|"mb")
gigabyte    ("gigabyte"|"gb")

%x ARGUMENT_COND DEPEND_COND SERVICE_COND URL_COND STRING_COND INCLUDE

%%

{wws}             { /* Wide white space */ }
(#.*)?\\?\n       { lineno++; } 

is                {/* EMPTY */}
as                {/* EMPTY */}
are               {/* EMPTY */}
for               {/* EMPTY */}
on(ly)?           {/* EMPTY */}
with(in|out)?     {/* EMPTY */}
program(s)?       {/* EMPTY */}
and               {/* EMPTY */}
has               {/* EMPTY */}
using             {/* EMPTY */}
use               {/* EMPTY */}
the               {/* EMPTY */}
sum               {/* EMPTY */}
than              {/* EMPTY */}
usage             {/* EMPTY */}
was               {/* EMPTY */}
times             {/* EMPTY */}
but               {/* EMPTY */}
of                {/* EMPTY */}
does              {/* EMPTY */}

{startarg}        { BEGIN(ARGUMENT_COND); return START; }
{stoparg}         { BEGIN(ARGUMENT_COND); return STOP; }
{execarg}         { BEGIN(ARGUMENT_COND); return EXEC; }

if                { return IF; }
or                { return OR; }
then              { return THEN; }
failed            { return FAILED; }
ssl               { return HTTPDSSL; }
enable            { return ENABLE; }
disable           { return DISABLE; }
set               { return SET; }
daemon            { return DAEMON; }
delay             { return DELAY; }
logfile           { return LOGFILE; }
syslog            { return SYSLOG; }
facility          { return FACILITY; }
httpd             { return HTTPD; }
address           { return ADDRESS; }
clientpemfile     { return CLIENTPEMFILE; }
allowselfcertification  { return ALLOWSELFCERTIFICATION; }
certmd5           { return CERTMD5; }
pemfile           { return PEMFILE; }
init              { return INIT; }
allow             { return ALLOW; }
read[-]?only      { return READONLY; }
pidfile           { return PIDFILE; }
idfile            { return IDFILE; }
statefile         { return STATEFILE; }
path              { return PATHTOK; }
start             { return START; }
stop              { return STOP; }
port(number)?     { return PORT; }
unix(socket)?     { return UNIXSOCKET; }
type              { return TYPE; }
proto(col)?       { return PROTOCOL; }
tcp               { return TCP; }
tcpssl            { return TCPSSL; }
udp               { return UDP; }
alert             { return ALERT; }
noalert           { return NOALERT; }
mail-format       { return MAILFORMAT; }
resource          { return RESOURCE; }
restart(s)?       { return RESTART; }
cycle(s)?         { return CYCLE;}
timeout           { return TIMEOUT; }
checksum          { return CHECKSUM; }
mailserver        { return MAILSERVER; }
every             { return EVERY; }
host              { return HOST; }
hostheader        { return HOSTHEADER; }
system            { return SYSTEM; }
default           { return DEFAULT; }
http              { return HTTP; }
apache-status     { return APACHESTATUS; }
ftp               { return FTP; }
smtp              { return SMTP; }
postfix-policy    { return POSTFIXPOLICY; }
pop               { return POP; }
imap              { return IMAP; }
clamav            { return CLAMAV; }
dns               { return DNS; }
mysql             { return MYSQL; }
nntp              { return NNTP; }
ntp3              { return NTP3; }
ssh               { return SSH; }
dwp               { return DWP; }
ldap2             { return LDAP2; }
ldap3             { return LDAP3; }
rdate             { return RDATE; }
lmtp              { return LMTP; }
rsync             { return RSYNC; }
tns               { return TNS; }
pgsql             { return PGSQL; }
sip               { return SIP; } 
gps               { return GPS; } 
radius            { return RADIUS; }
memcache          { return MEMCACHE; }
target            { return TARGET; }
maxforward        { return MAXFORWARD; }
mode              { return MODE; }
active            { return ACTIVE; }
passive           { return PASSIVE; }
manual            { return MANUAL; }
uid               { return UID; }
gid               { return GID; }
request           { return REQUEST; }
secret            { return SECRET; }
loglimit          { return LOGLIMIT; }
closelimit        { return CLOSELIMIT; }
dnslimit          { return DNSLIMIT; }
keepalivelimit    { return KEEPALIVELIMIT; }
replylimit        { return REPLYLIMIT; }
requestlimit      { return REQUESTLIMIT; }
startlimit        { return STARTLIMIT; }
waitlimit         { return WAITLIMIT; }
gracefullimit     { return GRACEFULLIMIT; }
cleanuplimit      { return CLEANUPLIMIT; }
mem(ory)?         { return MEMORY; }
swap              { return SWAP; }
totalmem(ory)?    { return TOTALMEMORY; }
cpu               { return CPU; }
totalcpu          { return TOTALCPU; }
child(ren)        { return CHILDREN; }
timestamp         { return TIMESTAMP; }
changed           { return CHANGED; }
second(s)?        { return SECOND; }
minute(s)?        { return MINUTE; }
hour(s)?          { return HOUR; }
day(s)?           { return DAY; }
sslv2             { return SSLV2; }
sslv3             { return SSLV3; }
tlsv1             { return TLSV1; }
sslauto           { return SSLAUTO; }
inode(s)?         { return INODE; }
space             { return SPACE; }
perm(ission)?     { return PERMISSION; }
exec(ute)?        { return EXEC; }
size              { return SIZE; }
basedir           { return BASEDIR; }
slot(s)?          { return SLOT; }
eventqueue        { return EVENTQUEUE; }
match(ing)?       { return MATCH; }
not               { return NOT; }
ignore            { return IGNORE; }
connection        { return CONNECTION; }
unmonitor         { return UNMONITOR; }
action            { return ACTION; }
icmp              { return ICMP; }
echo              { return ICMPECHO; }
send              { return SEND; }
expect            { return EXPECT; }
expectbuffer      { return EXPECTBUFFER; }
cleartext         { return CLEARTEXT; }
md5               { return MD5HASH; }
sha1              { return SHA1HASH; }
crypt             { return CRYPT; }
signature         { return SIGNATURE; }
nonexist          { return NONEXIST; }
exist             { return EXIST; }
invalid           { return INVALID; }
data              { return DATA; }
recovered         { return RECOVERED; }
passed            { return PASSED; }
succeeded         { return SUCCEEDED; }
else              { return ELSE; }
mmonit            { return MMONIT; }
url               { return URL; }
content           { return CONTENT; }
pid               { return PID; }
ppid              { return PPID; }
count             { return COUNT; }
reminder          { return REMINDER; }
instance          { return INSTANCE; }
hostname          { return HOSTNAME; }
username          { return USERNAME; }
password          { return PASSWORD; }
credentials       { return CREDENTIALS; }
register          { return REGISTER; }
fsflag(s)?        { return FSFLAG; }
fips              { return FIPS; }
{byte}            { return BYTE; }
{kilobyte}        { return KILOBYTE; }
{megabyte}        { return MEGABYTE; }
{gigabyte}        { return GIGABYTE; }
{loadavg1}        { return LOADAVG1; }
{loadavg5}        { return LOADAVG5; }
{loadavg15}       { return LOADAVG15; }
{cpuuser}         { return CPUUSER; }
{cpusyst}         { return CPUSYSTEM; }
{cpuwait}         { return CPUWAIT; }
{greater}         { return GREATER; }
{less}            { return LESS; }
{equal}           { return EQUAL; }
{notequal}        { return NOTEQUAL; }

include           { BEGIN(INCLUDE); }


depend(s)?[ \t]+(on[ \t]*)?  {
                    BEGIN(DEPEND_COND);
                    return DEPENDS;
                  } 

check[ \t]+(process[ \t])? {
                    BEGIN(SERVICE_COND);
                    return CHECKPROC;
                  }

check[ \t]+device { /* Filesystem alias for backward compatibility  */
                    BEGIN(SERVICE_COND);
                    return CHECKFILESYS;
                  }

check[ \t]+filesystem {
                    BEGIN(SERVICE_COND);
                    return CHECKFILESYS;
                  }

check[ \t]+file   {
                    BEGIN(SERVICE_COND);
                    return CHECKFILE;
                  }

check[ \t]+directory {
                    BEGIN(SERVICE_COND);
                    return CHECKDIR;
                  }

check[ \t]+host   {
                    BEGIN(SERVICE_COND);
                    return CHECKHOST;
                  }

check[ \t]+system {
                    BEGIN(SERVICE_COND);
                    return CHECKSYSTEM;
                  }

check[ \t]+fifo   {
                    BEGIN(SERVICE_COND);
                    return CHECKFIFO;
                  }

check[ \t]+status   {
                    BEGIN(SERVICE_COND);
                    return CHECKSTATUS;
                  }

group[ \t]+       {
                    BEGIN(STRING_COND);
                    return GROUP;
                  }

[a-zA-Z0-9]+"://" {
		    yylval.url= 
		      create_URL(xstrndup(yytext, strlen(yytext)-3));
                    BEGIN(URL_COND);
                  }

{number}          {
                    yylval.number= atoi(yytext);
                    save_arg(); return NUMBER;
                  }

{real}            {
                    yylval.real= atof(yytext);
                    save_arg(); return REAL;
                  }

{percent}         {
	            return PERCENT;
                  }

[a-zA-Z0-9]{str}  {
                    yylval.string= xstrdup(yytext);
                    save_arg(); return STRING;
                  }

\"[/][^\"\n]*\"   {
                    yylval.string= handle_quoted_string(yytext);
                    save_arg(); return PATH;
                  }

\'[/][^\'\n]*\'   {
                    yylval.string= handle_quoted_string(yytext);
                    save_arg(); return PATH;
                  }

\"[^\"]*\"        {
                    steplinenobycr(yytext);
                    yylval.string= handle_quoted_string(yytext);
                    save_arg(); return STRING;
                  }

\'[^\']*\'        {
                    steplinenobycr(yytext);
                    yylval.string= handle_quoted_string(yytext);
                    save_arg(); return STRING;
                  }

{str}[@]{str}     {
                    yylval.string= xstrdup(yytext);
                    save_arg(); return MAILADDR;
                  }

[/]{str}          {
                     yylval.string= xstrdup(yytext);
                     save_arg(); return PATH;
                  }

"/"               {
                     yylval.string= xstrdup(yytext);
                     save_arg(); return PATH;
                  }

"from:"[ \t]*{str}[@]{str} {
                      char *p= yytext+strlen("from:");
                      yylval.string = Util_trim(xstrdup(p));
                      save_arg(); return MAILFROM;
                  }

"reply-to:"[ \t]*{str}[@]{str} {
                      char *p= yytext+strlen("reply-to:");
                      yylval.string = Util_trim(xstrdup(p));
                      save_arg(); return MAILREPLYTO;
                  }

"subject:"[^}\n]* {
                      char *p= yytext+strlen("subject:");
                      yylval.string = Util_trim(xstrdup(p));
                      save_arg(); return MAILSUBJECT;
                  }

"message:"[^}]*   {
                      char *p= yytext+strlen("message:");
                      steplinenobycr(yytext);
                      yylval.string = Util_trim(xstrdup(p));
                      save_arg(); return MAILBODY;
                  }

{hostname}        {
                      yylval.string = xstrdup(yytext);
                      save_arg(); return STRING;
                  }

[\"\']            {
                      yyerror("unbalanced quotes");
                  }

<SERVICE_COND>{

  {ws}            ;

  [\n]            {
                    lineno++;
                  }

  {str}           {
                    yylval.string= xstrdup(yytext);
                    BEGIN(INITIAL);
                    save_arg(); return SERVICENAME;
                  }

  \"{str}\"       {
                    yylval.string= handle_quoted_string(yytext);
                    BEGIN(INITIAL);
                    save_arg(); return SERVICENAME;
                  }

  \'{str}\'       {
                    yylval.string= handle_quoted_string(yytext);
                    BEGIN(INITIAL);
                    save_arg(); return SERVICENAME;
                  }

  [\"\']          {
                      yyerror("unbalanced quotes");
                  }

}

<DEPEND_COND>{

  {wws}           ;

  {wws}?[\n]{wws}? {
                    lineno++;
                  }

  {str}           {
                    yylval.string= xstrdup(yytext);
                    save_arg(); return SERVICENAME;
                  }

  [ \r\n\t]+[^,]  {
                    steplinenobycr(yytext);
                    unput(yytext[strlen(yytext)-1]);
                    BEGIN(INITIAL);
                  }

}

<ARGUMENT_COND>{

  {ws}            ;

  [\n]            {
                    lineno++;
                  }

  \"              {
                      BEGIN(INITIAL);
                  }

  \'[^\']*\'      {
                      steplinenobycr(yytext);
                      yylval.string= handle_quoted_string(yytext);
                      save_arg(); return STRING;
                  }

  \'              {
                      yyerror("unbalanced quotes");
                  }

  [^ \t\n\"]+     {
                      yylval.string= xstrdup(yytext);
                      save_arg(); return STRING;
                  }

}

<URL_COND>{

  {ws}|[\n]       {
                      BEGIN(INITIAL);
		      if(!yylval.url->hostname)
			yyerror("missing hostname in URL");
		      if(!yylval.url->path)
			yylval.url->path= xstrdup("/");
                      yylval.url->url= Util_getString("%s://%s:%d%s%s%s",
                        yylval.url->protocol,
                        /* possible credentials are hidden */
                        yylval.url->hostname,
                        yylval.url->port,
                        yylval.url->path,
                        yylval.url->query?"?":"",
                        yylval.url->query?yylval.url->query:"");
		      save_arg(); return URLOBJECT;
                  }

  [^:@ ]+/[:][^@: ]+[@] {
	              yylval.url->user= xstrdup(yytext);
                  }

  [:][^@ ]+[@]    {
	              yytext++;
	              yylval.url->password= xstrndup(yytext, strlen(yytext)-1);
                  }

  [^/?:#\r\n ]+   {
	              yylval.url->hostname= xstrdup(yytext);
                  }

  [:]{number}     {
	              yylval.url->port= atoi(++yytext);
                  }

  [/][^?#\r\n ]*  {
	              yylval.url->path= Util_urlEncode(yytext);
                  }

  [?][^#\r\n ]*   {
	              yylval.url->query= Util_urlEncode(++yytext);
                  }

  [#][^\r\n ]*    { 
	              /* EMPTY - reference is ignored */ 
                  }

}

<STRING_COND>{

  {str}           {
                    yylval.string= xstrdup(yytext);
                    BEGIN(INITIAL);
                    save_arg(); return STRINGNAME;
                  }

  \"{str}\"       {
                    yylval.string= handle_quoted_string(yytext);
                    BEGIN(INITIAL);
                    save_arg(); return STRINGNAME;
                  }

  \'{str}\'       {
                    yylval.string= handle_quoted_string(yytext);
                    BEGIN(INITIAL);
                    save_arg(); return STRINGNAME;
                  }

  [\"\']          {
                      yyerror("unbalanced quotes");
                  }

}

<INITIAL,ARGUMENT_COND,SERVICE_COND,DEPEND_COND,URL_COND,STRING_COND>. {
                      return yytext[0];
                  }  


<INCLUDE>[ \t]*      /* eat the whitespace */

<INCLUDE>\"[^\"\r\n]+\" { /* got the include file name with double quotes */
                     char *temp=xstrdup(yytext);
                     Util_trimQuotes(temp);    
                     include_file(temp);
                     FREE(temp);
                     BEGIN(INITIAL);
                   }

<INCLUDE>\'[^\'\r\n]+\' { /* got the include file name with single quotes*/
                     char *temp=xstrdup(yytext);
                     Util_trimQuotes(temp);    
                     include_file(temp);
                     FREE(temp);
                     BEGIN(INITIAL);
                   }

<INCLUDE>[^ \t\r\n]+ { /* got the include file name without quotes*/
                     char *temp=xstrdup(yytext);
                     include_file(temp);
                     FREE(temp);
                     BEGIN(INITIAL);
                   }


<<EOF>>           {
                       
                       if ( !pop_buffer_state() )
                       {
                         yyterminate();
                       } else {
                         BEGIN(INITIAL);
                       }
                  }

%%

/*
 * Do lineno++ for every occurrence of '\n' in a string.  This is
 * necessary whenever a yytext has an unknown number of CRs.
 */

static void steplinenobycr(char *string) {

  char *pos= string;

  while(*pos)
    if('\n'==*pos++) {
      lineno++;
    }

}


static char *handle_quoted_string(char *string) {

  char *buf= xstrdup(string);

  Util_trimQuotes(buf);
  Util_handleEscapes(buf);

  return buf;

}


static void include_file(char *pattern) {
   
  glob_t globbuf;
  int i;

  if ( glob(pattern,  GLOB_MARK, NULL, &globbuf) != 0 ) {

    yywarning("include files not found");
    
    return;

  } 

  for (i = 0; i < globbuf.gl_pathc; i++) {
  
    FILE *yyin;
    int filename_length = strlen(globbuf.gl_pathv[i]);

    /* check whenever we have caught a directory
     * or file backup copy */

    if ((filename_length == 0) ||
        (globbuf.gl_pathv[i][filename_length-1] == '~' ) ||
        (globbuf.gl_pathv[i][filename_length-1] == '/' )) {

      continue;

    }

    yyin = fopen( globbuf.gl_pathv[i], "r" );
    
    if ( ! yyin ) {
      
      yyerror( "failed to include file" );
      
    } else {

      push_buffer_state(yy_create_buffer( yyin, YY_BUF_SIZE ), globbuf.gl_pathv[i]);

    }

  }

  globfree(&globbuf);
}


static void push_buffer_state(YY_BUFFER_STATE buffer, char *filename) {

  if ( buffer_stack_ptr >= MAX_STACK_DEPTH )
  {

    yyerror("include files are nested too deeply" );
    exit( 1 );
    
  }

  buffer_stack[buffer_stack_ptr].lineno = lineno;
  buffer_stack[buffer_stack_ptr].currentfile = currentfile;
  buffer_stack[buffer_stack_ptr].buffer = YY_CURRENT_BUFFER;

  buffer_stack_ptr++;

  lineno = 1;
  currentfile = xstrdup(filename);
      
  yy_switch_to_buffer(buffer);

  BEGIN(INITIAL);
  
}


static int pop_buffer_state(void) {

  if ( --buffer_stack_ptr < 0 ) {

    return 0;

  } else {
    
    fclose(yyin);
    lineno=buffer_stack[buffer_stack_ptr].lineno;

    FREE(currentfile);
    currentfile=buffer_stack[buffer_stack_ptr].currentfile;

    yy_delete_buffer( YY_CURRENT_BUFFER );
    yy_switch_to_buffer( buffer_stack[buffer_stack_ptr].buffer );
    
  }

  return 1;
 
}


static void save_arg(void) {
  
  arglineno=lineno;
  argcurrentfile=currentfile;
  FREE(argyytext);
  argyytext=xstrdup(yytext);
  
}


static URL_T create_URL(char *proto) {
  URL_T url;
  ASSERT(proto);
  NEW(url);
  url->protocol= proto;
  if(IS(url->protocol, "https")) {
    url->port= 443;
    if(!have_ssl())
      yyerror("HTTPS protocol not supported -- SSL support disabled" );
  } else if(IS(url->protocol, "http")) {
    url->port= 80;
  } else {
    yyerror("URL protocol not supported -- ");
  }
  return url;
}
