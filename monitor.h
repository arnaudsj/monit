/*
 * Copyright (C) 2000-2011 Tildeslash Ltd. All rights reserved.
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


#ifndef MONITOR_H
#define MONITOR_H

#include <config.h>
#include <assert.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "ssl.h"
#include "socket.h"


#define VERSION            PACKAGE_VERSION
#define MONITRC            "monitrc"
#define TIMEFORMAT         "%Z %b %e %T"
#define STRERROR            strerror(errno)
#define STRLEN             256
#define ARGMAX             64
#define HTTP_CONTENT_MAX   (1024*1000)
/* Set event queue directory mode: "drwx------" */
#define QUEUEMASK          0077
/* Set file mode: "drw-------" */
#define PRIVATEMASK        0177
/* Set log file mode: "-rw-r-----" */
#define LOGMASK            0137
/* Set pid file mode: "-rw-r--r--" */
#define MYPIDMASK          0122
#define MYPIDDIR           PIDDIR
#define MYPIDFILE          "monit.pid"
#define MYSTATEFILE        "monit.state"
#define MYIDFILE           "monit.id"
#define MYEVENTLISTBASE    "/var/monit"

#define LOCALHOST          "localhost"

#define PORT_SMTP          25
#define PORT_SMTPS         465
#define PORT_HTTP          80
#define PORT_HTTPS         443

#define SSL_TIMEOUT        15

#define START_DELAY        0
#define EXEC_TIMEOUT       30

#define START_HTTP         1
#define STOP_HTTP          2

#define TRUE               1
#define FALSE              0

#define MONITOR_NOT        0
#define MONITOR_YES        1
#define MONITOR_INIT       2

#define STATE_SUCCEEDED    0
#define STATE_FAILED       1
#define STATE_CHANGED      2
#define STATE_CHANGEDNOT   3
#define STATE_INIT         4

#define MODE_ACTIVE        0
#define MODE_PASSIVE       1
#define MODE_MANUAL        2

#define OPERATOR_GREATER   0
#define OPERATOR_LESS      1
#define OPERATOR_EQUAL     2
#define OPERATOR_NOTEQUAL  3

#define TIME_SECOND        1
#define TIME_MINUTE        60
#define TIME_HOUR          3600
#define TIME_DAY           86400

#define ACTION_IGNORE      0
#define ACTION_ALERT       1
#define ACTION_RESTART     2
#define ACTION_STOP        3
#define ACTION_EXEC        4
#define ACTION_UNMONITOR   5
#define ACTION_START       6
#define ACTION_MONITOR     7

#define TYPE_FILESYSTEM    0
#define TYPE_DIRECTORY     1
#define TYPE_FILE          2
#define TYPE_PROCESS       3
#define TYPE_HOST          4
#define TYPE_SYSTEM        5
#define TYPE_FIFO          6
#define TYPE_STATUS        7

#define RESOURCE_ID_CPU_PERCENT       1
#define RESOURCE_ID_MEM_PERCENT       2
#define RESOURCE_ID_MEM_KBYTE         3
#define RESOURCE_ID_LOAD1             4
#define RESOURCE_ID_LOAD5             5
#define RESOURCE_ID_LOAD15            6
#define RESOURCE_ID_CHILDREN          7
#define RESOURCE_ID_TOTAL_MEM_KBYTE   8
#define RESOURCE_ID_TOTAL_MEM_PERCENT 9
#define RESOURCE_ID_INODE             10
#define RESOURCE_ID_SPACE             11
#define RESOURCE_ID_CPUUSER           12
#define RESOURCE_ID_CPUSYSTEM         13
#define RESOURCE_ID_CPUWAIT           14
#define RESOURCE_ID_TOTAL_CPU_PERCENT 15
#define RESOURCE_ID_SWAP_PERCENT      16
#define RESOURCE_ID_SWAP_KBYTE        17

#define DIGEST_CLEARTEXT   1
#define DIGEST_CRYPT       2
#define DIGEST_MD5         3
#define DIGEST_PAM         4

#define UNIT_BYTE          1
#define UNIT_KILOBYTE      1024
#define UNIT_MEGABYTE      1048580
#define UNIT_GIGABYTE      1073740000

#define HASH_UNKNOWN       0
#define HASH_MD5           1
#define HASH_SHA1          2
#define DEFAULT_HASH       HASH_MD5   
/* Length of the longest message digest in bytes */
#define MD_SIZE            65

#define PROTOCOL_NULL      0
#define PROTOCOL_HTTP      1
#define PROTOCOL_HTTPS     2

#define LEVEL_FULL         0
#define LEVEL_SUMMARY      1

#define LEVEL_NAME_FULL    "full"
#define LEVEL_NAME_SUMMARY "summary"

#define HANDLER_SUCCEEDED  0x0
#define HANDLER_ALERT      0x1
#define HANDLER_MMONIT     0x2
#define HANDLER_MAX        HANDLER_MMONIT

#define ICMP_ATTEMPT_COUNT      3         


/** ------------------------------------------------- Special purpose macros */


/* Replace the standard signal function with a more reliable using
 * sigaction. Taken from Stevens APUE book. */
typedef void Sigfunc(int);
Sigfunc *signal(int signo, Sigfunc * func);
#if defined(SIG_IGN) && !defined(SIG_ERR)
#define SIG_ERR ((Sigfunc *)-1)
#endif


/** ------------------------------------------------- General purpose macros */


#undef MAX
#define MAX(x,y) ((x) > (y) ? (x) : (y))
#undef MIN
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#define IS(a,b)  ((a&&b)?!strcasecmp(a, b):0)
#define DEBUG if(Run.debug) LogDebug
#define FLAG(x, y) (x & y) == y 
#define NVLSTR(x) (x?x:"")


/** ------------------------------------------------- Synchronization macros */


#define LOCK(mutex) do { pthread_mutex_t *_yymutex = &(mutex); \
        assert(pthread_mutex_lock(_yymutex)==0);
#define END_LOCK assert(pthread_mutex_unlock(_yymutex)==0); } while (0)


/** ---------------------------------- Object Constructor/"Destructor" macro */


#define NEW(p) ((p)= xcalloc(1, (long)sizeof *(p)))
#define FREE(p) ((void)(free(p), (p)= 0))


/** ------------------------------------------ Simple Assert Exception macro */


#define ASSERT(e) do { if(!(e)) { LogCritical("AssertException: " #e \
        " at %s:%d\naborting..\n", __FILE__, __LINE__); abort(); } } while(0)


/* --------------------------------------------------------- Data structures */
           

/** Message Digest type with size for the longest digest we will compute */
typedef char MD_T[MD_SIZE];


/** Defines an string buffer object */
typedef struct mybuffer {
  char          *buf;                               /**< String buffer       */
  size_t         bufsize;                           /**< String buffer size  */
  size_t         bufused;                           /**< String buffer usage */
} Buffer_T;


/**
 * Defines a Command with ARGMAX optional arguments. The arguments
 * array must be NULL terminated and the first entry is the program
 * itself. In addition, a user and group may be set for the Command
 * which means that the Command should run as a certain user and with
 * certain group.
 */
typedef struct mycommand {
  char *arg[ARGMAX];                             /**< Program with arguments */
  int   length;                       /**< The length of the arguments array */
  int   has_uid;          /**< TRUE if a new uid is defined for this Command */
  uid_t uid;         /**< The user id to switch to when running this Command */
  int   has_gid;          /**< TRUE if a new gid is defined for this Command */
  gid_t gid;        /**< The group id to switch to when running this Command */
  unsigned timeout;     /**< Max seconds which we wait for method to execute */
} *Command_T;


/** Defines an event action object */
typedef struct myaction {
    int       id;                                     /**< Action to be done */
    Command_T exec;                    /**< Optional command to be executed  */
    unsigned  count;           /**< Event count needed to trigger the action */
    unsigned  cycles;    /**< Cycles during which count limit can be reached */
} *Action_T;


/** Defines event's up and down actions */
typedef struct myeventaction {
  Action_T  failed;                  /**< Action in the case of failure down */
  Action_T  succeeded;                    /**< Action in the case of failure up */
} *EventAction_T;


/** Defines an url object */
typedef struct myurl {
  char *url;                                                  /**< Full URL */
  char *protocol;                                    /**< URL protocol type */
  char *user;                                        /**< URL user     part */
  char *password;                                    /**< URL password part */
  char *hostname;                                    /**< URL hostname part */
  int   port;                                        /**< URL port     part */
  char *path;                                        /**< URL path     part */
  char *query;                                       /**< URL query    part */
} *URL_T;


/** Defines a HTTP client request object */
typedef struct myrequest {
  URL_T url;                                               /**< URL request */
  int   operator;                 /**< Response content comparison operator */
#ifdef HAVE_REGEX_H
  regex_t *regex;                   /* regex used to test the response body */
#else
  char *regex;                 /* string to search for in the response body */
#endif
} *Request_T;


/** Defines an event notification and status receiver object */
typedef struct mymmonit {
  URL_T url;                                             /**< URL definition */
  Ssl_T ssl;                                             /**< SSL definition */
  int   timeout;              /**< The timeout to wait for connection or i/o */

  /** For internal use */
  struct mymmonit *next;                         /**< next receiver in chain */
} *Mmonit_T;


/** Defines a mailinglist object */
typedef struct mymail {
  char *to;                         /**< Mail address for alert notification */
  char *from;                                     /**< The mail from address */
  char *replyto;                              /**< Optional reply-to address */
  char *subject;                                       /**< The mail subject */
  char *message;                                       /**< The mail message */
  unsigned int events;  /*< Events for which this mail object should be sent */
  unsigned int reminder;              /*< Send error reminder each Xth cycle */

  /** For internal use */
  struct mymail *next;                          /**< next recipient in chain */
} *Mail_T;


/** Defines a mail server address */
typedef struct mymailserver {
  char *host;     /**< Server host address, may be a IP or a hostname string */
  int   port;                                               /**< Server port */
  char *username;                               /** < Username for SMTP_AUTH */
  char *password;                               /** < Password for SMTP_AUTH */
  Ssl_T ssl;                                             /**< SSL definition */

  /** For internal use */
  struct mymailserver *next;        /**< Next server to try on connect error */
} *MailServer_T;


typedef struct myauthentication {
  char *uname;                  /**< User allowed to connect to monit httpd */
  char *passwd;                                /**< The users password data */
  char *groupname;                                      /**< PAM group name */
  int   digesttype;                      /**< How did we store the password */
  int   is_readonly;     /**< TRUE if this is a read-only authenticated user*/
  struct myauthentication *next;       /**< Next credential or NULL if last */
} *Auth_T;


/** Defines process tree - data storage backend*/
typedef struct myprocesstree {
  int           pid;
  int           ppid;
  int           status_flag;
  time_t        starttime;
  char         *cmdline;
  
  int           visited;
  int           children_num;
  int           children_sum;
  int           cpu_percent;
  int           cpu_percent_sum;
  unsigned long mem_kbyte;
  unsigned long mem_kbyte_sum;

  /** For internal use */
  double        time;                                      /**< 1/10 seconds */
  double        time_prev;                                 /**< 1/10 seconds */
  long          cputime;                                   /**< 1/10 seconds */
  long          cputime_prev;                              /**< 1/10 seconds */
  
  int           parent;
  int          *children;
} ProcessTree_T;


/** Defines data for systemwide statistic */
typedef struct mysysteminfo {
  struct timeval collected;                    /**< When were data collected */
  int cpus;                                              /**< Number of CPUs */
  double loadavg[3];                                /**< Load average triple */
  unsigned long mem_kbyte_max;               /**< Maximal system real memory */
  unsigned long swap_kbyte_max;                               /**< Swap size */
  unsigned long total_mem_kbyte; /**< Total real memory in use in the system */
  unsigned long total_swap_kbyte;       /**< Total swap in use in the system */
  int    total_mem_percent;      /**< Total real memory in use in the system */
  int    total_swap_percent;            /**< Total swap in use in the system */
  int    total_cpu_user_percent;   /**< Total CPU in use in user space (pct.)*/
  int    total_cpu_syst_percent; /**< Total CPU in use in kernel space (pct.)*/
  int    total_cpu_wait_percent;      /**< Total CPU in use in waiting (pct.)*/
  struct utsname uname;        /**< Platform information provided by uname() */
} SystemInfo_T;


/** Defines a protocol object with protocol functions */
typedef struct myprotocol {
  const char *name;                                       /**< Protocol name */
  int(*check)(Socket_T);                 /**< Protocol verification function */
} *Protocol_T;


/** Defines a send/expect object used for generic protocol tests */
typedef struct mygenericproto {
  char *send;                           /* string to send, or NULL if expect */
#ifdef HAVE_REGEX_H
  regex_t *expect;                  /* regex code to expect, or NULL if send */
#else
  char *expect;                         /* string to expect, or NULL if send */
#endif
  /** For internal use */
  struct mygenericproto *next;
} *Generic_T;

/** Defines a port object */
typedef struct myport {
  volatile int socket;                       /**< Socket used for connection */
  int  type;                  /**< Socket type used for connection (UDP/TCP) */
  int  family;            /**< Socket family used for connection (INET/UNIX) */
  char *hostname;                                     /**< Hostname to check */
  int  port;                                                 /**< Portnumber */
  char *request;                              /**< Specific protocol request */
  char *request_checksum;     /**< The optional checksum for a req. document */
  char *request_hostheader;            /**< The optional Host: header to use */
  int  request_hashtype;  /**< The optional type of hash for a req. document */
  char *pathname;                   /**< Pathname, in case of an UNIX socket */
  int maxforward;            /**< Optional max forward for protocol checking */
  Generic_T generic;                                /**< Generic test handle */
  int timeout;   /**< The timeout in seconds to wait for connect or read i/o */
  int is_available;                /**< TRUE if the server/port is available */
  double response;                      /**< Socket connection response time */
  EventAction_T action;  /**< Description of the action upon event occurence */
  /** Apache-status specific parameters */
  struct apache_status {
    int loglimit;                  /**< Max percentatge of logging processes */
    int loglimitOP;                                   /**< loglimit operator */
    int closelimit;             /**< Max percentatge of closinging processes */
    int closelimitOP;                               /**< closelimit operator */
    int dnslimit;         /**< Max percentatge of processes doing DNS lookup */
    int dnslimitOP;                                   /**< dnslimit operator */
    int keepalivelimit;          /**< Max percentatge of keepalive processes */
    int keepalivelimitOP;                       /**< keepalivelimit operator */
    int replylimit;               /**< Max percentatge of replying processes */
    int replylimitOP;                               /**< replylimit operator */
    int requestlimit;     /**< Max percentatge of processes reading requests */
    int requestlimitOP;                           /**< requestlimit operator */
    int startlimit;            /**< Max percentatge of processes starting up */
    int startlimitOP;                               /**< startlimit operator */
    int waitlimit;  /**< Min percentatge of processes waiting for connection */
    int waitlimitOP;                                 /**< waitlimit operator */
    int gracefullimit;/**< Max percentatge of processes gracefully finishing */
    int gracefullimitOP;                         /**< gracefullimit operator */
    int cleanuplimit;      /**< Max percentatge of processes in idle cleanup */
    int cleanuplimitOP;                           /**< cleanuplimit operator */
  } ApacheStatus;
  
  Ssl_T SSL;                                             /**< SSL definition */
  Protocol_T protocol;     /**< Protocol object for testing a port's service */
  Request_T url_request;             /**< Optional url client request object */
  
  /** For internal use */
  struct myport *next;                               /**< next port in chain */
} *Port_T;


/** Defines a ICMP object */
typedef struct myicmp {
  int type;                                              /**< ICMP type used */
  int count;                                   /**< ICMP echo requests count */
  int timeout;              /**< The timeout in seconds to wait for response */
  int is_available;                     /**< TRUE if the server is available */
  double response;                              /**< ICMP ECHO response time */
  EventAction_T action;  /**< Description of the action upon event occurence */
  
  /** For internal use */
  struct myicmp *next;                               /**< next icmp in chain */
} *Icmp_T;


typedef struct myservicegroupmember {
  char *name;                                           /**< name of service */

  /** For internal use */
  struct myservicegroupmember *next;              /**< next service in chain */
} *ServiceGroupMember_T;


typedef struct myservicegroup {
  char *name;                                     /**< name of service group */
  struct myservicegroupmember *members;           /**< Service group members */

  /** For internal use */
  struct myservicegroup *next;              /**< next service group in chain */
} *ServiceGroup_T;


typedef struct mydependant {
  char *dependant;                            /**< name of dependant service */

  /** For internal use */
  struct mydependant *next;             /**< next dependant service in chain */
} *Dependant_T;


/** Defines resource data */
typedef struct myresource {
  int  resource_id;                              /**< Which value is checked */
  long limit;                                     /**< Limit of the resource */
  int  operator;                                    /**< Comparison operator */
  EventAction_T action;  /**< Description of the action upon event occurence */
  
  /** For internal use */
  struct myresource *next;                       /**< next resource in chain */
} *Resource_T;


/** Defines timestamp object */
typedef struct mytimestamp {
  int  operator;                                    /**< Comparison operator */
  int  time;                                        /**< Timestamp watermark */
  int  test_changes;            /**< TRUE if we only should test for changes */
  time_t timestamp; /**< The original last modified timestamp for this object*/
  EventAction_T action;  /**< Description of the action upon event occurence */
  
  /** For internal use */
  struct mytimestamp *next;                     /**< next timestamp in chain */
} *Timestamp_T;


/** Defines action rate object */
typedef struct myactionrate {
  int  count;                                            /**< Action counter */
  int  cycle;                                             /**< Cycle counter */
  EventAction_T action;    /**< Description of the action upon matching rate */
 
  /** For internal use */
  struct myactionrate *next;                   /**< next actionrate in chain */
} *ActionRate_T;


/** Defines size object */
typedef struct mysize {
  int  operator;                                    /**< Comparison operator */
  unsigned long long size;                               /**< Size watermark */
  int  test_changes;            /**< TRUE if we only should test for changes */
  int  test_changes_ok;   /**< TRUE if size was initialized for changes test */
  EventAction_T action;  /**< Description of the action upon event occurence */
  
  /** For internal use */
  struct mysize *next;                          /**< next timestamp in chain */
} *Size_T;


/** Defines checksum object */
typedef struct mychecksum {
  MD_T  hash;                     /**< A checksum hash computed for the path */
  int   type;                       /**< The type of hash (e.g. md5 or sha1) */
  int   length;                                      /**< Length of the hash */
  int   test_changes;           /**< TRUE if we only should test for changes */
  int   test_changes_ok; /**< TRUE if cksum was initialized for changes test */
  EventAction_T action;  /**< Description of the action upon event occurence */
} *Checksum_T;


/** Defines permission object */
typedef struct myperm {
  int       perm;                                     /**< Access permission */
  EventAction_T action;  /**< Description of the action upon event occurence */
} *Perm_T;

/** Defines match object */
typedef struct mymatch {
  int     ignore;                                          /**< Ignore match */
  int     not;                                             /**< Invert match */
  char    *match_string;                                   /**< Match string */
  char    *match_path;                         /**< File with matching rules */
#ifdef HAVE_REGEX_H
  regex_t *regex_comp;                                    /**< Match compile */
#endif
  EventAction_T action;  /**< Description of the action upon event occurence */
 
  /** For internal use */
  struct mymatch *next;                             /**< next match in chain */
} *Match_T;


/** Defines uid object */
typedef struct myuid {
  uid_t     uid;                                            /**< Owner's uid */
  EventAction_T action;  /**< Description of the action upon event occurence */
} *Uid_T;


/** Defines gid object */
typedef struct mygid {
  gid_t     gid;                                            /**< Owner's gid */
  EventAction_T action;  /**< Description of the action upon event occurence */
} *Gid_T;


/** Defines filesystem configuration */
typedef struct myfilesystem {
  int  resource;                        /**< Whether to check inode or space */
  int  operator;                                    /**< Comparison operator */
  long limit_absolute;                               /**< Watermark - blocks */
  int  limit_percent;                               /**< Watermark - percent */
  EventAction_T action;  /**< Description of the action upon event occurence */

  /** For internal use */
  struct myfilesystem *next;                   /**< next filesystem in chain */
} *Filesystem_T;


/** Defines service data */
typedef struct myinfo {
  /* Shared */
  mode_t  st_mode;                                           /**< Permission */
  uid_t   st_uid;                                           /**< Owner's uid */
  gid_t   st_gid;                                           /**< Owner's gid */
  time_t  timestamp;                                          /**< Timestamp */

  union {
    struct {
      long   f_bsize;                               /**< Transfer block size */
      long   f_blocks;                  /**< Total data blocks in filesystem */
      long   f_blocksfree;       /**< Free blocks available to non-superuser */
      long   f_blocksfreetotal;               /**< Free blocks in filesystem */
      long   f_files;                    /**< Total file nodes in filesystem */
      long   f_filesfree;                 /**< Free file nodes in filesystem */
      char  *mntpath;          /**< Filesystem file, directory or mountpoint */
      int    inode_percent;                  /**< Used inode percentage * 10 */
      long   inode_total;                      /**< Used inode total objects */
      int    space_percent;                  /**< Used space percentage * 10 */
      long   space_total;                       /**< Used space total blocks */
      int    _flags;                   /**< Filesystem flags from last cycle */
      int    flags;                  /**< Filesystem flags from actual cycle */
    } filesystem;

    struct {
      off_t st_size;                                               /**< Size */
      off_t readpos;                        /**< Position for regex matching */
      ino_t st_ino;                                               /**< Inode */
      ino_t st_ino_prev;              /**< Previous inode for regex matching */
      MD_T  cs_sum;                                            /**< Checksum */
    } file;

    struct {
      int    _pid;                          /**< Process PID from last cycle */
      int    _ppid;                  /**< Process parent PID from last cycle */
      int    pid;                         /**< Process PID from actual cycle */
      int    ppid;                 /**< Process parent PID from actual cycle */
      int    status_flag;
      int    children;
      long   mem_kbyte;    
      long   total_mem_kbyte;
      int    mem_percent;                               /**< percentage * 10 */
      int    total_mem_percent;                         /**< percentage * 10 */
      int    cpu_percent;                               /**< percentage * 10 */
      int    total_cpu_percent;                         /**< percentage * 10 */
      time_t uptime;                                     /**< Process uptime */
    } process;
  } priv;
} *Info_T;


/** Defines service data */
typedef struct myservice {

  /** Common parameters */
  char *name;                                  /**< Service descriptive name */
  int (*check)(struct myservice *);       /**< Service verification function */
  int  type;                                     /**< Monitored service type */
  int  monitor;                                      /**< Monitor state flag */
  int  mode;                            /**< Monitoring mode for the service */
  int  ncycle;                          /**< The number of the current cycle */
  int  nstart;           /**< The number of current starts with this service */
  int  every;                        /**< Check this program at given cycles */
  int  nevery;          /**< Counter for every.  When nevery == every, check */
  int  def_every;              /**< TRUE if every is defined for the service */
  int  visited;      /**< Service visited flag, set if dependencies are used */
  int  depend_visited;/**< Depend visited flag, set if dependencies are used */
  Command_T start;                    /**< The start command for the service */
  Command_T stop;                      /**< The stop command for the service */

  Dependant_T dependantlist;                     /**< Dependant service list */
  Mail_T      maillist;                  /**< Alert notification mailinglist */

  /** Test rules and event handlers */
  ActionRate_T actionratelist;                    /**< ActionRate check list */
  Checksum_T  checksum;                                  /**< Checksum check */
  Filesystem_T filesystemlist;                    /**< Filesystem check list */
  Gid_T       gid;                                            /**< Gid check */
  Icmp_T      icmplist;                                 /**< ICMP check list */
  Perm_T      perm;                                    /**< Permission check */
  Port_T      portlist; /**< Portnumbers to check, either local or at a host */
  Resource_T  resourcelist;                          /**< Resouce check list */
  Size_T      sizelist;                                 /**< Size check list */
  Match_T     matchlist;                             /**< Content Match list */
  Timestamp_T timestamplist;                       /**< Timestamp check list */
  Uid_T       uid;                                            /**< Uid check */
  
  EventAction_T action_PID;                      /**< Action upon pid change */
  EventAction_T action_PPID;                    /**< Action upon ppid change */
  EventAction_T action_FSFLAG;      /**< Action upon filesystem flags change */

  /** General event handlers */
  EventAction_T action_DATA;       /**< Description of the action upon event */
  EventAction_T action_EXEC;       /**< Description of the action upon event */
  EventAction_T action_INVALID;    /**< Description of the action upon event */
  EventAction_T action_NONEXIST;   /**< Description of the action upon event */

  /** Internal monit events */
  EventAction_T action_MONIT_START;         /**< Monit instance start action */
  EventAction_T action_MONIT_STOP;           /**< Monit instance stop action */
  EventAction_T action_MONIT_RELOAD;       /**< Monit instance reload action */
  EventAction_T action_ACTION;           /**< Action requested by CLI or GUI */

  /** Runtime parameters */
  int                error;                          /**< Error flags bitmap */
  int                error_hint;   /**< Failed/Changed hint for error bitmap */
  Info_T             inf;                          /**< Service check result */
  struct timeval     collected;                /**< When were data collected */
  int                doaction;          /**< Action scheduled by http thread */
  char              *token;                                /**< Action token */

  /** Events */
  struct myevent {
    #define           EVENT_VERSION  3      /**< The event structure version */
    int               id;                      /**< The event identification */
    struct timeval    collected;                 /**< When the event occured */
    char             *source;                 /**< Event source service name */
    int               mode;             /**< Monitoring mode for the service */
    int               type;                      /**< Monitored service type */
    short             state;         /**< TRUE if failed, FALSE if succeeded */
    short             state_changed;              /**< TRUE if state changed */
    long long         state_map;           /**< Event bitmap for last cycles */
    unsigned int      count;                             /**< The event rate */
    unsigned int      flag;                     /**< The handlers state flag */
    char             *message;    /**< Optional message describing the event */
    EventAction_T     action;           /**< Description of the event action */
    /** For internal use */
    struct myevent   *next;                         /**< next event in chain */
    struct myevent   *previous;                 /**< previous event in chain */
  } *eventlist;                                     /**< Pending events list */

  /** Context specific parameters */
  char *path;  /**< Path to the filesys, file, directory or process pid file */
  
  /** For internal use */
  pthread_mutex_t   mutex;        /**< Mutex used for action synchronization */
  struct myservice *next;                         /**< next service in chain */
  struct myservice *next_conf;      /**< next service according to conf file */
  struct myservice *next_depend;           /**< next depend service in chain */
} *Service_T;


typedef struct myevent *Event_T;


/** Defines data for application runtime */
struct myrun {
  volatile int  stopped;/**< TRUE if monit was stopped. Flag used by threads */
  char *controlfile;                /**< The file to read configuration from */
  char *logfile;                         /**< The file to write logdata into */
  char *localhostname;                      /**< The host name for localhost */
  char *pidfile;                                  /**< This programs pidfile */
  char *idfile;                           /**< The file with unique monit id */
  char id[STRLEN];                                      /**< Unique monit id */
  char *statefile;                /**< The file with the saved runtime state */
  char *mygroup;                              /**< Group Name of the Service */
  int  debug;                   /**< Write debug information - TRUE or FALSE */
  int  use_syslog;                          /**< If TRUE write log to syslog */
  int  dolog;       /**< TRUE if program should log actions, otherwise FALSE */
  int  isdaemon;                 /**< TRUE if program should run as a daemon */
  int  polltime;        /**< In deamon mode, the sleeptime (sec) between run */
  int  startdelay;                    /**< the sleeptime (sec) after startup */
  int  dohttpd;                    /**< TRUE if monit HTTP server should run */
  int  httpdssl;                     /**< TRUE if monit HTTP server uses ssl */
  char *httpsslpem;                       /**< PEM file for the HTTPS server */
  int  clientssl;   /**< TRUE if monit HTTP server uses ssl with client auth */
  char *httpsslclientpem;      /**< PEM file/dir to check against at connect */
  int  allowselfcert;   /**< TRUE if self certified client certs are allowed */
  int  httpdsig;   /**< TRUE if monit HTTP server presents version signature */
  int  httpdport;                    /**< The monit http server's portnumber */
  int  once;                                       /**< TRUE - run only once */
  int  init;                   /**< TRUE - don't background to run from init */
  int  facility;              /** The facility to use when running openlog() */
  int  doprocess;                 /**< TRUE if process status engine is used */
  char *bind_addr;                  /**< The address monit http will bind to */
  volatile int  doreload;    /**< TRUE if a monit daemon should reinitialize */
  volatile int  dowakeup;  /**< TRUE if a monit daemon was wake up by signal */
  int  doaction;             /**< TRUE if some service(s) has action pending */
  mode_t umask;                /**< The initial umask monit was started with */
  int  testing;   /**< Running in configuration testing mode - TRUE or FALSE */
  time_t incarnation;              /**< Unique ID for running monit instance */
  int  handler_init;                  /**< The handlers queue initialization */
  int  handler_flag;                            /**< The handlers state flag */
  int  handler_queue[HANDLER_MAX+1];         /**< The handlers queue counter */
  Service_T system;                          /**< The general system service */
  char *eventlist_dir;                   /**< The event queue base directory */
  int  eventlist_slots;          /**< The event queue size - number of slots */
  int  expectbuffer; /**< Generic protocol expect buffer - STRLEN by default */

       /** An object holding program relevant "environment" data, see; env.c */
  struct myenvironment {
    char *user;             /**< The the effective user running this program */
    char *home;                                    /**< Users home directory */
    char *cwd;                                /**< Current working directory */
  } Env;

  char *mail_hostname;    /**< Used in HELO/EHLO/MessageID when sending mail */
  int mailserver_timeout;    /**< Connect and read timeout for a SMTP server */
  Mail_T maillist;                /**< Global alert notification mailinglist */
  MailServer_T mailservers;    /**< List of MTAs used for alert notification */
  Mmonit_T mmonits;        /**< Event notification and status receivers list */
  Auth_T credentials;    /** A list holding Basic Authentication information */
  int dommonitcredentials;   /**< TRUE if M/Monit should receive credentials */
  Auth_T mmonitcredentials;     /**< Pointer to selected credentials or NULL */
  Event_T eventlist;              /** A list holding partialy handled events */
                                      /** User selected standard mail format */
  struct myformat {
    char *from;                          /**< The standard mail from address */
    char *replyto;                             /**< Optional reply-to header */
    char *subject;                            /**< The standard mail subject */
    char *message;                            /**< The standard mail message */
  } MailFormat;
                                          
  pthread_mutex_t mutex;    /**< Mutex used for service data synchronization */
#ifdef OPENSSL_FIPS
  int fipsEnabled;                /** TRUE if monit should use FIPS-140 mode */
#endif
};


/* -------------------------------------------------------- Global variables */

extern char          *prog;
extern struct myrun   Run;
extern Service_T      servicelist;
extern Service_T      servicelist_conf;
extern ServiceGroup_T servicegrouplist;
extern SystemInfo_T   systeminfo;
extern ProcessTree_T *ptree;     
extern int            ptreesize;    
extern ProcessTree_T *oldptree;  
extern int            oldptreesize; 

extern char actionnames[][STRLEN];
extern char modenames[][STRLEN];
extern char checksumnames[][STRLEN];
extern char operatornames[][STRLEN];
extern char operatorshortnames[][3];
extern char monitornames[][STRLEN];
extern char statusnames[][STRLEN];
extern char servicetypes[][STRLEN];
extern char pathnames[][STRLEN];
extern char icmpnames[19][STRLEN];
extern char sslnames[][STRLEN];

/* ------------------------------------------------------- Public prototypes */

#include "util.h"
#include "file.h"

/* FIXME: move remaining prototypes into seperate header-files */

int   parse(char *);
int   control_service(const char *, int);
int   control_service_string(const char *, const char *);
int   control_service_daemon(const char *, const char *);
void  setup_dependants();
void  reset_depend();
void  spawn(Service_T, Command_T, Event_T);
int   status(char *);
int   log_init();
void  LogEmergency(const char *, ...);
void  LogAlert(const char *, ...);
void  LogCritical(const char *, ...);
void  LogError(const char *, ...);
void  LogWarning(const char *, ...);
void  LogNotice(const char *, ...);
void  LogInfo(const char *, ...);
void  LogDebug(const char *, ...);
void  log_close();
#ifndef HAVE_VSYSLOG
#ifdef HAVE_SYSLOG
void vsyslog (int, const char *, va_list);
#endif /* HAVE_SYSLOG */
#endif /* HAVE_VSYSLOG */
int   validate();
void  daemonize();
void  gc();
void  gc_mail_list(Mail_T *);
void  gccmd(Command_T *);
void  gc_event(Event_T *e);
int   kill_daemon(int);
int   exist_daemon(); 
int   sendmail(Mail_T);
int   sock_msg(int, char *, ...);
void  init_env();
void *xmalloc (int);
void *xcalloc(long, long);
char *xstrdup(const char *);
char *xstrndup(const char *, long);
void *xresize(void *, long);
void  monit_http(int);
int   can_http();
char *format(const char *, va_list, long *);
void  redirect_stdfd();
void  fd_close();
pid_t getpgid(pid_t);
#if ! HAVE_MALLOC
void *rpl_malloc (size_t __size);
#endif
void unset_signal_block(sigset_t *);
void set_signal_block(sigset_t *, sigset_t *);
int  check_process(Service_T);
int  check_filesystem(Service_T);
int  check_file(Service_T);
int  check_directory(Service_T);
int  check_remote_host(Service_T);
int  check_system(Service_T);
int  check_fifo(Service_T);
int  check_status(Service_T);
int  check_URL(Service_T s);
int  sha_md5_stream (FILE *, void *, void *);
void reset_procinfo(Service_T);
int  check_service_status(Service_T);
void printhash(char *);  
char *status_xml(Event_T, short, int, const char *);
int  handle_mmonit(Event_T);
int  do_wakeupcall();

#endif
