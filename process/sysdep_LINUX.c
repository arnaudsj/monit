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

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef TIME_WITH_SYS_TIME
#include <time.h>

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#else
#include <time.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_ASM_PARAM_H
#include <asm/param.h>
#endif

#ifdef HAVE_GLOB_H
#include <glob.h>
#endif

#ifndef HZ
# define HZ sysconf(_SC_CLK_TCK)
#endif

#include "monitor.h"
#include "process.h"
#include "process_sysdep.h"


/**
 *  System dependent resource gathering code for Linux.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Christian Hopp <chopp@iei.tu-clausthal.de>
 *  @author Martin Pala <martinp@tildeslash.com>
 *  @author Arkadiusz Miskiewicz <arekm@pld-linux.org>
 *
 *  @file
 */


/* ----------------------------------------------------------------- Private */


#define MEMTOTAL  "MemTotal:"
#define MEMFREE   "MemFree:"
#define MEMBUF    "Buffers:"
#define MEMCACHE  "Cached:"
#define SWAPTOTAL "SwapTotal:"
#define SWAPFREE  "SwapFree:"

#define NSEC_PER_SEC    1000000000L

static unsigned long long old_cpu_user     = 0;
static unsigned long long old_cpu_syst     = 0;
static unsigned long long old_cpu_wait     = 0;
static unsigned long long old_cpu_total    = 0;
static int                page_shift_to_kb = 0;


/**
 * Get system start time
 * @return seconds since unix epoch
 */
static time_t get_starttime() {
  char   buf[1024];
  double up = 0;

  if (! read_proc_file(buf, 1024, "uptime", -1, NULL)) {
    LogError("system statistic error -- cannot get system uptime\n");
    return 0;
  }

  if (sscanf(buf, "%lf", &up) != 1) {
    LogError("system statistic error -- invalid uptime\n");
    return 0;
  }

  return time(NULL) - (time_t)up;
}
  

/* ------------------------------------------------------------------ Public */


int init_process_info_sysdep(void) {
  char *ptr;
  char  buf[1024];
  long  page_size;
  int   page_shift;  

  if (! read_proc_file(buf, sizeof(buf), "meminfo", -1, NULL)) 
    return FALSE;
  if (! (ptr = strstr(buf, MEMTOTAL))) {
    DEBUG("system statistic error -- cannot get real memory amount\n");
    return FALSE;
  }
  if (sscanf(ptr+strlen(MEMTOTAL), "%ld", &systeminfo.mem_kbyte_max) != 1) {
    DEBUG("system statistic error -- cannot get real memory amount\n");
    return FALSE;
  }

  if ((systeminfo.cpus = sysconf(_SC_NPROCESSORS_CONF)) < 0) {
    DEBUG("system statistic error -- cannot get cpu count: %s\n", STRERROR);
    return FALSE;
  } else if (systeminfo.cpus == 0) {
    DEBUG("system reports cpu count 0, setting dummy cpu count 1\n");
    systeminfo.cpus = 1;
  }

  if ((page_size = sysconf(_SC_PAGESIZE)) <= 0) {
    DEBUG("system statistic error -- cannot get page size: %s\n", STRERROR);
    return FALSE;
  }

  for (page_shift = 0; page_size != 1; page_size >>= 1, page_shift++);
  page_shift_to_kb = page_shift - 10;

  return TRUE;
}


/**
 * Read all processes of the proc files system to initialize
 * the process tree (sysdep version... but should work for
 * all procfs based unices) 
 * @param reference  reference of ProcessTree
 * @return treesize>0 if succeeded otherwise =0.
 */
int initprocesstree_sysdep(ProcessTree_T ** reference) {
  int                 i = 0, j;
  int                 rv, bytes = 0;
  int                 treesize = 0;
  int                 stat_ppid = 0;
  char               *tmp = NULL;
  char                procname[STRLEN];
  char                buf[1024];
  char                stat_item_state;
  long                stat_item_cutime = 0;
  long                stat_item_cstime = 0;
  long                stat_item_rss = 0;
  glob_t              globbuf;
  unsigned long       stat_item_utime = 0;
  unsigned long       stat_item_stime = 0;
  unsigned long long  stat_item_starttime = 0ULL;
  ProcessTree_T      *pt = NULL;

  ASSERT(reference);

  /* Find all processes in the /proc directory */
  if ((rv = glob("/proc/[0-9]*", GLOB_ONLYDIR, NULL, &globbuf))) {
    LogError("system statistic error -- glob failed: %d (%s)\n", rv, STRERROR);
    return FALSE;
  } 

  treesize = globbuf.gl_pathc;

  pt = xcalloc(sizeof(ProcessTree_T), treesize);

  /* Insert data from /proc directory */
  for (i = 0; i < treesize; i++) {

    pt[i].pid = atoi(globbuf.gl_pathv[i] + strlen("/proc/"));
    
    if (!read_proc_file(buf, sizeof(buf), "stat", pt[i].pid, NULL)) {
      DEBUG("system statistic error -- cannot read /proc/%d/stat\n", pt[i].pid);
      continue;
    }

    pt[i].time = get_float_time();

    if (!(tmp = strrchr(buf, ')'))) {
      DEBUG("system statistic error -- file /proc/%d/stat parse error\n", pt[i].pid);
      continue;
    }
    *tmp = 0;
    if (sscanf(buf, "%*d (%256s", procname) != 1) {
      DEBUG("system statistic error -- file /proc/%d/stat process name parse error\n", pt[i].pid);
      continue;
    }

    tmp += 2;

    /* This implementation is done by using fs/procfs/array.c as a basis
     * it is also worth looking into the source of the procps utils */
    if (sscanf(tmp,
         "%c %d %*d %*d %*d %*d %*u %*u"
         "%*u %*u %*u %lu %lu %ld %ld %*d %*d %*d "
         "%*u %llu %*u %ld %*u %*u %*u %*u %*u "
         "%*u %*u %*u %*u %*u %*u %*u %*u %*d %*d\n",
         &stat_item_state,
         &stat_ppid,
         &stat_item_utime,
         &stat_item_stime,
         &stat_item_cutime,
         &stat_item_cstime,
         &stat_item_starttime,
         &stat_item_rss) != 8) {
      DEBUG("system statistic error -- file /proc/%d/stat parse error\n", pt[i].pid);
      continue;
    }
    
    pt[i].ppid      = stat_ppid;
    pt[i].starttime = get_starttime() + (time_t)(stat_item_starttime / HZ);
  
    /* jiffies -> seconds = 1 / HZ
     * HZ is defined in "asm/param.h"  and it is usually 1/100s but on
     * alpha system it is 1/1024s */
    pt[i].cputime     = ((float)(stat_item_utime + stat_item_stime) * 10.0) / HZ;
    pt[i].cpu_percent = 0;

    /* State is Zombie -> then we are a Zombie ... clear or? (-: */
    if (stat_item_state == 'Z')
      pt[i].status_flag |= PROCESS_ZOMBIE;

    if (page_shift_to_kb < 0)
      pt[i].mem_kbyte = (stat_item_rss >> abs(page_shift_to_kb));
    else
      pt[i].mem_kbyte = (stat_item_rss << abs(page_shift_to_kb));

    if (! read_proc_file(buf, sizeof(buf), "cmdline", pt[i].pid, &bytes)) {
      DEBUG("system statistic error -- cannot read /proc/%d/cmdline\n", pt[i].pid);
      continue;
    }
    /* The cmdline file contains argv elements/strings terminated separated by '\0' => join the string: */
    for (j = 0; j < (bytes - 1); j++)
      if (buf[j] == 0)
        buf[j] = ' ';
    pt[i].cmdline = *buf ? xstrdup(buf) : xstrdup(procname);
  }
  
  *reference = pt;
  globfree(&globbuf);

  return treesize;
}


/**
 * This routine returns 'nelem' double precision floats containing
 * the load averages in 'loadv'; at most 3 values will be returned.
 * @param loadv destination of the load averages
 * @param nelem number of averages
 * @return: 0 if successful, -1 if failed (and all load averages are 0).
 */
int getloadavg_sysdep (double *loadv, int nelem) {
  return getloadavg(loadv, nelem);
}


/**
 * This routine returns kbyte of real memory in use.
 * @return: TRUE if successful, FALSE if failed
 */
int used_system_memory_sysdep(SystemInfo_T *si) {
  char          *ptr;
  char           buf[1024];
  unsigned long  mem_free = 0UL;
  unsigned long  buffers = 0UL;
  unsigned long  cached = 0UL;
  unsigned long  swap_total = 0UL;
  unsigned long  swap_free = 0UL;
  
  if (! read_proc_file(buf, 1024, "meminfo", -1, NULL)) {
    LogError("system statistic error -- cannot get real memory free amount\n");
    goto error;
  }

  /* Memory */
  if (! (ptr = strstr(buf, MEMFREE)) || sscanf(ptr + strlen(MEMFREE), "%ld", &mem_free) != 1) {
    LogError("system statistic error -- cannot get real memory free amount\n");
    goto error;
  }
  if (! (ptr = strstr(buf, MEMBUF)) || sscanf(ptr + strlen(MEMBUF), "%ld", &buffers) != 1)
    DEBUG("system statistic error -- cannot get real memory buffers amount\n");
  if (! (ptr = strstr(buf, MEMCACHE)) || sscanf(ptr + strlen(MEMCACHE), "%ld", &cached) != 1)
    DEBUG("system statistic error -- cannot get real memory cache amount\n");
  si->total_mem_kbyte = systeminfo.mem_kbyte_max - mem_free - buffers - cached;

  /* Swap */
  if (! (ptr = strstr(buf, SWAPTOTAL)) || sscanf(ptr + strlen(SWAPTOTAL), "%ld", &swap_total) != 1) {
    LogError("system statistic error -- cannot get swap total amount\n");
    goto error;
  }
  if (! (ptr = strstr(buf, SWAPFREE)) || sscanf(ptr + strlen(SWAPFREE), "%ld", &swap_free) != 1) {
    LogError("system statistic error -- cannot get swap free amount\n");
    goto error;
  }
  si->swap_kbyte_max   = swap_total;
  si->total_swap_kbyte = swap_total - swap_free;

  return TRUE;

  error:
  si->total_mem_kbyte = 0;
  si->swap_kbyte_max = 0;
  return FALSE;
}


/**
 * This routine returns system/user CPU time in use.
 * @return: TRUE if successful, FALSE if failed (or not available)
 */
int used_system_cpu_sysdep(SystemInfo_T *si) {
  int                rv;
  unsigned long long cpu_total;
  unsigned long long cpu_user;
  unsigned long long cpu_nice;
  unsigned long long cpu_syst;
  unsigned long long cpu_idle;
  unsigned long long cpu_wait;
  unsigned long long cpu_irq;
  unsigned long long cpu_softirq;
  char               buf[1024];

  if (!read_proc_file(buf, 1024, "stat", -1, NULL)) {
    LogError("system statistic error -- cannot read /proc/stat\n");
    goto error;
  }

  rv = sscanf(buf, "cpu %llu %llu %llu %llu %llu %llu %llu",
         &cpu_user,
         &cpu_nice,
         &cpu_syst,
         &cpu_idle,
         &cpu_wait,
         &cpu_irq,
         &cpu_softirq);
  if (rv < 4) {
    LogError("system statistic error -- cannot read cpu usage\n");
    goto error;
  } else if (rv == 4) {
    /* linux 2.4.x doesn't support these values */
    cpu_wait    = 0;
    cpu_irq     = 0;
    cpu_softirq = 0;
  }

  cpu_total = cpu_user + cpu_nice + cpu_syst + cpu_idle + cpu_wait + cpu_irq + cpu_softirq;
  cpu_user  = cpu_user + cpu_nice;

  if (old_cpu_total == 0) {
    si->total_cpu_user_percent = -10;
    si->total_cpu_syst_percent = -10;
    si->total_cpu_wait_percent = -10;
  } else {
    unsigned long long delta = cpu_total - old_cpu_total;
  
    si->total_cpu_user_percent = (int)(1000 * (double)(cpu_user - old_cpu_user) / delta);
    si->total_cpu_syst_percent = (int)(1000 * (double)(cpu_syst - old_cpu_syst) / delta);
    si->total_cpu_wait_percent = (int)(1000 * (double)(cpu_wait - old_cpu_wait) / delta);
  }

  old_cpu_user  = cpu_user;
  old_cpu_syst  = cpu_syst;
  old_cpu_wait  = cpu_wait;
  old_cpu_total = cpu_total;
  return TRUE;

  error:
  si->total_cpu_user_percent = 0;
  si->total_cpu_syst_percent = 0;
  si->total_cpu_wait_percent = 0;
  return FALSE;
}


