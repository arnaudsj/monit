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

#ifdef TIME_WITH_SYS_TIME
#include <time.h>

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#else
#include <time.h>
#endif

#ifdef HAVE_SYS_LOADAVG_H
#include <sys/loadavg.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_PROCFS_H
#include <procfs.h>
#endif

#ifdef HAVE_GLOB_H
#include <glob.h>
#endif

#ifdef HAVE_KSTAT_H
#include <kstat.h>
#endif

#ifdef HAVE_SYS_SWAP_H
#include <sys/swap.h>
#endif

#include <sys/sysinfo.h>

#include "monitor.h"
#include "process.h"
#include "process_sysdep.h"

/**
 *  System dependent resource gathering code for Solaris.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Christian Hopp <chopp@iei.tu-clausthal.de>
 *  @author Martin Pala <martinp@tildeslash.com>
 *
 *  @file
 */

#define pagetok(size) ((size) << pageshift)

static int    page_size;
static int    pageshift=0;
static long   old_cpu_user=0;
static long   old_cpu_syst=0;
static long   old_cpu_wait=0;
static long   old_total=0;

#define MAXSTRSIZE 80

#ifndef LOG1024
#define LOG1024         10
#endif

int init_process_info_sysdep(void) {
  register int pagesize;

  systeminfo.cpus = sysconf( _SC_NPROCESSORS_ONLN);

  pagesize  = sysconf(_SC_PAGESIZE);
  pageshift = 0;
  while (pagesize > 1) {
    pageshift++;
    pagesize >>= 1;
  }

  /* we only need the amount of log(2)1024 for our conversion */
  pageshift -= LOG1024;

  systeminfo.mem_kbyte_max = pagetok(sysconf(_SC_PHYS_PAGES));
  page_size = getpagesize();

  return (TRUE);
}

double timestruc_to_tseconds(timestruc_t t) {
  return  t.tv_sec * 10 + t.tv_nsec / 100000000.0;
}


/**
 * Read all processes of the proc files system to initialize
 * the process tree (sysdep version... but should work for
 * all procfs based unices)
 * @param reference  reference of ProcessTree
 * @return treesize>0 if succeeded otherwise =0.
 */
int initprocesstree_sysdep(ProcessTree_T ** reference) {
  int            i;
  int            rv;
  int            pid;
  int            treesize;
  char           buf[4096];
  glob_t         globbuf;
  pstatus_t      pstatus;
  psinfo_t      *psinfo = (psinfo_t *)&buf;
  ProcessTree_T *pt;

  ASSERT(reference);

  /* Find all processes in the /proc directory */
  if ((rv = glob("/proc/[0-9]*", NULL, NULL, &globbuf)) != 0) {
    LogError("system statistic error -- glob failed: %d (%s)\n", rv, STRERROR);
    return 0;
  }

  treesize = globbuf.gl_pathc;

  /* Allocate the tree */
  pt = xcalloc(sizeof(ProcessTree_T), treesize);

  /* Insert data from /proc directory */
  for (i = 0; i < treesize; i++) {
    pid = atoi(globbuf.gl_pathv[i] + strlen("/proc/"));
    pt[i].pid = pid;

    /* get the actual time */
    pt[i].time = get_float_time();

    if (! read_proc_file(buf, sizeof(buf), "psinfo", pt[i].pid, NULL)) {
      pt[i].cputime     = 0;
      pt[i].cpu_percent = 0;
      pt[i].mem_kbyte   = 0;
      continue;
    } 

    pt[i].ppid      = psinfo->pr_ppid;
    pt[i].starttime = psinfo->pr_start.tv_sec;
        
    /* If we don't have any light-weight processes (LWP) then we are definitely a zombie */
    if (psinfo->pr_nlwp == 0) {
      pt[i].status_flag = PROCESS_ZOMBIE;
      pt[i].cputime     = 0;
      pt[i].cpu_percent = 0;
      pt[i].mem_kbyte   = 0;
      continue;
    } 
    
    pt[i].mem_kbyte = psinfo->pr_rssize;

    pt[i].cmdline  = xstrdup(psinfo->pr_psargs);
    if (! pt[i].cmdline || ! *pt[i].cmdline)
      pt[i].cmdline = xstrdup(psinfo->pr_fname);

    if (! read_proc_file(buf, sizeof(buf), "status", pt[i].pid, NULL)) {
      pt[i].cputime     = 0;
      pt[i].cpu_percent = 0;
    } else {
      memcpy(&pstatus, buf, sizeof(pstatus_t));
      pt[i].cputime     = (timestruc_to_tseconds(pstatus.pr_utime) + timestruc_to_tseconds(pstatus.pr_stime));
      pt[i].cpu_percent = 0;
    }
  }
  
  *reference = pt;

  /* Free globbing buffer */
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
 * @return: TRUE if successful, FALSE if failed (or not available)
 */
int used_system_memory_sysdep(SystemInfo_T *si) {
  int                 i, n, num;
  kstat_ctl_t        *kctl;  
  kstat_named_t      *knamed;
  kstat_t            *kstat;
  swaptbl_t          *s;
  char               *strtab;
  unsigned long long  total = 0ULL;
  unsigned long long  used  = 0ULL;

  /* Memory */
  kctl  = kstat_open();
  kstat = kstat_lookup(kctl, "unix", 0, "system_pages");
  if (kstat_read(kctl, kstat, 0) == -1) {
    LogError("system statistic error -- memory usage gathering failed\n");
    kstat_close(kctl);
    return FALSE;
  }
  knamed = kstat_data_lookup(kstat, "freemem");
  if (knamed)
    si->total_mem_kbyte = systeminfo.mem_kbyte_max-pagetok(knamed->value.ul);
  kstat_close(kctl);

 /* Swap */
again:
 if ((num = swapctl(SC_GETNSWP, 0)) == -1) {
    LogError("system statistic error -- swap usage gathering failed: %s\n", STRERROR);
    return FALSE;
  }
  if (num == 0) {
    DEBUG("system statistic -- no swap configured\n");
    si->swap_kbyte_max = 0;
    return TRUE;
  }
  s = (swaptbl_t *)xmalloc(num * sizeof(swapent_t) + sizeof(struct swaptable));
  strtab = (char *)xmalloc((num + 1) * MAXSTRSIZE);
  for (i = 0; i < (num + 1); i++)
    s->swt_ent[i].ste_path = strtab + (i * MAXSTRSIZE);
  s->swt_n = num + 1;
  if ((n = swapctl(SC_LIST, s)) < 0) {
    LogError("system statistic error -- swap usage gathering failed: %s\n", STRERROR);
    si->swap_kbyte_max = 0;
    FREE(s);
    FREE(strtab);
    return FALSE;
  }
  if (n > num) {
    DEBUG("system statistic -- new swap added: deferring swap usage statistics to next cycle\n");
    FREE(s);
    FREE(strtab);
    goto again;
  }
  for (i = 0; i < n; i++) {
    if (!(s->swt_ent[i].ste_flags & ST_INDEL) && !(s->swt_ent[i].ste_flags & ST_DOINGDEL)) {
      total += s->swt_ent[i].ste_pages;
      used  += s->swt_ent[i].ste_pages - s->swt_ent[i].ste_free;
    }
  }
  FREE(s);
  FREE(strtab);
  si->swap_kbyte_max   = (unsigned long)(double)(total * page_size) / 1024.;
  si->total_swap_kbyte = (unsigned long)(double)(used  * page_size) / 1024.;

  return TRUE;
}


/**
 * This routine returns system/user CPU time in use.
 * @return: TRUE if successful, FALSE if failed (or not available)
 */
int used_system_cpu_sysdep(SystemInfo_T *si) {
  int             i, ncpu = 0, ncpus;
  long            cpu_user = 0, cpu_syst = 0, cpu_wait = 0;
  long            total = 0;
  kstat_ctl_t    *kctl;  
  kstat_named_t  *knamed;
  kstat_t        *kstat;
  kstat_t       **cpu_ks;
  cpu_stat_t     *cpu_stat;
  
  si->total_cpu_user_percent = 0;
  si->total_cpu_syst_percent = 0;
  si->total_cpu_wait_percent = 0;

  kctl  = kstat_open();
  kstat = kstat_lookup(kctl, "unix", 0, "system_misc");
  if (kstat_read(kctl, kstat, 0) == -1)
    goto error;
  
  if (NULL == (knamed = kstat_data_lookup(kstat, "ncpus")))
    goto error;
  
  ncpus = knamed->value.ui32;

  cpu_ks   = (kstat_t **)xmalloc(ncpus * sizeof(kstat_t *));
  cpu_stat = (cpu_stat_t *)xmalloc(ncpus * sizeof(cpu_stat_t));

  for (kstat = kctl->kc_chain; kstat; kstat = kstat->ks_next) {
    if (strncmp(kstat->ks_name, "cpu_stat", 8) == 0) {

      if (-1 == kstat_read(kctl, kstat, NULL))
        goto error2;

      cpu_ks[ncpu] = kstat;
      if (++ncpu > ncpus)
        goto error2;
    }
  }
  
  for (i = 0; i < ncpu; i++) {

    if (-1 == kstat_read(kctl, cpu_ks[i], &cpu_stat[i]))
      goto error2;
    
    cpu_user += cpu_stat[i].cpu_sysinfo.cpu[CPU_USER];
    cpu_syst += cpu_stat[i].cpu_sysinfo.cpu[CPU_KERNEL];
    cpu_wait += cpu_stat[i].cpu_sysinfo.cpu[CPU_WAIT];
    total    += (cpu_stat[i].cpu_sysinfo.cpu[0]+ cpu_stat[i].cpu_sysinfo.cpu[1]+ cpu_stat[i].cpu_sysinfo.cpu[2]+ cpu_stat[i].cpu_sysinfo.cpu[3]);
  }

  if (old_total == 0.0 ) {
    si->total_cpu_user_percent = -10;
    si->total_cpu_syst_percent = -10;
    si->total_cpu_wait_percent = -10;
  } else {
    si->total_cpu_user_percent = (int)((1000 * (cpu_user - old_cpu_user)) / (total - old_total));
    si->total_cpu_syst_percent = (int)((1000 * (cpu_syst - old_cpu_syst)) / (total - old_total));
    si->total_cpu_wait_percent = (int)((1000 * (cpu_wait - old_cpu_wait)) / (total - old_total));
  }

  
  old_cpu_user = cpu_user;
  old_cpu_syst = cpu_syst;
  old_cpu_wait = cpu_wait;
  old_total    = total;
  
  FREE(cpu_ks);
  FREE(cpu_stat);
  kstat_close(kctl);
  return TRUE;
 
  error2:
  old_total=0;
  FREE(cpu_ks);
  FREE(cpu_stat);

  error:
  kstat_close(kctl);
  return FALSE;
}

