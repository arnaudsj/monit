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

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#define _RUSAGE_EXTENDED

#ifdef HAVE_SYS_PSTAT_H
#include <sys/pstat.h>
#endif

#ifdef HAVE_NLIST_H
#include <nlist.h>
#endif

#ifdef HAVE_SYS_DK_H
#include <sys/dk.h>
#endif

#ifdef HAVE_SYS_SWAP_H
#include <sys/swap.h>
#endif

#include "monitor.h"
#include "process.h"
#include "process_sysdep.h"

static int         page_size;
static int         nproc;
static long        cpu_total_old = 0;
static long        cpu_user_old = 0;
static long        cpu_syst_old = 0;
static long        cpu_wait_old = 0;
struct pst_dynamic pst_dyn;
struct pst_status *psall;

#define MAXSTRSIZE 80

/**
 *  System dependent resource gathering code for HP/UX.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Christian Hopp <chopp@iei.tu-clausthal.de>
 *  @author Joe Bryant <JBryant@RiteAid.com>
 *  @author Martin Pala, <martinp@tildeslash.com>
 *
 *  @file
 */

/*
 * Helpful guide for implematation:
 * "SunOS to HP-UX 9.05 Porting Guide" at http://www.interex.org/tech/9000/Tech/sun_hpux_port/portguide.html
 */

int init_process_info_sysdep(void) {
  struct pst_dynamic psd;
  struct pst_static pst;

  if (pstat_getdynamic(&psd,sizeof(psd),(size_t)1,0) != -1)
    systeminfo.cpus=psd.psd_proc_cnt;
  else
    return FALSE;

  if (pstat_getstatic(&pst, sizeof(pst), (size_t) 1, 0) != -1) {
    systeminfo.mem_kbyte_max=(unsigned long)(pst.physical_memory * (pst.page_size / 1024)); 
    page_size=pst.page_size;
  } else {
    return FALSE;
  }

  return TRUE;
}


/**
 * This routine returns 'na' double precision floats containing
 * the load averages in 'a'; at most 3 values will be returned.
 * @param loadv destination of the load averages
 * @param nelem number of averages
 * @return: 0 if successful, -1 if failed (and all load averages are 0).
 */
int getloadavg_sysdep (double *a, int na) {
  struct pst_dynamic psd;
	
  if (pstat_getdynamic(&psd, sizeof(psd), (size_t)1, 0) != -1) {
    switch (na) {
    case 3:
      a[2] = psd.psd_avg_15_min;

    case 2:
      a[1] = psd.psd_avg_5_min;

    case 1:
      a[0] = psd.psd_avg_1_min;
    }
  } else {
    return FALSE;
  }

  return TRUE;
}


/**
 * Read all processes to initialize the process tree
 * @param reference  reference of ProcessTree
 * @return treesize>0 if succeeded otherwise 0.
 */
int initprocesstree_sysdep(ProcessTree_T ** reference) {
  int            i;
  int            treesize;
  ProcessTree_T *pt;

  ASSERT(reference);

  pstat_getdynamic(&pst_dyn, sizeof(struct pst_dynamic), 1, 0);
  nproc = pst_dyn.psd_activeprocs;

  if ((psall = (struct pst_status *)xresize(psall, nproc * sizeof(struct pst_status))) == NULL)
    return 0;

  if ((treesize = pstat_getproc(psall, sizeof(struct pst_status), nproc , 0)) == -1) {
    LogError("system statistic error 1 -- pstat_getproc failed: %s\n", strerror(errno));
    return 0;
  }

  pt = xcalloc(sizeof(ProcessTree_T), treesize);

  for (i = 0; i < treesize; i++) {
    pt[i].pid         = psall[i].pst_pid;
    pt[i].ppid        = psall[i].pst_ppid;
    pt[i].starttime   = psall[i].pst_start;
    pt[i].time        = get_float_time();
    pt[i].cputime     =  psall[i].pst_utime + psall[i].pst_stime * 10;
    pt[i].cpu_percent = (int)(1000. * psall[i].pst_pctcpu / (float)systeminfo.cpus);
    pt[i].mem_kbyte   = (unsigned long)(psall[i].pst_rssize * (page_size / 1024.0));
    pt[i].cmdline     = (psall[i].pst_cmd && *psall[i].pst_cmd) ? xstrdup(psall[i].pst_cmd) : xstrdup(psall[i].pst_ucomm);

    if ( psall[i].pst_stat == PS_ZOMBIE )
      pt[i].status_flag |= PROCESS_ZOMBIE;
  }

  *reference = pt;

  return treesize;
}


/**
 * This routine returns kbyte of real memory in use.
 * @return: TRUE if successful, FALSE if failed (or not available)
 */
int used_system_memory_sysdep(SystemInfo_T *si) {
  int                 i, n, num;
  struct pst_static   pst;
  struct pst_dynamic  psd;
  struct swaptable   *s;
  char               *strtab;
  unsigned long long  total = 0ULL;
  unsigned long long  used  = 0ULL;

  /* Memory */
  if(pstat_getstatic(&pst, sizeof(pst), (size_t)1, 0) == -1) {
    LogError("system statistic error -- pstat_getstatic failed: %s\n", STRERROR);
    return FALSE;
  }
  if(pstat_getdynamic(&psd, sizeof(psd), (size_t)1, 0) == -1) {
    LogError("system statistic error -- pstat_getdynamic failed: %s\n", STRERROR);
    return FALSE;
  }
  si->total_mem_kbyte = (unsigned long)((pst.physical_memory - psd.psd_free) * (pst.page_size/1024));

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
  s = (struct swaptable *)xmalloc(num * sizeof(struct swapent) + sizeof(struct swaptable));
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
  int                i;
  long               cpu_total;
  long               cpu_total_new = 0;
  long               cpu_user = 0;
  long               cpu_syst = 0;
  long               cpu_wait = 0;
  struct pst_dynamic psd;

  pstat_getdynamic(&psd, sizeof(psd), 1, 0);

  for(i = 0; i < CPUSTATES; i++)
    cpu_total_new += psd.psd_cpu_time[i];
  cpu_total     = cpu_total_new - cpu_total_old;
  cpu_total_old = cpu_total_new;
  cpu_user      = psd.psd_cpu_time[CP_USER] + psd.psd_cpu_time[CP_NICE];
  cpu_syst      = psd.psd_cpu_time[CP_SYS];
  cpu_wait      = psd.psd_cpu_time[CP_WAIT];

  si->total_cpu_user_percent = (cpu_total > 0)?(int)(1000 * (double)(cpu_user - cpu_user_old) / cpu_total):-10;
  si->total_cpu_syst_percent = (cpu_total > 0)?(int)(1000 * (double)(cpu_syst - cpu_syst_old) / cpu_total):-10;
  si->total_cpu_wait_percent = (cpu_total > 0)?(int)(1000 * (double)(cpu_wait - cpu_wait_old) / cpu_total):-10;

  cpu_user_old = cpu_user;
  cpu_syst_old = cpu_syst;
  cpu_wait_old = cpu_wait;

  return TRUE;
}

