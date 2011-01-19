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

/**
 *  System independent /proc & kvm methods.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Christian Hopp <chopp@iei.tu-clausthal.de>
 *  @author Martin Pala <martinp@tildeslash.com>
 *
 *  @file
 */

#include <config.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_LOADAVG_H
#include <sys/loadavg.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "monitor.h"
#include "process.h"
#include "process_sysdep.h"


/**
 * Reads an process dependent entry or the proc filesystem
 * @param buf buffer to write to
 * @param buf_size size of buffer "buf"
 * @param name name of proc service
 * @param pid number of the process / or <0 if main directory
 * @param bytes_read number of bytes read to buffer
 * @return TRUE if succeeded otherwise FALSE.
 */
int read_proc_file(char *buf, int buf_size, char *name, int pid, int *bytes_read) {
  int fd;
  char filename[STRLEN];
  int bytes;
  int rv = FALSE;

  ASSERT(buf);
  ASSERT(name);

  if (pid < 0)
    snprintf(filename, STRLEN, "/proc/%s", name);
  else
    snprintf(filename, STRLEN, "/proc/%d/%s", pid, name);
    
  if ((fd = open(filename, O_RDONLY)) < 0) {
    DEBUG("%s: Cannot open proc file %s -- %s\n", prog, filename, STRERROR);
    return rv;
  }

  if ((bytes = read(fd, buf, buf_size-1)) < 0) {
    DEBUG("%s: Cannot read proc file %s -- %s\n", prog, filename, STRERROR);
    goto error;
  }
  if (bytes_read)
    *bytes_read = bytes;
       
  /* In case it is a string we have to 0 terminate it our self */
  buf[bytes]='\0';
  rv = TRUE;

error:
  if (close(fd) < 0)
    LogError("%s: Socket close failed -- %s\n", prog, STRERROR);

  return rv;
}

/**
 * Get the actual time as a floating point number
 * @return time in seconds
 */
double get_float_time(void) {    
  struct timeval t;

  gettimeofday(&t, NULL);
  return (double) t.tv_sec * 10 + (double) t.tv_usec / 100000.0;
}


/**
 * Connects child and parent in a process tree
 * @param pt process tree
 * @param parent index
 * @param child index
 * @return TRUE if succeeded otherwise FALSE.
 */
int connectchild(ProcessTree_T *pt, int parent, int child) {

  ASSERT(pt);

  if (pt[parent].pid == pt[child].pid)
    return FALSE;

  pt[parent].children = xresize(pt[parent].children, sizeof(ProcessTree_T *) * (pt[parent].children_num + 1));
  pt[parent].children[pt[parent].children_num] = child;
  pt[parent].children_num++;

  return TRUE;
}


/**
 * Fill data in the process tree by recusively walking through it
 * @param pt process tree
 * @param i process index
 * @return TRUE if succeeded otherwise FALSE.
 */
void fillprocesstree(ProcessTree_T *pt, int index) {
  int            i;
  ProcessTree_T *parent_pt;

  ASSERT(pt);

  if (pt[index].visited == 1)
    return;

  pt[index].visited         = 1;
  pt[index].children_sum    = pt[index].children_num;
  pt[index].mem_kbyte_sum   = pt[index].mem_kbyte;
  pt[index].cpu_percent_sum = pt[index].cpu_percent;

  for (i = 0; i < pt[index].children_num; i++)
    fillprocesstree(pt, pt[index].children[i]);

  if (pt[index].parent != -1 && pt[index].parent != index) {
    parent_pt                   = &pt[pt[index].parent];
    parent_pt->children_sum    += pt[index].children_sum;
    parent_pt->mem_kbyte_sum   += pt[index].mem_kbyte_sum;
    parent_pt->cpu_percent_sum += pt[index].cpu_percent_sum;
    parent_pt->cpu_percent_sum  = (pt[index].cpu_percent_sum > 1000) ? 1000 : parent_pt->cpu_percent_sum;
  } 
}

