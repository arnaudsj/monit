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


#ifndef MONIT_UTIL_H
#define MONIT_UTIL_H


/**
 *  General purpose utility methods.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author "Martin Pala" <martinp@tildeslash.com>
 *  @author Christian Hopp <chopp@iei.tu-clausthal.de>
 *  @author Michael Amster, <mamster@webeasy.com> 
 *
 *  @file
 */


/**
 * Return only the filename with leading directory components
 * removed. This function does not modify the path string.
 * @param path A file path string
 * @return A pointer to the basename in path
 */
char *Util_basename(char* path);


/**
  * Removes everything from the first line break or newline (CR|LF)
  * @param s A string to be chomped
  * @return The chomped string
  */
char *Util_chomp(char *s);


/**
 * Remove leading and trailing space from the string
 * @param s A string
 * @return s with leading and trailing spaces removed
 */
char *Util_trim(char *s);


/**
 * Remove leading white space [ \t\r\n] from the string.
 * @param s A string
 * @return s with leading spaces removed
 */
char *Util_ltrim(char *s);


/**
 * Remove trailing white space [ \t\r\n] from the string
 * @param s A string
 * @return s with trailing spaces removed
 */
char *Util_rtrim(char *s);


/**
 * Remove any enclosing quotes ["'] from the string
 * @param s A string
 * @return s with any enclosed quotes removed
 */
void Util_trimQuotes(char *s);


/**
 * Truncate <code>s</code> at <code>n</code> and add a trailing "..." 
 * to the end of <code>s</code>. If <code>s</code> is shorter than 
 * <code>n</code> or has no space for the trail, <code>s</code> is left
 * untouched otherwise this function modifies <code>s</code>. 
 * <pre>
 * Example: 
 *  char s[]= "Hello World!";
 *  Util_trunc(s, strlen(s)); --> "Hello World!" 
 *  Util_trunc(s, 5); --> "Hello..."
 *  Util_trunc(s, 0); --> "..."
 * </pre>
 * @param s String to truncate at n
 * @param n number of bytes from where s is truncated
 * @return A pointer to s
 */
char *Util_trunc(char *s, int n);


/**
 * Replace all occurrences of the <code>old</code> char in the string
 * <code>s</code> with the <code>new</code> char.
 * @param s A string
 * @param old The old char
 * @param new The new char
 * @return s where all occurrence of old are replaced with new
 */
char *Util_replace(char *s, char old, char new);


/**
 * Replace all occurrences of the sub-string old in the string src
 * with the sub-string new. The method is case sensitive for the
 * sub-strings new and old. The string parameter src must be an
 * allocated string, not a character array.
 * @param src An allocated string reference (e.g. &string)
 * @param old The old sub-string
 * @param new The new sub-string
 * @return src where all occurrences of the old sub-string are
 * replaced with the new sub-string. 
 */
char *Util_replaceString(char **src, const char *old, const char *new);


/**
 * Count the number the sub-string word occurs in s.
 * @param s The String to search for word in
 * @param word 	The sub-string to count in s
 */
int Util_countWords(char *s, const char *word);


/**
 * Return TRUE if the string <i>a</i> starts with the string
 * <i>b</i>. The test is <i>case-insensitive</i> but depends on that
 * all characters in the two strings can be translated in the current
 * locale.
 * @param a The string to search for b in
 * @param b The sub-string to test a against
 * @return TRUE if a starts with b, otherwise FALSE
 */
int Util_startsWith(const char *a, const char *b);


/**
 * Exchanges \escape sequences in a string
 * @param buf A string
 */
void Util_handleEscapes(char *buf);


/**
 * Variant of Util_handleEscapes() which only handle \0x00 escape sequences 
 * in a string
 * @param buf A string
 * @return The new length of buf
 */
int Util_handle0Escapes(char *buf);

 
/**
 * Convert a digest buffer to a char string
 * @param digest buffer containing a MD digest
 * @param mdlen digest length
 * @param result buffer to write the result to. Must be at least
 * 41 bytes long.
 */
char *Util_digest2Bytes(unsigned char *digest, int mdlen, MD_T result);


/**
 * @param name A service name as stated in the config file
 * @return the named service or NULL if not found
 */
Service_T Util_getService(const char *name);


/**
 * @param name A service name as stated in the config file
 * @return TRUE if the service name exist in the
 * servicelist, otherwise FALSE
 */
int Util_existService(const char *name);


/**
 * Get the length of the service list, that is; the number of services
 * managed by monit
 * @return The number of services monitored
 */
int Util_getNumberOfServices();


/**
 * Print the Runtime object
 */
void Util_printRunList();


/**
 * Print a service object
 * @param p A Service_T object
 */
void Util_printService(Service_T s);


/**
 * Print all the services in the servicelist
 */
void Util_printServiceList();


/**
 * Print file hashes from stdin or from the given file
 */
void Util_printHash(char *filename);


/**
 * Open and read the id from the given idfile. If the idfile doesn't exist,
 * generate new id and store it in the id file.
 * @param idfile An idfile with full path
 * @return the id or NULL
 */
char *Util_monitId(char *idfile);


/**
 * Open and read the pid from the given pidfile.
 * @param pidfile A pidfile with full path
 * @return the pid (TRUE) or FALSE if the pid could
 * not be read from the file
 */
pid_t Util_getPid(char *pidfile);


/**
 * Check whether the process is running
 * @param s The service being checked
 * @param refresh TRUE to refresh the global ptree (useful for procmatch if process was mangled by monit in the same cycle such as by restart action) or FALSE to use cached ptree
 * @return The PID of the running running process or 0 if the process is not running.
 */
int Util_isProcessRunning(Service_T s, int refresh);


/**
 * Returns a RFC822 Date string. If the given date is NULL compute the
 * date now. If an error occured the result buffer is set to an empty
 * string. The result buffer should be large enough to hold 33 bytes.
 * @param date seconds since EPOCH
 * @param result The buffer to write the date string to
 * @param len the length of the result buffer
 * @return a pointer to the result buffer
 */
char *Util_getRFC822Date(time_t *date, char *result, int len);


/**
 * Compute an uptime for a process based on the ctime
 * from the pidfile.
 * @param pidfile A process pidfile
 * @return an uptime
 */
time_t Util_getProcessUptime(char *pidfile);


/**
 * Compute an uptime string based on the delta time in seconds. The
 * caller must free the returned string.
 * @param delta seconds. 
 * @param sep string separator
 * @return an uptime string
 */
char *Util_getUptime(time_t delta, char *sep);


/**
 * @return Store checksum for the given file in supplied buffer, return FALSE if failed, otherwise TRUE.
 */
int Util_getChecksum(char *file, int hashtype, char *buf, int bufsize);


/**
 * Returns true if url contains url safe characters otherwise false
 * @param url an url string to test
 * @return true if url is url safe otherwise false
 */
int Util_isurlsafe(const char *url);

/**
 * Escape an url string converting unsafe characters to a hex (%xx)
 * representation.  The caller must free the returned string.
 * @param url an url string
 * @return the escaped string
 */
char *Util_urlEncode(char *url);


/**
 * Unescape an url string. The <code>url</code> parameter is modified
 * by this method.
 * @param url an escaped url string
 * @return A pointer to the unescaped <code>url</code>string
 */
char *Util_urlDecode(char *url);


/**
 * URL escape a service name so it can be safely transfeered over HTTP. In
 * particular any '/' chars in name is encoded. The caller must free the 
 * returned string.
 * @param name a service name string to be URL encoded
 * @return the escaped string
 */
char *Util_encodeServiceName(char *name);


/**
 * @return a Basic Authentication Authorization string (RFC 2617),
 * with credentials from the Run object, NULL if credentials are not defined.
 */
char *Util_getBasicAuthHeaderMonit();


/**
 * @return a Basic Authentication Authorization string (RFC 2617),
 * NULL if username is not defined.
 */
char *Util_getBasicAuthHeader(char *username, char *password);


/**
 * Creates a new String by merging a formated string and a variable
 * argument list. The caller must free the returned String.
 * @param s A format string
 * @return The new String or NULL if the string could not be created
 */
char *Util_getString(const char *s, ...);


/**
 * Do printf style format line parsing
 * @param s format string
 * @param ap variable argument list
 * @param len The lenght of the bytes written,
 * may be different from the returned allocated buffer size
 * @return buffer with parsed string
 */
char *Util_formatString(const char *s, va_list ap, long *len);


/**
 * Redirect the standard file descriptors to /dev/null and route any
 * error messages to the log file.
 */
void Util_redirectStdFds();


/*
 * Close all filedescriptors except standard. Everything
 * seems to have getdtablesize, so we'll use it here, and back
 * out to use 1024 if getdtablesize not available.
 */

void Util_closeFds();


/*
 * Check if monit does have credentials for this user.  If successful
 * a pointer to the password is returned.
 */

Auth_T Util_getUserCredentials(char *uname);


/**
 * Check if the given password match the registred password for the
 * given username. 
 * @param uname Username
 * @param outside The password to test
 * @return TRUE if the passwords match for the given uname otherwise
 * FALSE
 */
int Util_checkCredentials(char *uname, char *outside);


/**
 * Compute SHA1 and MD5 message digests simultaneously for bytes read
 * from STREAM (suitable for stdin, which is not always rewindable).
 * The resulting message digest numbers will be written into the first
 * bytes of resblock buffers.
 * @param stream The stream from where the digests are computed
 * @param sha_resblock The buffer to write the SHA1 result to
 * @param md5_resblock The buffer to write the MD5 result to
 */
int Util_getStreamDigests (FILE *stream, void *sha_resblock, void *md5_resblock);


/**
 * Reset the service information structure
 */
void Util_resetInfo(Service_T s);


/**
 * Are service status data available?
 * @param s The service to test
 * @return TRUE if available otherwise FALSE
 */
int Util_hasServiceStatus(Service_T s);


/**
 * Construct a HTTP/1.1 Host header utilizing information from the
 * socket. The returned hostBuf is set to "hostname:port" or to the
 * empty string if information is not available or not applicable.
 * @param s A connected socket 
 * @param hostBuf the buffer to write the host-header to
 * @param len Length of the hostBuf
 * @return the hostBuffer
 */
char *Util_getHTTPHostHeader(Socket_T s, char *hostBuf, int len);


/**
 * Evaluate a qualification expression. 
 * @param operator The qualification operator
 * @param left Expression lval
 * @param rightExpression rval
 * @return the boolean value of the expression
 */
int Util_evalQExpression(int operator, long long left, long long right);


/*
 * This will enable service monitoring in the case that it was disabled.
 * @param s A Service_T object
 */
void Util_monitorSet(Service_T s);


/*
 * This will disable service monitoring in the case that it is enabled
 * @param s A Service_T object
 */
void Util_monitorUnset(Service_T s);


/*
 * Retun appropriate action id for string
 * @param action A action string
 * @return the action id
 */
int Util_getAction(const char *action);


/*
 * Write full action description to given buffer
 * @param action An action object
 * @param buf Buffer
 * @param bufsize Buffer size
 * @return the buffer
 */
char *Util_describeAction(Action_T action, char *buf, int bufsize);


/**
 * Print event ratio needed to trigger the action to given buffer
 * @param action A action string
 * @param buf Buffer
 * @param bufsize Buffer size
 * @return the buffer
 */
char *Util_getEventratio(Action_T action, char *buf, int bufsize);


/**
 * Print port type description
 * @param p A port structure
 * @return the socket type description
 */
char *Util_portTypeDescription(Port_T p);


/**
 * Print full port description <INET|UNIX>\[<host>:<port>[request]\][via TCP|TCPSSL|UDP]
 * @param p A port structure
 * @param buf Buffer
 * @param bufsize Buffer size
 * @return the buffer
 */
char *Util_portDescription(Port_T p, char *buf, int bufsize);


/**
 * Print to string buffer
 * @param b A Buffer object
 * @param m Format string
 * @return the socket type description
 */
void Util_stringbuffer(Buffer_T *b, const char *m, ...);


/**
 *  Returns the FQDN hostname or fallback to gethostname() output
 *  @param buf the character array for hostname
 *  @param len the length of buf
 *  @return zero on success
 */
int Util_getfqdnhostname(char *buf, unsigned len);


#endif
