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


#ifndef NET_H
#define NET_H

#include <config.h>
#include "monitor.h"


/**
 *  General purpose Network and Socket methods.
 *
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Christian Hopp, <chopp@iei.tu-clausthal.de>
 *  @author Martin Pala, <martinp@tildeslash.com>
 *
 *  @file
 */


/**
 * Standard seconds to wait for a socket connection or for socket read
 * i/o before aborting
 */
#define NET_TIMEOUT 5


/**
 * Check if the hostname resolves
 * @param hostname The host to check
 * @return TRUE if hostname resolves, otherwise FALSE
 */
int check_host(const char *hostname);


/**
 * Verify that the socket is ready for i|o
 * @param socket A socket
 * @return TRUE if the socket is ready, otherwise FALSE.
 */
int check_socket(int socket);


/**
 * Verify that the udp server is up. The given socket must be a 
 * connected udp socket if we should be able to test the udp server. 
 * The test is conducted by sending a datagram to the server and
 * check for a returned ICMP error when reading from the socket.
 * @param socket A socket
 * @return TRUE if the socket is ready, otherwise FALSE.
 */
int check_udp_socket(int socket);


/**
 * Create a non-blocking socket against hostname:port with the given
 * protocol. The protocol should be either SOCK_STREAM or SOCK_DGRAM.
 * @param hostname The host to open a socket at
 * @param port The port number to connect to
 * @param protocol Socket protocol to use (SOCK_STREAM|SOCK_DGRAM)
 * @param timeout If not connected within timeout seconds abort and return -1
 * @return The socket or -1 if an error occured.
 */
int create_socket(const char *hostname, int port, int protocol, int timeout);


/**
 * Open a socket using the given Port_T structure. The protocol,
 * destination and type are selected appropriately.
 * @param p connection description
 * @return The socket or -1 if an error occured.
 */
int create_generic_socket(Port_T p);


/**
 * Create a non-blocking UNIX socket.
 * @param pathname The pathname to use for the unix socket
 * @param timeout If not connected within timeout seconds abort and return -1
 * @return The socket or -1 if an error occured.
 */
int create_unix_socket(const char *pathname, int timeout);


/**
 * Create a blocking server socket and bind it to the specified local
 * port number, with the specified backlog. Set a socket option to
 * make the port reusable again. If a bind address is given the socket
 * will only accept connect requests to this addresses. If the bind
 * address is NULL it will accept connections on any/all local
 * addresses
 * @param port The localhost port number to open
 * @param backlog The maximum queue length for incomming connections
 * @param bindAddr the local address the server will bind to
 * @return The socket ready for accept, or -1 if an error occured.
 */
int create_server_socket(int port, int backlog, const char *bindAddr);


/**
 * Shutdown a socket and close the descriptor.
 * @param socket The socket to shutdown and close
 * @return TRUE if the close succeed otherwise FALSE
 */
int close_socket(int socket);


/**
 * Enable nonblocking i|o on the given socket.
 * @param socket A socket
 * @return TRUE if success, otherwise FALSE
 */
int set_noblock(int socket);


/**
 * Disable nonblocking i|o on the given socket
 * @param socket A socket
 * @return TRUE if success, otherwise FALSE
 */
int set_block(int socket);


/**
 * Check if data is available, if not, wait timeout seconds for data
 * to be present.
 * @param socket A socket
 * @param timeout How long to wait before timeout (value in seconds)
 * @return Return TRUE if the event occured, otherwise FALSE.
 */
int can_read(int socket, int timeout);


/**
 * Check if data can be sent to the socket, if not, wait timeout
 * seconds for the socket to be ready.
 * @param socket A socket
 * @param timeout How long to wait before timeout (value in seconds)
 * @return Return TRUE if the event occured, otherwise FALSE.
 */
int can_write(int socket, int timeout);


/**
 * Write <code>size</code> bytes from the <code>buffer</code> to the
 * <code>socket</code> 
 * @param socket the socket to write to
 * @param buffer The buffer to write
 * @param size Number of bytes to send
 * @param timeout Seconds to wait for data to be written
 * @return The number of bytes sent or -1 if an error occured.
 */
int sock_write(int socket, const void *buffer, int size, int timeout);
  

/**
 * Read up to size bytes from the <code>socket</code> into the
 * <code>buffer</code>. If data is not available wait for
 * <code>timeout</code> seconds.
 * @param socket the Socket to read data from
 * @param buffer The buffer to write the data to
 * @param size Number of bytes to read from the socket
 * @param timeout Seconds to wait for data to be available
 * @return The number of bytes read or -1 if an error occured. 
*/
int sock_read(int socket, void *buffer, int size, int timeout);


/**
 * Write <code>size</code> bytes from the <code>buffer</code> to the
 * <code>socket</code>. The given socket <b>must</b> be a connected
 * UDP socket
 * @param socket the socket to write to
 * @param buffer The buffer to write
 * @param size Number of bytes to send
 * @param timeout Seconds to wait for data to be written
 * @return The number of bytes sent or -1 if an error occured.
 */
int udp_write(int socket, void *b, int len, int timeout);


/**
 * Create a ICMP socket against hostname, send echo and wait for response.
 * The 'count' echo requests  is send and we expect at least one reply.
 * @param hostname The host to open a socket at
 * @param timeout If response will not come within timeout seconds abort
 * @param count How many pings to send
 * @return response time on succes, -1 on error
 */
double icmp_echo(const char *hostname, int timeout, int count);

#endif
