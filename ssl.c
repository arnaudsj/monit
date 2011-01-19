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


#ifdef HAVE_OPENSSL


#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif


#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

#include "monitor.h"
#include "net.h"
#include "ssl.h"


/* -------------------------------------------------------------- Prototypes */


#define SSLERROR ERR_error_string(ERR_get_error(),NULL)

static int unsigned long ssl_thread_id();
static void ssl_mutex_lock(int, int n, const char *, int );
static int verify_init(ssl_server_connection *);
static int verify_callback(int, X509_STORE_CTX *);
static int check_preverify(X509_STORE_CTX *);
static void cleanup_ssl_socket(ssl_connection *);
static void cleanup_ssl_server_socket(ssl_server_connection *);
static int handle_error(int, ssl_connection *);
static int update_ssl_cert_data(ssl_connection *);
static ssl_server_connection *new_ssl_server_connection(char *, char *);
static int start_ssl();

static int              allow_self_certification = FALSE;
static int              ssl_initialized          = FALSE;
static pthread_mutex_t  ssl_mutex                = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t *ssl_mutex_table;


/* ------------------------------------------------------------- Definitions */


/**
 * Number of random bytes to obtain
 */
#define RANDOM_BYTES 1024

/**
 * The PRIMARY random device selected for seeding the PRNG. We use a
 * non-blocking pseudo random device, to generate pseudo entropy.
 */
#define URANDOM_DEVICE "/dev/urandom"

/**
 * If a non-blocking device is not found on the system a blocking
 * entropy producer is tried instead.
 */
#define RANDOM_DEVICE "/dev/random"


/**
 *  SSL Socket methods.
 *
 *  @author Christian Hopp <chopp@iei.tu-clausthal.de>
 *  @author Jan-Henrik Haukeland, <hauk@tildeslash.com>
 *  @author Martin Pala, <martinp@tildeslash.com>
 *
 *  @file
 */

/**
 * For some of the code I was enlightened by:
 *
 * An Introduction to OpenSSL Programming, Part I of II
 *
 * by Eric Rescorla
 * Linux Journal 9/2001
 * http://www.linuxjournal.com/article.php?sid=4822
 */


/* ------------------------------------------------------------------ Public */


/**
 * Embeds a socket in a ssl connection.
 * @param socket the socket to be used.
 * @return The ssl connection or NULL if an error occured.
 */
int embed_ssl_socket(ssl_connection *ssl, int socket) {
  int ssl_error;
  time_t ssl_time;
  
  if (!ssl)
    return FALSE;
  
  if (!ssl_initialized)
    start_ssl();

  if (socket >= 0) {
    ssl->socket = socket;
  } else {
    LogError("%s: Socket error!\n", prog);
    goto sslerror;
  }

  if ((ssl->handler = SSL_new (ssl->ctx)) == NULL) {
    LogError("%s: Cannot initialize the SSL handler -- %s\n", prog, SSLERROR);
    goto sslerror;
  }

  set_noblock(ssl->socket);

  if ((ssl->socket_bio = BIO_new_socket(ssl->socket, BIO_NOCLOSE)) == NULL) {
    LogError("%s: Cannot generate IO buffer -- %s\n", prog, SSLERROR);
    goto sslerror;
  }

  SSL_set_bio(ssl->handler, ssl->socket_bio, ssl->socket_bio);
  ssl_time = time(NULL);

  while ((ssl_error = SSL_connect (ssl->handler)) < 0) {
    if ((time(NULL) - ssl_time) > SSL_TIMEOUT) {
      LogError("%s: SSL service timeout!\n", prog);
      goto sslerror;
    }

    if (!handle_error(ssl_error, ssl))
      goto sslerror;

    if (!BIO_should_retry(ssl->socket_bio))
      goto sslerror;
  }

  ssl->cipher = (char *) SSL_get_cipher(ssl->handler);

  if (! update_ssl_cert_data(ssl)) {
    LogError("%s: Cannot get the SSL server certificate!\n", prog);
    goto sslerror;
  }

  return TRUE;

sslerror:
  cleanup_ssl_socket(ssl);
  return FALSE;
} 


/**
 * Compare certificate with given md5 sum
 * @param ssl reference to ssl connection 
 * @param md5sum string of the md5sum to test against
 * @return TRUE, if sums do not match FALSE 
 */
int check_ssl_md5sum(ssl_connection *ssl, char *md5sum) {
  unsigned int i = 0;

  ASSERT(md5sum);

  while ((i < ssl->cert_md5_len) && (md5sum[2*i] != '\0') && (md5sum[2*i+1] != '\0')) {
    unsigned char c = (md5sum[2*i] > 57 ? md5sum[2*i] - 87 : md5sum[2*i] - 48) * 0x10+ (md5sum[2*i+1] > 57 ? md5sum[2*i+1] - 87 : md5sum[2*i+1] - 48);
    if (c != ssl->cert_md5[i])
      return FALSE;
    i++;
  }
  return TRUE;
}


/**
 * Closes a ssl connection (ssl socket + net socket)
 * @param ssl ssl connection
 * @return TRUE, or FALSE if an error has occured.
 */
int close_ssl_socket(ssl_connection *ssl) {
  int rv;

  if (!ssl)
    return FALSE;

  if (! (rv = SSL_shutdown(ssl->handler))) {
    shutdown(ssl->socket, 1);
    rv = SSL_shutdown(ssl->handler);
  }

  close_socket(ssl->socket);
  cleanup_ssl_socket(ssl);

  return (rv > 0) ? TRUE : FALSE;
}


/**
 * Garbage collection for non-reusable parts a ssl connection
 * @param ssl ssl connection
 */
void delete_ssl_socket(ssl_connection *ssl) {
  if (!ssl)
    return;

  cleanup_ssl_socket(ssl);

  if (ssl->ctx && !ssl->accepted)
    SSL_CTX_free(ssl->ctx);

  ssl->ctx = NULL;

  FREE(ssl);
}


/**
 * Initializes a ssl connection for server use.
 * @param pemfilename Filename for the key/cert file
 * @return An ssl connection, or NULL if an error occured.
 */
ssl_server_connection *init_ssl_server(char *pemfile, char *clientpemfile) {
  SSL_METHOD *server_method = NULL;
  ssl_server_connection *ssl_server;

  ASSERT(pemfile);

  if (!ssl_initialized)
    start_ssl();

  ssl_server = new_ssl_server_connection(pemfile, clientpemfile);
#ifdef OPENSSL_FIPS
  if (FIPS_mode())
    server_method = TLSv1_server_method();
  else
    server_method = SSLv23_server_method();
#else
  server_method = SSLv23_server_method();
#endif
  if (!(ssl_server->method = server_method)) {
    LogError("%s: Cannot initialize the SSL method -- %s\n", prog, SSLERROR);
    goto sslerror;
  }

  if (!(ssl_server->ctx = SSL_CTX_new(ssl_server->method))) {
    LogError("%s: Cannot initialize SSL server certificate handler -- %s\n", prog, SSLERROR);
    goto sslerror;
  }

  if (SSL_CTX_use_certificate_chain_file(ssl_server->ctx, pemfile) != 1) {
    LogError("%s: Cannot initialize SSL server certificate -- %s\n", prog, SSLERROR);
    goto sslerror;
  }

  if (SSL_CTX_use_PrivateKey_file(ssl_server->ctx, pemfile, SSL_FILETYPE_PEM) != 1) {
    LogError("%s: Cannot initialize SSL server private key -- %s\n", prog, SSLERROR);
    goto sslerror;
  }

  if (SSL_CTX_check_private_key(ssl_server->ctx) != 1) {
    LogError("%s: The private key doesn't match the certificate public key -- %s\n", prog, SSLERROR);
    goto sslerror;
  }

  /* Disable session cache */
  SSL_CTX_set_session_cache_mode(ssl_server->ctx, SSL_SESS_CACHE_OFF);

  /*
   * We need this to force transmission of client certs
   */
  if (!verify_init(ssl_server)) {
    LogError("%s: Verification engine was not properly initialized -- %s\n", prog, SSLERROR);
    goto sslerror;
  }

  if (ssl_server->clientpemfile) {
    STACK_OF(X509_NAME) *stack = SSL_CTX_get_client_CA_list(ssl_server->ctx);
    LogInfo("%s: Found %d client certificates\n", prog, sk_X509_NAME_num(stack));
  }

  return ssl_server;

sslerror:
  delete_ssl_server_socket(ssl_server);
  return NULL;
}


/**
 * Deletes a SSL server connection. 
 * @param ssl_server data for ssl server connection
 */
void delete_ssl_server_socket(ssl_server_connection *ssl_server) {
  if (!ssl_server)
    return;

  cleanup_ssl_server_socket(ssl_server);

  if (ssl_server->ctx)
    SSL_CTX_free(ssl_server->ctx);

  FREE(ssl_server);
}


/**
 * Inserts an SSL connection in the connection list of a server.
 * @param ssl_server data for ssl server connection
 * @return new SSL connection for the connection, or NULL if failed
 */
ssl_connection *insert_accepted_ssl_socket(ssl_server_connection *ssl_server) {
  ssl_connection *ssl;

  ASSERT(ssl_server);

  if (!ssl_initialized)
    start_ssl();

  NEW(ssl);
  ssl->method = NULL;
  ssl->handler = NULL;
  ssl->cert = NULL;
  ssl->cipher = NULL;
  ssl->socket = 0;
  ssl->next = NULL;
  ssl->accepted = FALSE;
  ssl->cert_md5= NULL;
  ssl->cert_md5_len = 0;
  ssl->clientpemfile = NULL;

  if (ssl_server->clientpemfile != NULL)
    ssl->clientpemfile = xstrdup(ssl_server->clientpemfile);

  LOCK(ssl_mutex);

  ssl->prev = NULL;
  ssl->next = ssl_server->ssl_conn_list;

  if ( ssl->next != NULL )
    ssl->next->prev = ssl;

  END_LOCK;

  ssl_server->ssl_conn_list = ssl;
  ssl->ctx = ssl_server->ctx;
  ssl->accepted = TRUE;

  return ssl;
}


/**
 * Closes an accepted SSL server connection and deletes it form the 
 * connection list. 
 * @param ssl_server data for ssl server connection
 * @param ssl data the connection to be deleted
 */
void close_accepted_ssl_socket(ssl_server_connection *ssl_server, ssl_connection *ssl) {
  if (!ssl || !ssl_server)
    return;

  close_socket(ssl->socket);
  
  LOCK(ssl_mutex);

    if (ssl->prev == NULL)
      ssl_server->ssl_conn_list = ssl->next;
    else
      ssl->prev->next = ssl->next;

  END_LOCK;  

  delete_ssl_socket(ssl);
}


/**
 * Embeds an accepted server socket in an existing ssl connection.
 * @param ssl ssl connection
 * @param socket the socket to be used.
 * @return TRUE, or FALSE if an error has occured.
 */
int embed_accepted_ssl_socket(ssl_connection *ssl, int socket) {
  int ssl_error;
  time_t ssl_time;

  ASSERT(ssl);
  
  ssl->socket = socket;

  if (!ssl_initialized)
    start_ssl();

  if (!(ssl->handler = SSL_new(ssl->ctx))) { 
    LogError("%s: Cannot initialize the SSL handler -- %s\n", prog, SSLERROR);
    return FALSE;
  } 

  if (socket < 0) {
    LogError("%s: Socket error!\n", prog);
    return FALSE;
  }

  set_noblock(ssl->socket);

  if (!(ssl->socket_bio = BIO_new_socket(ssl->socket, BIO_NOCLOSE))) {
    LogError("%s: Cannot generate IO buffer -- %s\n", prog, SSLERROR);
    return FALSE;
  }

  SSL_set_bio(ssl->handler, ssl->socket_bio, ssl->socket_bio);

  ssl_time = time(NULL);
  
  while ((ssl_error = SSL_accept(ssl->handler)) < 0) {

    if ((time(NULL) - ssl_time) > SSL_TIMEOUT) {
      LogError("%s: SSL service timeout!\n", prog);
      return FALSE;
    }

    if (!handle_error(ssl_error, ssl))
      return FALSE;

    if (!BIO_should_retry(ssl->socket_bio))
      return FALSE;

  }

  ssl->cipher = (char *)SSL_get_cipher(ssl->handler);

  if (!update_ssl_cert_data(ssl) && ssl->clientpemfile) {
    LogError("%s: The client did not supply a required client certificate!\n",
	  prog);
    return FALSE;
  }

  if (SSL_get_verify_result(ssl->handler) > 0) {
    LogError("%s: Verification of the certificate has failed!\n", prog);
    return FALSE;
  }

  return TRUE;
}


/**
 * Send data package though the ssl connection 
 * @param ssl ssl connection
 * @param buffer array containg the data
 * @param len size of the data container
 * @param timeout Seconds to wait for data to be written
 * @return number of bytes transmitted, -1 in case of an error
 */
int send_ssl_socket(ssl_connection *ssl, void *buffer, int len, int timeout) {
  int n = 0;

  ASSERT(ssl);

  do {
    n = SSL_write(ssl->handler, buffer, len);
  } while (n <= 0 && BIO_should_retry(ssl->socket_bio) && can_write(ssl->socket, timeout));
  
  return (n > 0) ? n : -1;
}


/**
 * Receive data package though the ssl connection 
 * @param ssl ssl connection
 * @param buffer array to hold the data
 * @param len size of the data container
 * @param timeout Seconds to wait for data to be available
 * @return number of bytes transmitted, -1 in case of an error
 */
int recv_ssl_socket(ssl_connection *ssl, void *buffer, int len, int timeout) {
  int n = 0;

  ASSERT(ssl);

  do {
    n = SSL_read(ssl->handler, buffer, len);
  } while (n < 0 && BIO_should_retry(ssl->socket_bio) && can_read(ssl->socket, timeout));
  
  return (n >= 0) ? n : -1;
}


/**
 * Stop SSL support library
 * @return TRUE, or FALSE if an error has occured.
 */
void stop_ssl() {
  if (ssl_initialized) {
    int i;
    ssl_initialized = FALSE;
    ERR_free_strings();
    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++)
      assert(pthread_mutex_destroy(&ssl_mutex_table[i]) == 0);
    FREE(ssl_mutex_table);
    RAND_cleanup();
  }
}


/**
 * Configures the ssl engine
 */
void config_ssl(int conf_allow_self_cert) {
  allow_self_certification = conf_allow_self_cert;
}


/**
 * Generate a new ssl connection
 * @return ssl connection container
 */
ssl_connection *new_ssl_connection(char *clientpemfile, int sslversion) {
  ssl_connection *ssl;

  if (!ssl_initialized)
    start_ssl();

  NEW(ssl);
  ssl->socket_bio = NULL; 
  ssl->handler = NULL;
  ssl->cert = NULL;
  ssl->cipher = NULL;
  ssl->socket = 0;
  ssl->next = NULL;
  ssl->accepted = FALSE;
  ssl->cert_md5 = NULL;
  ssl->cert_md5_len = 0;
  ssl->clientpemfile = clientpemfile ? xstrdup(clientpemfile) : NULL;
  
  switch (sslversion) {

  case SSL_VERSION_AUTO:
#ifdef OPENSSL_FIPS
    if (FIPS_mode()) {
      ssl->method = TLSv1_client_method();
    } else {
#endif
      ssl->method = SSLv23_client_method();
#ifdef OPENSSL_FIPS
    }
#endif
    break;

  case SSL_VERSION_SSLV2:
#ifdef OPENSSL_FIPS
    if (FIPS_mode()) {
      LogError("SSLv2 is not allowed in FIPS mode - use TLSv1");
      goto sslerror;
    } else {
#endif
      ssl->method = SSLv2_client_method();
#ifdef OPENSSL_FIPS
    }
#endif
    break;

  case SSL_VERSION_SSLV3:
#ifdef OPENSSL_FIPS
    if (FIPS_mode()) {
      LogError("SSLv3 is not allowed in FIPS mode - use TLSv1");
      goto sslerror;
    } else {
#endif
      ssl->method = SSLv3_client_method();
#ifdef OPENSSL_FIPS
    }
#endif
    break;

  case SSL_VERSION_TLS:
    ssl->method = TLSv1_client_method();
    break;

  default:
    LogError("%s: Unknown SSL version!\n", prog);
    goto sslerror;

  }

  if (!ssl->method) {
    LogError("%s: Cannot initialize SSL method -- %s\n", prog, SSLERROR);
    goto sslerror;
  } 

  if (!(ssl->ctx = SSL_CTX_new(ssl->method))) {
    LogError("%s: Cannot initialize SSL server certificate handler -- %s\n", prog, SSLERROR);
    goto sslerror;
  }

  if (ssl->clientpemfile) {

    if (SSL_CTX_use_certificate_chain_file(ssl->ctx, ssl->clientpemfile) <= 0) {
      LogError("%s: Cannot initialize SSL server certificate -- %s\n", prog, SSLERROR);
      goto sslerror;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl->ctx, ssl->clientpemfile, SSL_FILETYPE_PEM) <= 0) {
      LogError("%s: Cannot initialize SSL server private key -- %s\n", prog, SSLERROR);
      goto sslerror;
    }

    if (!SSL_CTX_check_private_key(ssl->ctx)) {
      LogError("%s: Private key does not match the certificate public key -- %s\n", prog, SSLERROR);
      goto sslerror;
    }

  }

  return ssl;

sslerror:
  delete_ssl_socket(ssl);
  return NULL;
}


/* ----------------------------------------------------------------- Private */


/**
 * Init verification of transmitted client certs
 */
static int verify_init(ssl_server_connection *ssl_server) {
  struct stat stat_buf;

  if (!ssl_server->clientpemfile) {
    SSL_CTX_set_verify(ssl_server->ctx, SSL_VERIFY_NONE, NULL);
    return TRUE;
  }

  if (stat(ssl_server->clientpemfile, &stat_buf) == -1) {
    LogError("%s: Cannot stat the SSL pem path '%s' -- %s\n", prog, Run.httpsslclientpem, STRERROR);
    return FALSE;
  }
  
  if (S_ISDIR(stat_buf.st_mode)) {

    if (!SSL_CTX_load_verify_locations(ssl_server->ctx, NULL , ssl_server->clientpemfile)) {
      LogError("%s: Error setting verify directory to %s -- %s\n", prog, Run.httpsslclientpem, SSLERROR);
      return FALSE;
    }

    LogInfo("%s: Loaded SSL client pem directory '%s'\n", prog, ssl_server->clientpemfile);

    /* Monit's server cert for cli support */

    if (!SSL_CTX_load_verify_locations(ssl_server->ctx, ssl_server->pemfile, NULL)) {
      LogError("%s: Error loading verify certificates from %s -- %s\n", prog, ssl_server->pemfile, SSLERROR);
      return FALSE;
    }

    LogInfo("%s: Loaded monit's SSL pem server file '%s'\n", prog, ssl_server->pemfile);

  } else if (S_ISREG(stat_buf.st_mode)) {

    if (!SSL_CTX_load_verify_locations(ssl_server->ctx, ssl_server->clientpemfile, NULL)) {
      LogError("%s: Error loading verify certificates from %s -- %s\n", prog, Run.httpsslclientpem, SSLERROR);
      return FALSE;
    }

    LogInfo("%s: Loaded SSL pem client file '%s'\n", prog, ssl_server->clientpemfile);

    /* Monits server cert for cli support ! */

    if (!SSL_CTX_load_verify_locations(ssl_server->ctx, ssl_server->pemfile, NULL)) {
      LogError("%s: Error loading verify certificates from %s -- %s\n", prog, ssl_server->pemfile, SSLERROR);
      return FALSE;
    }

    LogInfo("%s: Loaded monit's SSL pem server file '%s'\n", prog, ssl_server->pemfile);

    SSL_CTX_set_client_CA_list(ssl_server->ctx, SSL_load_client_CA_file(ssl_server->clientpemfile));

  } else {
    LogError("%s: SSL client pem path is no file or directory %s\n", prog, ssl_server->clientpemfile);
    return FALSE;
  }

  SSL_CTX_set_verify(ssl_server->ctx, SSL_VERIFY_PEER, verify_callback);

  return TRUE;
}


/**
 * Check the transmitted client certs and a compare with client cert database
 */
static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
  char subject[STRLEN];
  X509_OBJECT found_cert;

  X509_NAME_oneline(X509_get_subject_name(ctx->current_cert), subject, STRLEN-1);

  if (!preverify_ok && !check_preverify(ctx))
    return 0;

  if (ctx->error_depth == 0 && X509_STORE_get_by_subject(ctx, X509_LU_X509, X509_get_subject_name(ctx->current_cert), &found_cert) != 1) {
    LogError("%s: SSL connection rejected. No matching certificate found -- %s\n", prog, SSLERROR);
    return 0;
  }

  return 1; 
}


/**
 * Analyse errors found before actual verification
 * @return TRUE if successful
 */
static int check_preverify(X509_STORE_CTX *ctx) {
  if ((ctx->error != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) && (ctx->error != X509_V_ERR_INVALID_PURPOSE)) {
    /* Remote site specified a certificate, but it's not correct */
    LogError("%s: SSL connection rejected because certificate verification has failed -- error %i\n", prog, ctx->error);
    /* Reject connection */
    return FALSE;
  } 

  if (allow_self_certification && (ctx->error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)) {
    /* Let's accept self signed certs for the moment! */
    LogInfo("%s: SSL connection accepted with self signed certificate!\n", prog);
    ctx->error = 0;
    return TRUE;
  } 

  /* Reject connection */
  LogError("%s: SSL connection rejected because certificate verification has failed -- error %i!\n", prog, ctx->error);
  return FALSE;
}


/**
 * Helper function for the SSL threadding support
 * @return current thread number
 */
static int unsigned long ssl_thread_id() {
  return ((unsigned long) pthread_self());
}


/**
 * Helper function for the SSL threadding support
 */
static void ssl_mutex_lock(int mode, int n, const char *file, int line) {
  if (mode & CRYPTO_LOCK)
    assert(pthread_mutex_lock( & ssl_mutex_table[n]) == 0);
  else
    assert(pthread_mutex_unlock( & ssl_mutex_table[n]) == 0);
}


/**
 * Handle errors during read, write, connect and accept
 * @return TRUE if non fatal, FALSE if non fatal and retry
 */
static int handle_error(int code, ssl_connection *ssl) {
  int ssl_error = SSL_get_error(ssl->handler, code);

  switch (ssl_error) {
    
  case SSL_ERROR_WANT_READ:
    if (can_read(ssl->socket, SSL_TIMEOUT))
      return TRUE;
    LogError("%s: Openssl read timeout error!\n", prog);
    break;
      
  case SSL_ERROR_WANT_WRITE:
    if (can_read(ssl->socket, SSL_TIMEOUT))
      return TRUE;
    LogError("%s: Openssl write timeout error!\n", prog);
    break;
    
  case SSL_ERROR_SYSCALL:
    LogError("%s: Openssl syscall error: %s!\n", prog, STRERROR);
    break;

  case SSL_ERROR_SSL:
    LogError("%s: Openssl engine error: %s\n", prog, SSLERROR);
    break;
      
  default:
    LogError("%s: Openssl error!\n", prog);
    break;

  }

  return FALSE;
}


/**
 * Garbage collection for non reusable parts of the ssl connection
 * @param ssl ssl connection
 */
static void cleanup_ssl_socket(ssl_connection *ssl) {
  if (!ssl)
    return;

  if (ssl->cert) {
    X509_free(ssl->cert);
    ssl->cert = NULL;
  }

  if (ssl->handler) {
    SSL_free(ssl->handler);
    ssl->handler = NULL;
  }

  if (ssl->socket_bio) {
    /* no BIO_free(ssl->socket_bio); necessary, because BIO is freed by ssl->handler */
    ssl->socket_bio = NULL;
  }

  FREE(ssl->cert_issuer);
  FREE(ssl->cert_subject);
  FREE(ssl->cert_md5);
  FREE(ssl->clientpemfile);
}


/**
 * Garbage collection for a SSL server connection. 
 * @param ssl_server data for ssl server connection
 */
static void cleanup_ssl_server_socket(ssl_server_connection *ssl_server) {
  if (!ssl_server)
    return;

  FREE(ssl_server->pemfile);
  FREE(ssl_server->clientpemfile);

  while (ssl_server->ssl_conn_list) {
    ssl_connection *ssl = ssl_server->ssl_conn_list;
    ssl_server->ssl_conn_list = ssl_server->ssl_conn_list->next;
    close_accepted_ssl_socket(ssl_server, ssl);
  }
}


/**
 * Updates some data in the ssl connection
 * @param ssl reference to ssl connection 
 * @return TRUE, if not successful FALSE 
 */
static int update_ssl_cert_data(ssl_connection *ssl) {
  unsigned char md5[EVP_MAX_MD_SIZE];

  ASSERT(ssl);
  
  if (!(ssl->cert = SSL_get_peer_certificate(ssl->handler)))
    return FALSE;

#ifdef OPENSSL_FIPS
  if (!FIPS_mode()) {
    /* In FIPS-140 mode, MD5 is unavailable. */
#endif
    ssl->cert_issuer = X509_NAME_oneline (X509_get_issuer_name(ssl->cert), 0, 0);
    ssl->cert_subject = X509_NAME_oneline (X509_get_subject_name(ssl->cert), 0, 0);
    X509_digest(ssl->cert, EVP_md5(), md5, &ssl->cert_md5_len);
    ssl->cert_md5= (unsigned char *)xstrdup((char *)md5);
#ifdef OPENSSL_FIPS
  }
#endif
  return TRUE;
}


/**
 * Generate a new ssl server connection
 * @return ssl server connection container
 */
static ssl_server_connection *new_ssl_server_connection(char * pemfile, char * clientpemfile) {
  ssl_server_connection *ssl_server;

  ASSERT(pemfile);

  NEW(ssl_server);
  ssl_server->ctx = NULL;
  ssl_server->method = NULL;
  ssl_server->server_socket = 0;
  ssl_server->ssl_conn_list = NULL;
  ssl_server->pemfile = xstrdup(pemfile);
  ssl_server->clientpemfile = clientpemfile ? xstrdup(clientpemfile) : NULL;
  
  return ssl_server;
}

#ifdef OPENSSL_FIPS
/**
 * Enable FIPS mode, if it isn't enabled yet.
 */
void enable_fips_mode() {
  if (!FIPS_mode()) {
    ASSERT(FIPS_mode_set(1));
    LogInfo("FIPS-140 mode is enabled\n");
  }
}
#endif

/**
 * Start SSL support library. It has to be run before the SSL support
 * can be used.
 * @return TRUE, or FALSE if an error has occured.
 */
static int start_ssl() {
  if (! ssl_initialized) {
    int i;
    int locks = CRYPTO_num_locks();

#ifdef OPENSSL_FIPS
    if (Run.fipsEnabled)
      enable_fips_mode();
#endif

    ssl_initialized = TRUE;
    ERR_load_crypto_strings();
    ssl_mutex_table = xcalloc(locks, sizeof(pthread_mutex_t));
    for (i = 0; i < locks; i++)
      pthread_mutex_init(&ssl_mutex_table[i], NULL);
    CRYPTO_set_id_callback(ssl_thread_id);
    CRYPTO_set_locking_callback(ssl_mutex_lock);
    SSL_library_init();
    if (File_exist(URANDOM_DEVICE)) {
      return(RAND_load_file(URANDOM_DEVICE, RANDOM_BYTES)==RANDOM_BYTES);
    } else if (File_exist(RANDOM_DEVICE)) {
      DEBUG("Gathering entropy from the random device\n");
      return(RAND_load_file(RANDOM_DEVICE, RANDOM_BYTES)==RANDOM_BYTES);
    }
    return FALSE;
  }

  return TRUE;
}


#endif


