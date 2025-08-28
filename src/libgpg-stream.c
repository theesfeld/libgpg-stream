/* libgpg-stream.c - Simplified GNU-Standard GPG Streaming Implementation
 *
 * Copyright (C) 2025 William Theesfeld <william@theesfeld.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "libgpg-stream.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <gpgme.h>
#include <locale.h>
#include <time.h>
#include <stdarg.h>

/* ========================================================================
 * INTERNAL TYPES - Hidden implementation details
 * ======================================================================== */

#define GPG_STREAM_MAX_PACKET_SIZE 4096
#define GPG_STREAM_KEYID_SIZE 16
#define GPG_STREAM_SESSION_ID_SIZE 8

/* Wire protocol packet - packed to prevent alignment issues */
typedef struct __attribute__((packed)) {
  uint32_t sequence;
  double timestamp;
  size_t encrypted_size;
  char sender_keyid[GPG_STREAM_KEYID_SIZE + 1];
  uint8_t encrypted_data[GPG_STREAM_MAX_PACKET_SIZE];
} gpg_wire_packet_t;

/* Stream context - opaque to user */
struct gpg_stream_t {
  /* Network */
  int sockfd;
  struct sockaddr_in addr;
  char multicast_addr[64];
  int port;
  
  /* GPG */
  gpgme_ctx_t gpgme_ctx;
  char sender_keyid[GPG_STREAM_KEYID_SIZE + 1];
  char **recipient_keys;
  int recipient_count;
  int recipient_capacity;
  
  /* State */
  uint32_t sequence;
  pthread_t source_thread;
  bool source_running;
  gpg_source_type_t source_type;
  const char *source_path;
  double source_interval;
  gpg_data_func_t source_func;
  void *source_context;
  
  /* Statistics */
  gpg_stream_stats_t stats;
  
  /* Logging */
  gpg_log_func_t log_callback;
  int log_level;
  
  /* Error handling */
  char last_error[512];
  
  /* Receive state */
  bool receiving;
  pthread_t receive_thread;
  gpg_receive_callback_t receive_callback;
  void *receive_context;
  
  /* Thread safety */
  pthread_mutex_t mutex;
};

/* ========================================================================
 * INTERNAL UTILITIES
 * ======================================================================== */

static void
log_message (gpg_stream_t *stream, int level, const char *format, ...)
{
  if (!stream->log_callback || level > stream->log_level)
    return;
    
  va_list args;
  va_start (args, format);
  char buffer[1024];
  vsnprintf (buffer, sizeof (buffer), format, args);
  va_end (args);
  
  stream->log_callback (level, buffer);
}

static void
set_error (gpg_stream_t *stream, const char *format, ...)
{
  va_list args;
  va_start (args, format);
  vsnprintf (stream->last_error, sizeof (stream->last_error), format, args);
  va_end (args);
  
  log_message (stream, GPG_LOG_ERROR, "%s", stream->last_error);
}

static bool
init_gpgme_context (gpg_stream_t *stream)
{
  gpgme_error_t err;
  
  /* Initialize GPGME */
  gpgme_check_version (NULL);
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
  
  err = gpgme_new (&stream->gpgme_ctx);
  if (err)
    {
      set_error (stream, "Failed to create GPGME context: %s", gpgme_strerror (err));
      return false;
    }
  
  /* Use binary mode for UDP transmission */
  gpgme_set_armor (stream->gpgme_ctx, 0);
  
  log_message (stream, GPG_LOG_DEBUG, "GPGME context initialized");
  return true;
}

static bool
create_socket (gpg_stream_t *stream)
{
  stream->sockfd = socket (AF_INET, SOCK_DGRAM, 0);
  if (stream->sockfd < 0)
    {
      set_error (stream, "Failed to create socket: %s", strerror (errno));
      return false;
    }
  
  /* Set socket options for multicast */
  int reuse = 1;
  if (setsockopt (stream->sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof (reuse)) < 0)
    {
      set_error (stream, "Failed to set socket reuse: %s", strerror (errno));
      close (stream->sockfd);
      return false;
    }
  
  /* Set up multicast address */
  memset (&stream->addr, 0, sizeof (stream->addr));
  stream->addr.sin_family = AF_INET;
  stream->addr.sin_port = htons (stream->port);
  inet_pton (AF_INET, stream->multicast_addr, &stream->addr.sin_addr);
  
  log_message (stream, GPG_LOG_DEBUG, "Socket created for %s:%d", 
               stream->multicast_addr, stream->port);
  return true;
}

static ssize_t
encrypt_and_sign_data (gpg_stream_t *stream, const void *data, size_t size,
                       void *encrypted_buffer, size_t buffer_size)
{
  gpgme_error_t err;
  gpgme_data_t plain, cipher;
  gpgme_key_t *keys;
  
  /* Create data objects */
  err = gpgme_data_new_from_mem (&plain, data, size, 0);
  if (err)
    {
      set_error (stream, "Failed to create plain data: %s", gpgme_strerror (err));
      return -1;
    }
  
  err = gpgme_data_new (&cipher);
  if (err)
    {
      set_error (stream, "Failed to create cipher data: %s", gpgme_strerror (err));
      gpgme_data_release (plain);
      return -1;
    }
  
  /* Set up recipient keys */
  keys = malloc (sizeof (gpgme_key_t) * (stream->recipient_count + 1));
  for (int i = 0; i < stream->recipient_count; i++)
    {
      err = gpgme_get_key (stream->gpgme_ctx, stream->recipient_keys[i], &keys[i], 0);
      if (err)
        {
          set_error (stream, "Failed to get recipient key %s: %s",
                     stream->recipient_keys[i], gpgme_strerror (err));
          for (int j = 0; j < i; j++)
            gpgme_key_unref (keys[j]);
          free (keys);
          gpgme_data_release (plain);
          gpgme_data_release (cipher);
          return -1;
        }
    }
  keys[stream->recipient_count] = NULL;
  
  /* Encrypt and sign */
  err = gpgme_op_encrypt_sign (stream->gpgme_ctx, keys, GPGME_ENCRYPT_ALWAYS_TRUST,
                               plain, cipher);
  
  /* Clean up keys */
  for (int i = 0; i < stream->recipient_count; i++)
    gpgme_key_unref (keys[i]);
  free (keys);
  
  if (err)
    {
      set_error (stream, "Failed to encrypt and sign: %s", gpgme_strerror (err));
      gpgme_data_release (plain);
      gpgme_data_release (cipher);
      return -1;
    }
  
  /* Get encrypted data */
  size_t encrypted_size;
  char *encrypted_data = gpgme_data_release_and_get_mem (cipher, &encrypted_size);
  
  if (encrypted_size > buffer_size)
    {
      set_error (stream, "Encrypted data too large: %zu > %zu", encrypted_size, buffer_size);
      gpgme_free (encrypted_data);
      gpgme_data_release (plain);
      return -1;
    }
  
  memcpy (encrypted_buffer, encrypted_data, encrypted_size);
  gpgme_free (encrypted_data);
  gpgme_data_release (plain);
  
  return encrypted_size;
}

static ssize_t
decrypt_and_verify_data (gpg_stream_t *stream, const void *encrypted_data, 
                         size_t encrypted_size, void *plain_buffer, 
                         size_t buffer_size, gpg_packet_info_t *info)
{
  gpgme_error_t err;
  gpgme_data_t cipher, plain;
  gpgme_ctx_t ctx;
  
  /* Create fresh GPGME context for decryption */
  err = gpgme_new (&ctx);
  if (err)
    {
      set_error (stream, "Failed to create decrypt context: %s", gpgme_strerror (err));
      return -1;
    }
  
  gpgme_set_armor (ctx, 0);
  
  /* Create data objects */
  err = gpgme_data_new_from_mem (&cipher, encrypted_data, encrypted_size, 0);
  if (err)
    {
      set_error (stream, "Failed to create cipher data: %s", gpgme_strerror (err));
      gpgme_release (ctx);
      return -1;
    }
  
  err = gpgme_data_new (&plain);
  if (err)
    {
      set_error (stream, "Failed to create plain data: %s", gpgme_strerror (err));
      gpgme_data_release (cipher);
      gpgme_release (ctx);
      return -1;
    }
  
  /* Try decrypt and verify first */
  err = gpgme_op_decrypt_verify (ctx, cipher, plain);
  if (err)
    {
      log_message (stream, GPG_LOG_WARN, "Decrypt+verify failed: %s", gpgme_strerror (err));
      
      /* Reset data and try decrypt only */
      gpgme_data_seek (cipher, 0, SEEK_SET);
      gpgme_data_seek (plain, 0, SEEK_SET);
      
      err = gpgme_op_decrypt (ctx, cipher, plain);
      if (err)
        {
          set_error (stream, "Failed to decrypt: %s", gpgme_strerror (err));
          gpgme_data_release (cipher);
          gpgme_data_release (plain);
          gpgme_release (ctx);
          return -1;
        }
      
      /* Mark as unsigned */
      if (info)
        {
          info->was_signed = false;
          info->signature_valid = false;
        }
    }
  else
    {
      /* Successfully decrypted and verified */
      if (info)
        {
          info->was_signed = true;
          
          /* Get signature verification result */
          gpgme_verify_result_t verify_result = gpgme_op_verify_result (ctx);
          if (verify_result && verify_result->signatures)
            {
              gpgme_signature_t sig = verify_result->signatures;
              info->signature_valid = (sig->status == GPG_ERR_NO_ERROR);
              
              /* Get signer information */
              if (sig->fpr)
                info->sender_fingerprint = strdup (sig->fpr);
              
              /* Try to get email from key */
              gpgme_key_t key;
              if (gpgme_get_key (ctx, sig->fpr, &key, 0) == GPG_ERR_NO_ERROR)
                {
                  if (key->uids && key->uids->email)
                    info->sender_email = strdup (key->uids->email);
                  gpgme_key_unref (key);
                }
            }
          else
            {
              info->signature_valid = false;
            }
        }
    }
  
  /* Read decrypted data */
  gpgme_data_seek (plain, 0, SEEK_SET);
  ssize_t plain_size = gpgme_data_read (plain, plain_buffer, buffer_size);
  
  if (info)
    info->data_size = plain_size;
  
  gpgme_data_release (cipher);
  gpgme_data_release (plain);
  gpgme_release (ctx);
  
  return plain_size;
}

/* ========================================================================
 * INITIALIZATION - Simple, automatic key detection
 * ======================================================================== */

gpg_stream_t *
gpg_stream_new (void)
{
  return gpg_stream_new_address ("239.0.0.1", 5555);
}

gpg_stream_t *
gpg_stream_new_address (const char *address, int port)
{
  gpg_stream_t *stream = calloc (1, sizeof (gpg_stream_t));
  if (!stream)
    return NULL;
  
  /* Initialize defaults */
  strncpy (stream->multicast_addr, address ? address : "239.0.0.1", 
           sizeof (stream->multicast_addr) - 1);
  stream->port = port > 0 ? port : 5555;
  stream->sockfd = -1;
  stream->sequence = 1;
  stream->recipient_capacity = 16;
  stream->recipient_keys = malloc (sizeof (char*) * stream->recipient_capacity);
  
  pthread_mutex_init (&stream->mutex, NULL);
  
  if (!init_gpgme_context (stream))
    {
      gpg_stream_free (stream);
      return NULL;
    }
  
  return stream;
}

void
gpg_stream_free (gpg_stream_t *stream)
{
  if (!stream)
    return;
  
  /* Stop any running operations */
  gpg_stream_stop_source (stream);
  gpg_stream_stop_receive (stream);
  
  /* Clean up socket */
  if (stream->sockfd >= 0)
    close (stream->sockfd);
  
  /* Clean up GPG */
  if (stream->gpgme_ctx)
    gpgme_release (stream->gpgme_ctx);
  
  /* Clean up recipients */
  for (int i = 0; i < stream->recipient_count; i++)
    free (stream->recipient_keys[i]);
  free (stream->recipient_keys);
  
  pthread_mutex_destroy (&stream->mutex);
  free (stream);
}

void
gpg_stream_set_logging (gpg_stream_t *stream, gpg_log_func_t callback, int level)
{
  if (!stream)
    return;
    
  stream->log_callback = callback;
  stream->log_level = level;
}

/* ========================================================================
 * KEY MANAGEMENT - Automatic with overrides
 * ======================================================================== */

bool
gpg_stream_auto_keys (gpg_stream_t *stream)
{
  if (!stream)
    return false;
  
  gpgme_error_t err;
  gpgme_key_t key;
  
  /* Find first secret key */
  err = gpgme_op_keylist_start (stream->gpgme_ctx, NULL, 1); /* secret keys only */
  if (err)
    {
      set_error (stream, "Failed to start key listing: %s", gpgme_strerror (err));
      return false;
    }
  
  err = gpgme_op_keylist_next (stream->gpgme_ctx, &key);
  if (err)
    {
      set_error (stream, "No secret keys found: %s", gpgme_strerror (err));
      gpgme_op_keylist_end (stream->gpgme_ctx);
      return false;
    }
  
  /* Use first key as both sender and recipient */
  strncpy (stream->sender_keyid, key->subkeys->keyid, GPG_STREAM_KEYID_SIZE);
  
  if (!gpg_stream_add_recipient (stream, key->subkeys->keyid))
    {
      gpgme_key_unref (key);
      gpgme_op_keylist_end (stream->gpgme_ctx);
      return false;
    }
  
  log_message (stream, GPG_LOG_INFO, "Auto-detected key: %s (%s)", 
               key->subkeys->keyid, key->uids ? key->uids->email : "no email");
  
  gpgme_key_unref (key);
  gpgme_op_keylist_end (stream->gpgme_ctx);
  return true;
}

bool
gpg_stream_set_sender (gpg_stream_t *stream, const char *key_id)
{
  if (!stream || !key_id)
    return false;
  
  /* Verify key exists and can sign */
  gpgme_key_t key;
  gpgme_error_t err = gpgme_get_key (stream->gpgme_ctx, key_id, &key, 1);
  if (err)
    {
      set_error (stream, "Sender key not found: %s", gpgme_strerror (err));
      return false;
    }
  
  if (!key->can_sign)
    {
      set_error (stream, "Key cannot sign: %s", key_id);
      gpgme_key_unref (key);
      return false;
    }
  
  strncpy (stream->sender_keyid, key_id, GPG_STREAM_KEYID_SIZE);
  
  /* Add as signing key */
  gpgme_signers_clear (stream->gpgme_ctx);
  err = gpgme_signers_add (stream->gpgme_ctx, key);
  if (err)
    {
      set_error (stream, "Failed to add signing key: %s", gpgme_strerror (err));
      gpgme_key_unref (key);
      return false;
    }
  
  log_message (stream, GPG_LOG_INFO, "Sender key set: %s", key_id);
  gpgme_key_unref (key);
  return true;
}

bool
gpg_stream_add_recipient (gpg_stream_t *stream, const char *key_id)
{
  if (!stream || !key_id)
    return false;
  
  /* Verify key exists and can encrypt */
  gpgme_key_t key;
  gpgme_error_t err = gpgme_get_key (stream->gpgme_ctx, key_id, &key, 0);
  if (err)
    {
      set_error (stream, "Recipient key not found: %s", gpgme_strerror (err));
      return false;
    }
  
  if (!key->can_encrypt)
    {
      set_error (stream, "Key cannot encrypt: %s", key_id);
      gpgme_key_unref (key);
      return false;
    }
  
  /* Expand array if needed */
  if (stream->recipient_count >= stream->recipient_capacity)
    {
      stream->recipient_capacity *= 2;
      stream->recipient_keys = realloc (stream->recipient_keys,
                                        sizeof (char*) * stream->recipient_capacity);
    }
  
  stream->recipient_keys[stream->recipient_count++] = strdup (key_id);
  
  log_message (stream, GPG_LOG_INFO, "Recipient added: %s", key_id);
  gpgme_key_unref (key);
  return true;
}

/* ========================================================================
 * SENDING - Universal input, automatic formatting
 * ======================================================================== */

bool
gpg_stream_send (gpg_stream_t *stream, const void *data, size_t size)
{
  if (!stream || !data || size == 0)
    return false;
  
  pthread_mutex_lock (&stream->mutex);
  
  /* Create socket if needed */
  if (stream->sockfd < 0 && !create_socket (stream))
    {
      pthread_mutex_unlock (&stream->mutex);
      return false;
    }
  
  /* Create packet */
  gpg_wire_packet_t packet = {0};
  packet.sequence = htonl (stream->sequence++);
  packet.timestamp = time (NULL);
  strncpy (packet.sender_keyid, stream->sender_keyid, GPG_STREAM_KEYID_SIZE);
  packet.sender_keyid[GPG_STREAM_KEYID_SIZE] = '\0';
  
  /* Encrypt and sign data */
  ssize_t encrypted_size = encrypt_and_sign_data (stream, data, size,
                                                  packet.encrypted_data,
                                                  GPG_STREAM_MAX_PACKET_SIZE);
  if (encrypted_size < 0)
    {
      pthread_mutex_unlock (&stream->mutex);
      return false;
    }
  
  packet.encrypted_size = encrypted_size;
  
  /* Send packet */
  ssize_t sent = sendto (stream->sockfd, &packet, 
                         sizeof (packet) - GPG_STREAM_MAX_PACKET_SIZE + encrypted_size,
                         0, (struct sockaddr*)&stream->addr, sizeof (stream->addr));
  
  if (sent < 0)
    {
      set_error (stream, "Failed to send packet: %s", strerror (errno));
      pthread_mutex_unlock (&stream->mutex);
      return false;
    }
  
  stream->stats.packets_sent++;
  stream->stats.bytes_sent += size;
  
  log_message (stream, GPG_LOG_DEBUG, "Sent packet %u (%zu bytes encrypted to %zd)",
               ntohl (packet.sequence), size, encrypted_size);
  
  pthread_mutex_unlock (&stream->mutex);
  return true;
}

bool
gpg_stream_send_string (gpg_stream_t *stream, const char *str)
{
  return gpg_stream_send (stream, str, strlen (str));
}

bool
gpg_stream_send_fd (gpg_stream_t *stream, int fd)
{
  char buffer[4096];
  ssize_t bytes_read;
  
  while ((bytes_read = read (fd, buffer, sizeof (buffer))) > 0)
    {
      if (!gpg_stream_send (stream, buffer, bytes_read))
        return false;
    }
  
  return bytes_read == 0; /* EOF is success */
}

bool
gpg_stream_send_file (gpg_stream_t *stream, const char *path)
{
  int fd = open (path, O_RDONLY);
  if (fd < 0)
    {
      set_error (stream, "Failed to open file %s: %s", path, strerror (errno));
      return false;
    }
  
  bool result = gpg_stream_send_fd (stream, fd);
  close (fd);
  return result;
}

bool
gpg_stream_send_stdin (gpg_stream_t *stream)
{
  return gpg_stream_send_fd (stream, STDIN_FILENO);
}

bool
gpg_stream_send_pipe (gpg_stream_t *stream, const char *pipe_path)
{
  int fd = open (pipe_path, O_RDONLY);
  if (fd < 0)
    {
      set_error (stream, "Failed to open pipe %s: %s", pipe_path, strerror (errno));
      return false;
    }
  
  bool result = gpg_stream_send_fd (stream, fd);
  close (fd);
  return result;
}

bool
gpg_stream_send_command (gpg_stream_t *stream, const char *command)
{
  FILE *fp = popen (command, "r");
  if (!fp)
    {
      set_error (stream, "Failed to execute command %s: %s", command, strerror (errno));
      return false;
    }
  
  char buffer[4096];
  size_t bytes_read;
  bool success = true;
  
  while ((bytes_read = fread (buffer, 1, sizeof (buffer), fp)) > 0)
    {
      if (!gpg_stream_send (stream, buffer, bytes_read))
        {
          success = false;
          break;
        }
    }
  
  pclose (fp);
  return success;
}

bool
gpg_stream_send_function (gpg_stream_t *stream, gpg_data_func_t func, void *context)
{
  if (!stream || !func)
    return false;
  
  char buffer[4096];
  ssize_t bytes_read;
  
  while ((bytes_read = func (context, buffer, sizeof (buffer))) > 0)
    {
      if (!gpg_stream_send (stream, buffer, bytes_read))
        return false;
    }
  
  return bytes_read == 0; /* EOF is success */
}

/* Thread function for continuous streaming */
static void *
source_thread_func (void *arg)
{
  gpg_stream_t *stream = (gpg_stream_t*)arg;
  
  while (stream->source_running)
    {
      bool success = false;
      
      switch (stream->source_type)
        {
        case GPG_SOURCE_STDIN:
          success = gpg_stream_send_stdin (stream);
          break;
        case GPG_SOURCE_FILE:
          success = gpg_stream_send_file (stream, (const char*)stream->source_path);
          break;
        case GPG_SOURCE_PIPE:
          success = gpg_stream_send_pipe (stream, (const char*)stream->source_path);
          break;
        case GPG_SOURCE_COMMAND:
          success = gpg_stream_send_command (stream, (const char*)stream->source_path);
          break;
        case GPG_SOURCE_FUNCTION:
          success = gpg_stream_send_function (stream, stream->source_func, stream->source_context);
          break;
        default:
          success = false;
          break;
        }
      
      if (!success && stream->source_running)
        {
          log_message (stream, GPG_LOG_WARN, "Source read failed, retrying in %.1fs", 
                       stream->source_interval);
        }
      
      /* Sleep for interval (unless stopping) */
      if (stream->source_running && stream->source_interval > 0)
        {
          struct timespec ts;
          ts.tv_sec = (time_t)stream->source_interval;
          ts.tv_nsec = (long)((stream->source_interval - ts.tv_sec) * 1e9);
          nanosleep (&ts, NULL);
        }
      else if (stream->source_running)
        {
          /* No interval specified, single shot */
          break;
        }
    }
  
  return NULL;
}

bool
gpg_stream_start_source (gpg_stream_t *stream, gpg_source_type_t type,
                          const void *source, double interval)
{
  if (!stream || stream->source_running)
    return false;
  
  stream->source_type = type;
  stream->source_interval = interval;
  stream->source_running = true;
  
  switch (type)
    {
    case GPG_SOURCE_STDIN:
    case GPG_SOURCE_FILE:
    case GPG_SOURCE_PIPE:
    case GPG_SOURCE_COMMAND:
      stream->source_path = (const char*)source;
      break;
    case GPG_SOURCE_FUNCTION:
      /* source should be cast to appropriate function pointer */
      stream->source_func = (gpg_data_func_t)source;
      break;
    default:
      stream->source_running = false;
      set_error (stream, "Invalid source type: %d", type);
      return false;
    }
  
  /* Create thread for continuous streaming */
  if (pthread_create (&stream->source_thread, NULL, source_thread_func, stream) != 0)
    {
      stream->source_running = false;
      set_error (stream, "Failed to create source thread: %s", strerror (errno));
      return false;
    }
  
  log_message (stream, GPG_LOG_INFO, "Started continuous source (interval: %.1fs)", interval);
  return true;
}

void
gpg_stream_stop_source (gpg_stream_t *stream)
{
  if (!stream || !stream->source_running)
    return;
  
  stream->source_running = false;
  
  if (stream->source_thread)
    {
      pthread_cancel (stream->source_thread);
      pthread_join (stream->source_thread, NULL);
      stream->source_thread = 0;
    }
  
  log_message (stream, GPG_LOG_INFO, "Stopped continuous source");
}

/* ========================================================================
 * RECEIVING - Automatic session management, full metadata
 * ======================================================================== */

bool
gpg_stream_start_receive (gpg_stream_t *stream)
{
  if (!stream || stream->receiving)
    return false;
  
  /* Create and bind socket */
  if (stream->sockfd < 0)
    {
      if (!create_socket (stream))
        return false;
    }
  
  /* Bind for receiving */
  if (bind (stream->sockfd, (struct sockaddr*)&stream->addr, sizeof (stream->addr)) < 0)
    {
      set_error (stream, "Failed to bind socket: %s", strerror (errno));
      return false;
    }
  
  /* Join multicast group */
  struct ip_mreq mreq;
  mreq.imr_multiaddr.s_addr = stream->addr.sin_addr.s_addr;
  mreq.imr_interface.s_addr = INADDR_ANY;
  
  if (setsockopt (stream->sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof (mreq)) < 0)
    {
      set_error (stream, "Failed to join multicast group: %s", strerror (errno));
      return false;
    }
  
  stream->receiving = true;
  log_message (stream, GPG_LOG_INFO, "Started receiving on %s:%d", 
               stream->multicast_addr, stream->port);
  
  return true;
}

void
gpg_stream_stop_receive (gpg_stream_t *stream)
{
  if (!stream)
    return;
  
  stream->receiving = false;
  
  if (stream->receive_thread)
    {
      pthread_cancel (stream->receive_thread);
      pthread_join (stream->receive_thread, NULL);
      stream->receive_thread = 0;
    }
}

ssize_t
gpg_stream_receive (gpg_stream_t *stream, void *buffer, size_t size,
                    gpg_packet_info_t *info, int timeout_ms)
{
  if (!stream || !buffer || !stream->receiving)
    return -1;
  
  /* Set socket timeout */
  if (timeout_ms > 0)
    {
      struct timeval timeout;
      timeout.tv_sec = timeout_ms / 1000;
      timeout.tv_usec = (timeout_ms % 1000) * 1000;
      setsockopt (stream->sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof (timeout));
    }
  
  /* Receive packet */
  gpg_wire_packet_t packet;
  struct sockaddr_in sender_addr;
  socklen_t sender_len = sizeof (sender_addr);
  
  ssize_t received = recvfrom (stream->sockfd, &packet, sizeof (packet), 0,
                               (struct sockaddr*)&sender_addr, &sender_len);
  
  if (received < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0; /* Timeout */
      set_error (stream, "Failed to receive: %s", strerror (errno));
      return -1;
    }
  
  /* Decrypt and verify */
  if (info)
    {
      memset (info, 0, sizeof (*info));
      info->sequence = ntohl (packet.sequence);
      info->timestamp = packet.timestamp;
    }
  
  ssize_t plain_size = decrypt_and_verify_data (stream, packet.encrypted_data,
                                                packet.encrypted_size, buffer, size, info);
  
  if (plain_size < 0)
    {
      stream->stats.decrypt_failures++;
      return -1;
    }
  
  if (info && !info->signature_valid)
    stream->stats.signature_failures++;
  
  stream->stats.packets_received++;
  stream->stats.bytes_received += plain_size;
  
  log_message (stream, GPG_LOG_DEBUG, "Received packet %u (%zd bytes)",
               info ? info->sequence : 0, plain_size);
  
  return plain_size;
}

char *
gpg_stream_receive_string (gpg_stream_t *stream, gpg_packet_info_t *info, int timeout_ms)
{
  char *buffer = malloc (GPG_STREAM_MAX_PACKET_SIZE + 1);
  if (!buffer)
    return NULL;
  
  ssize_t received = gpg_stream_receive (stream, buffer, GPG_STREAM_MAX_PACKET_SIZE,
                                         info, timeout_ms);
  if (received < 0)
    {
      free (buffer);
      return NULL;
    }
  
  buffer[received] = '\0';
  return buffer;
}

/* ========================================================================
 * UTILITIES - GNU-standard error handling and debugging
 * ======================================================================== */

const char *
gpg_stream_error (gpg_stream_t *stream)
{
  return stream ? stream->last_error : "Invalid stream";
}

void
gpg_stream_clear_error (gpg_stream_t *stream)
{
  if (stream)
    stream->last_error[0] = '\0';
}

bool
gpg_stream_get_stats (gpg_stream_t *stream, gpg_stream_stats_t *stats)
{
  if (!stream || !stats)
    return false;
  
  pthread_mutex_lock (&stream->mutex);
  *stats = stream->stats;
  pthread_mutex_unlock (&stream->mutex);
  
  return true;
}

void
gpg_stream_reset_stats (gpg_stream_t *stream)
{
  if (!stream)
    return;
  
  pthread_mutex_lock (&stream->mutex);
  memset (&stream->stats, 0, sizeof (stream->stats));
  pthread_mutex_unlock (&stream->mutex);
}

void
gpg_packet_info_free (gpg_packet_info_t *info)
{
  if (!info)
    return;
  
  free (info->sender_fingerprint);
  free (info->sender_email);
  memset (info, 0, sizeof (*info));
}