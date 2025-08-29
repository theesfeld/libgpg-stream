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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
#include <sys/select.h>
#include <sys/time.h>

/* ========================================================================
 * INTERNAL TYPES - Hidden implementation details
 * ======================================================================== */

#define GPG_STREAM_MAX_PACKET_SIZE 4096
#define GPG_STREAM_KEYID_SIZE 16
#define GPG_STREAM_SESSION_ID_SIZE 8

/* Packet types for unicast client management */
#define PACKET_DATA        0  /* Normal data packet */
#define PACKET_SUBSCRIBE   1  /* Client registration */
#define PACKET_KEEPALIVE   2  /* Client keepalive */
#define PACKET_UNSUBSCRIBE 3  /* Client leaving */

/* Wire protocol packet - packed to prevent alignment issues */
typedef struct __attribute__((packed)) {
  uint8_t packet_type;       /* Packet type (data, subscribe, keepalive, etc) */
  uint32_t sequence;
  double timestamp;
  size_t data_size;
  char sender_keyid[GPG_STREAM_KEYID_SIZE + 1];
  uint8_t data[GPG_STREAM_MAX_PACKET_SIZE]; /* May be plain, signed, encrypted, or signed+encrypted */
} gpg_wire_packet_t;

/* Client tracking for unicast mode */
typedef struct client_node {
  struct sockaddr_in addr;
  time_t last_seen;
  struct client_node *next;
} client_node_t;

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
  gpg_mode_t mode;
  
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
  
  /* Unicast client tracking */
  client_node_t *clients;
  bool is_unicast_server;
  bool is_unicast_client;
  pthread_t cleanup_thread;
  pthread_t keepalive_thread;
  bool cleanup_running;
  bool keepalive_running;
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

static bool
is_multicast_address (const char *addr)
{
  if (!addr)
    return false;
    
  struct in_addr inaddr;
  if (inet_pton (AF_INET, addr, &inaddr) != 1)
    return false;
    
  uint32_t ip = ntohl (inaddr.s_addr);
  /* Multicast range: 224.0.0.0 - 239.255.255.255 (0xE0000000 - 0xEFFFFFFF) */
  return (ip >= 0xE0000000 && ip <= 0xEFFFFFFF);
}

static void
update_client_list (gpg_stream_t *stream, struct sockaddr_in *addr)
{
  if (!stream->is_unicast_server)
    return;
    
  /* Check if client already exists */
  for (client_node_t *client = stream->clients; client; client = client->next)
    {
      if (client->addr.sin_addr.s_addr == addr->sin_addr.s_addr &&
          client->addr.sin_port == addr->sin_port)
        {
          client->last_seen = time (NULL);
          return;
        }
    }
  
  /* New client - add to list */
  client_node_t *new_client = malloc (sizeof (client_node_t));
  if (!new_client)
    return;
    
  memcpy (&new_client->addr, addr, sizeof (struct sockaddr_in));
  new_client->last_seen = time (NULL);
  new_client->next = stream->clients;
  stream->clients = new_client;
  
  log_message (stream, GPG_LOG_INFO, "New client registered: %s:%d",
               inet_ntoa (addr->sin_addr), ntohs (addr->sin_port));
}

static void
remove_stale_clients (gpg_stream_t *stream, int timeout_seconds)
{
  if (!stream->is_unicast_server)
    return;
    
  time_t now = time (NULL);
  client_node_t **current = &stream->clients;
  
  while (*current)
    {
      if (now - (*current)->last_seen > timeout_seconds)
        {
          client_node_t *stale = *current;
          log_message (stream, GPG_LOG_INFO, "Removing stale client: %s:%d",
                       inet_ntoa (stale->addr.sin_addr), ntohs (stale->addr.sin_port));
          *current = stale->next;
          free (stale);
        }
      else
        {
          current = &(*current)->next;
        }
    }
}

static void *
keepalive_thread_func (void *arg)
{
  gpg_stream_t *stream = (gpg_stream_t *)arg;
  gpg_wire_packet_t keepalive = {0};
  keepalive.packet_type = PACKET_KEEPALIVE;
  
  while (stream->keepalive_running && stream->receiving)
    {
      /* Send keepalive to server */
      sendto (stream->sockfd, &keepalive, sizeof (keepalive.packet_type) + sizeof (keepalive.sequence), 0,
              (struct sockaddr*)&stream->addr, sizeof (stream->addr));
      
      /* Sleep for 20 seconds */
      for (int i = 0; i < 20 && stream->keepalive_running; i++)
        sleep (1);
    }
  
  return NULL;
}

static void *
cleanup_thread_func (void *arg)
{
  gpg_stream_t *stream = (gpg_stream_t *)arg;
  
  while (stream->cleanup_running)
    {
      /* Remove stale clients every 10 seconds */
      for (int i = 0; i < 10 && stream->cleanup_running; i++)
        sleep (1);
        
      if (!stream->cleanup_running)
        break;
        
      pthread_mutex_lock (&stream->mutex);
      remove_stale_clients (stream, 60);  /* 60 second timeout */
      pthread_mutex_unlock (&stream->mutex);
    }
  
  return NULL;
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
process_data_for_send (gpg_stream_t *stream, const void *data, size_t size,
                       void *output_buffer, size_t buffer_size)
{
  gpgme_error_t err;
  gpgme_data_t plain, output;
  gpgme_key_t *keys = NULL;
  size_t output_size;
  char *output_data;
  
  /* Handle plain mode */
  if (stream->mode == GPG_MODE_PLAIN)
    {
      if (size > buffer_size)
        {
          set_error (stream, "Data too large: %zu > %zu", size, buffer_size);
          return -1;
        }
      memcpy (output_buffer, data, size);
      return size;
    }
  
  /* Create data objects for GPG operations */
  err = gpgme_data_new_from_mem (&plain, data, size, 0);
  if (err)
    {
      set_error (stream, "Failed to create plain data: %s", gpgme_strerror (err));
      return -1;
    }
  
  err = gpgme_data_new (&output);
  if (err)
    {
      set_error (stream, "Failed to create output data: %s", gpgme_strerror (err));
      gpgme_data_release (plain);
      return -1;
    }
  
  /* Handle different modes */
  switch (stream->mode)
    {
    case GPG_MODE_SIGN_ONLY:
      err = gpgme_op_sign (stream->gpgme_ctx, plain, output, GPGME_SIG_MODE_NORMAL);
      if (err)
        set_error (stream, "Failed to sign: %s", gpgme_strerror (err));
      break;
      
    case GPG_MODE_ENCRYPT_ONLY:
      if (stream->recipient_count == 0)
        {
          set_error (stream, "No recipients for encryption");
          err = GPG_ERR_NO_PUBKEY;
          break;
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
              keys = NULL;
              break;
            }
        }
      
      if (!err)
        {
          keys[stream->recipient_count] = NULL;
          err = gpgme_op_encrypt (stream->gpgme_ctx, keys, GPGME_ENCRYPT_ALWAYS_TRUST,
                                  plain, output);
          if (err)
            set_error (stream, "Failed to encrypt: %s", gpgme_strerror (err));
        }
      break;
      
    case GPG_MODE_SIGN_AND_ENCRYPT:
      if (stream->recipient_count == 0)
        {
          set_error (stream, "No recipients for encryption");
          err = GPG_ERR_NO_PUBKEY;
          break;
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
              keys = NULL;
              break;
            }
        }
      
      if (!err)
        {
          keys[stream->recipient_count] = NULL;
          err = gpgme_op_encrypt_sign (stream->gpgme_ctx, keys, GPGME_ENCRYPT_ALWAYS_TRUST,
                                       plain, output);
          if (err)
            set_error (stream, "Failed to encrypt and sign: %s", gpgme_strerror (err));
        }
      break;
      
    default:
      err = GPG_ERR_INV_VALUE;
      set_error (stream, "Invalid GPG mode: %d", stream->mode);
      break;
    }
  
  /* Clean up keys */
  if (keys)
    {
      for (int i = 0; i < stream->recipient_count; i++)
        gpgme_key_unref (keys[i]);
      free (keys);
    }
  
  if (err)
    {
      gpgme_data_release (plain);
      gpgme_data_release (output);
      return -1;
    }
  
  /* Get processed data */
  output_data = gpgme_data_release_and_get_mem (output, &output_size);
  
  if (output_size > buffer_size)
    {
      set_error (stream, "Processed data too large: %zu > %zu", output_size, buffer_size);
      gpgme_free (output_data);
      gpgme_data_release (plain);
      return -1;
    }
  
  memcpy (output_buffer, output_data, output_size);
  gpgme_free (output_data);
  gpgme_data_release (plain);
  
  return output_size;
}

static ssize_t
process_received_data (gpg_stream_t *stream, const void *received_data, 
                       size_t received_size, void *plain_buffer, 
                       size_t buffer_size, gpg_packet_info_t *info)
{
  gpgme_error_t err;
  gpgme_data_t input, output;
  gpgme_ctx_t ctx;
  bool operation_successful = false;
  ssize_t plain_size = -1;
  
  /* Initialize info structure */
  if (info)
    {
      info->was_signed = false;
      info->was_encrypted = false;
      info->signature_valid = false;
      info->sender_fingerprint = NULL;
      info->sender_email = NULL;
    }
  
  /* First, try to detect if this is plain data by checking for GPG markers */
  const char *data_str = (const char*)received_data;
  const unsigned char *data_bytes = (const unsigned char*)received_data;
  bool looks_like_gpg = (received_size > 10 && 
                         (strstr(data_str, "-----BEGIN PGP") ||
                          (data_bytes[0] & 0x80))); /* Binary GPG starts with high bit set */
  
  if (!looks_like_gpg)
    {
      /* Treat as plain data */
      if (received_size > buffer_size)
        {
          set_error (stream, "Plain data too large: %zu > %zu", received_size, buffer_size);
          return -1;
        }
      
      memcpy (plain_buffer, received_data, received_size);
      
      if (info)
        info->data_size = received_size;
      
      log_message (stream, GPG_LOG_DEBUG, "Received plain data (%zu bytes)", received_size);
      return received_size;
    }
  
  /* Create fresh GPGME context for processing */
  err = gpgme_new (&ctx);
  if (err)
    {
      set_error (stream, "Failed to create GPG context: %s", gpgme_strerror (err));
      return -1;
    }
  
  gpgme_set_armor (ctx, 0);
  
  /* Create data objects */
  err = gpgme_data_new_from_mem (&input, received_data, received_size, 0);
  if (err)
    {
      set_error (stream, "Failed to create input data: %s", gpgme_strerror (err));
      gpgme_release (ctx);
      return -1;
    }
  
  err = gpgme_data_new (&output);
  if (err)
    {
      set_error (stream, "Failed to create output data: %s", gpgme_strerror (err));
      gpgme_data_release (input);
      gpgme_release (ctx);
      return -1;
    }
  
  /* Try operations in order: decrypt+verify, decrypt-only, verify-only */
  
  /* 1. Try decrypt and verify (signed+encrypted) */
  err = gpgme_op_decrypt_verify (ctx, input, output);
  if (err == GPG_ERR_NO_ERROR)
    {
      operation_successful = true;
      if (info)
        {
          info->was_encrypted = true;
          info->was_signed = true;
          
          /* Get signature verification result */
          gpgme_verify_result_t verify_result = gpgme_op_verify_result (ctx);
          if (verify_result && verify_result->signatures)
            {
              gpgme_signature_t sig = verify_result->signatures;
              info->signature_valid = (sig->status == GPG_ERR_NO_ERROR);
              
              if (sig->fpr)
                info->sender_fingerprint = strdup (sig->fpr);
              
              gpgme_key_t key;
              if (gpgme_get_key (ctx, sig->fpr, &key, 0) == GPG_ERR_NO_ERROR)
                {
                  if (key->uids && key->uids->email)
                    info->sender_email = strdup (key->uids->email);
                  gpgme_key_unref (key);
                }
            }
        }
      log_message (stream, GPG_LOG_DEBUG, "Processed signed+encrypted data");
    }
  else
    {
      /* 2. Try decrypt only (encrypted-only) */
      gpgme_data_seek (input, 0, SEEK_SET);
      gpgme_data_seek (output, 0, SEEK_SET);
      
      err = gpgme_op_decrypt (ctx, input, output);
      if (err == GPG_ERR_NO_ERROR)
        {
          operation_successful = true;
          if (info)
            {
              info->was_encrypted = true;
              info->was_signed = false;
            }
          log_message (stream, GPG_LOG_DEBUG, "Processed encrypted-only data");
        }
      else
        {
          /* 3. Try verify only (signed-only) */
          gpgme_data_seek (input, 0, SEEK_SET);
          gpgme_data_seek (output, 0, SEEK_SET);
          
          err = gpgme_op_verify (ctx, input, NULL, output);
          if (err == GPG_ERR_NO_ERROR)
            {
              operation_successful = true;
              if (info)
                {
                  info->was_encrypted = false;
                  info->was_signed = true;
                  
                  gpgme_verify_result_t verify_result = gpgme_op_verify_result (ctx);
                  if (verify_result && verify_result->signatures)
                    {
                      gpgme_signature_t sig = verify_result->signatures;
                      info->signature_valid = (sig->status == GPG_ERR_NO_ERROR);
                      
                      if (sig->fpr)
                        info->sender_fingerprint = strdup (sig->fpr);
                      
                      gpgme_key_t key;
                      if (gpgme_get_key (ctx, sig->fpr, &key, 0) == GPG_ERR_NO_ERROR)
                        {
                          if (key->uids && key->uids->email)
                            info->sender_email = strdup (key->uids->email);
                          gpgme_key_unref (key);
                        }
                    }
                }
              log_message (stream, GPG_LOG_DEBUG, "Processed signed-only data");
            }
        }
    }
  
  if (!operation_successful)
    {
      /* Could not decrypt/verify - treat as raw data and pass it through */
      log_message (stream, GPG_LOG_WARN, "Failed to process GPG data, streaming raw: %s", gpgme_strerror (err));
      
      if (received_size > buffer_size)
        {
          set_error (stream, "Raw data too large: %zu > %zu", received_size, buffer_size);
          gpgme_data_release (input);
          gpgme_data_release (output);
          gpgme_release (ctx);
          return -1;
        }
      
      memcpy (plain_buffer, received_data, received_size);
      
      if (info)
        {
          info->was_encrypted = true; /* We detected GPG format but couldn't process it */
          info->was_signed = false;
          info->signature_valid = false;
          info->data_size = received_size;
        }
      
      gpgme_data_release (input);
      gpgme_data_release (output);
      gpgme_release (ctx);
      return received_size;
    }
  
  /* Read processed data */
  gpgme_data_seek (output, 0, SEEK_SET);
  plain_size = gpgme_data_read (output, plain_buffer, buffer_size);
  
  if (plain_size < 0)
    {
      set_error (stream, "Failed to read processed data");
    }
  else if (info)
    {
      info->data_size = plain_size;
    }
  
  gpgme_data_release (input);
  gpgme_data_release (output);
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
  const char *final_address = address ? address : "239.0.0.1";
  strncpy (stream->multicast_addr, final_address, sizeof (stream->multicast_addr) - 1);
  stream->port = port > 0 ? port : 5555;
  stream->sockfd = -1;
  stream->sequence = 1;
  stream->recipient_capacity = 16;
  stream->recipient_keys = malloc (sizeof (char*) * stream->recipient_capacity);
  stream->mode = GPG_MODE_SIGN_AND_ENCRYPT;
  
  /* Detect mode based on address */
  if (is_multicast_address (final_address))
    {
      stream->is_unicast_server = false;
      stream->is_unicast_client = false;
    }
  else
    {
      stream->is_unicast_server = true;
      stream->is_unicast_client = true;
      
      /* Start cleanup thread for unicast servers */
      stream->cleanup_running = true;
      if (pthread_create (&stream->cleanup_thread, NULL, cleanup_thread_func, stream) != 0)
        {
          log_message (stream, GPG_LOG_WARN, "Failed to create cleanup thread");
          stream->cleanup_running = false;
        }
    }
  
  stream->clients = NULL;
  stream->keepalive_running = false;
  
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
  
  /* Stop cleanup thread for unicast servers */
  if (stream->cleanup_running)
    {
      stream->cleanup_running = false;
      if (stream->cleanup_thread)
        {
          pthread_join (stream->cleanup_thread, NULL);
          stream->cleanup_thread = 0;
        }
    }
  
  /* Clean up client list */
  while (stream->clients)
    {
      client_node_t *next = stream->clients->next;
      free (stream->clients);
      stream->clients = next;
    }
  
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

bool
gpg_stream_set_mode (gpg_stream_t *stream, gpg_mode_t mode)
{
  if (!stream)
    return false;
    
  stream->mode = mode;
  return true;
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

void
gpg_stream_clear_recipients (gpg_stream_t *stream)
{
  if (!stream)
    return;
    
  for (int i = 0; i < stream->recipient_count; i++)
    {
      free (stream->recipient_keys[i]);
      stream->recipient_keys[i] = NULL;
    }
  
  stream->recipient_count = 0;
  log_message (stream, GPG_LOG_INFO, "All recipients cleared");
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
  packet.packet_type = PACKET_DATA;
  packet.sequence = htonl (stream->sequence++);
  packet.timestamp = time (NULL);
  strncpy (packet.sender_keyid, stream->sender_keyid, GPG_STREAM_KEYID_SIZE);
  packet.sender_keyid[GPG_STREAM_KEYID_SIZE] = '\0';
  
  /* Process data according to mode */
  ssize_t processed_size = process_data_for_send (stream, data, size,
                                                  packet.data,
                                                  GPG_STREAM_MAX_PACKET_SIZE);
  if (processed_size < 0)
    {
      pthread_mutex_unlock (&stream->mutex);
      return false;
    }
  
  packet.data_size = processed_size;
  
  size_t packet_size = sizeof (packet) - GPG_STREAM_MAX_PACKET_SIZE + processed_size;
  ssize_t total_sent = 0;
  
  /* Send packet based on mode */
  if (stream->is_unicast_server)
    {
      /* Unicast mode: send to all registered clients */
      int client_count = 0;
      for (client_node_t *client = stream->clients; client; client = client->next)
        {
          ssize_t sent = sendto (stream->sockfd, &packet, packet_size, 0,
                                 (struct sockaddr*)&client->addr, sizeof (client->addr));
          if (sent > 0)
            {
              total_sent = sent;
              client_count++;
            }
        }
      
      /* Remove stale clients periodically */
      if (stream->sequence % 100 == 0)  /* Every 100 packets */
        remove_stale_clients (stream, 60);
        
      if (client_count == 0)
        {
          log_message (stream, GPG_LOG_WARN, "No clients registered for unicast stream");
          total_sent = packet_size;  /* Consider successful for sender */
        }
    }
  else
    {
      /* Multicast mode: send to multicast group */
      total_sent = sendto (stream->sockfd, &packet, packet_size, 0,
                          (struct sockaddr*)&stream->addr, sizeof (stream->addr));
    }
  
  if (total_sent < 0)
    {
      set_error (stream, "Failed to send packet: %s", strerror (errno));
      pthread_mutex_unlock (&stream->mutex);
      return false;
    }
  
  stream->stats.packets_sent++;
  stream->stats.bytes_sent += size;
  
  log_message (stream, GPG_LOG_DEBUG, "Sent packet %u (%zu bytes processed to %zd)",
               ntohl (packet.sequence), size, processed_size);
  
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
  
  /* Handle multicast vs unicast mode */
  if (!stream->is_unicast_client)
    {
      /* Multicast mode: join multicast group */
      struct ip_mreq mreq;
      mreq.imr_multiaddr.s_addr = stream->addr.sin_addr.s_addr;
      mreq.imr_interface.s_addr = INADDR_ANY;
      
      if (setsockopt (stream->sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof (mreq)) < 0)
        {
          set_error (stream, "Failed to join multicast group: %s", strerror (errno));
          return false;
        }
    }
  else
    {
      /* Unicast mode: send initial subscribe packet and start keepalive */
      gpg_wire_packet_t subscribe = {0};
      subscribe.packet_type = PACKET_SUBSCRIBE;
      sendto (stream->sockfd, &subscribe, sizeof (subscribe.packet_type) + sizeof (subscribe.sequence), 0,
              (struct sockaddr*)&stream->addr, sizeof (stream->addr));
      
      /* Start keepalive thread */
      stream->keepalive_running = true;
      if (pthread_create (&stream->keepalive_thread, NULL, keepalive_thread_func, stream) != 0)
        {
          set_error (stream, "Failed to create keepalive thread");
          stream->keepalive_running = false;
          return false;
        }
    }
  
  stream->receiving = true;
  log_message (stream, GPG_LOG_INFO, "Started receiving on %s:%d (%s mode)", 
               stream->multicast_addr, stream->port,
               stream->is_unicast_client ? "unicast" : "multicast");
  
  return true;
}

void
gpg_stream_stop_receive (gpg_stream_t *stream)
{
  if (!stream)
    return;
  
  stream->receiving = false;
  
  /* Stop keepalive thread for unicast clients */
  if (stream->is_unicast_client && stream->keepalive_running)
    {
      /* Send unsubscribe packet */
      gpg_wire_packet_t unsubscribe = {0};
      unsubscribe.packet_type = PACKET_UNSUBSCRIBE;
      sendto (stream->sockfd, &unsubscribe, sizeof (unsubscribe.packet_type) + sizeof (unsubscribe.sequence), 0,
              (struct sockaddr*)&stream->addr, sizeof (stream->addr));
      
      /* Stop keepalive thread */
      stream->keepalive_running = false;
      if (stream->keepalive_thread)
        {
          pthread_join (stream->keepalive_thread, NULL);
          stream->keepalive_thread = 0;
        }
    }
  
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
  
  /* Loop until we get a data packet (filter control packets) */
  while (1)
    {
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
      
      /* Handle unicast server mode - register clients from control packets */
      if (stream->is_unicast_server && packet.packet_type != PACKET_DATA)
        {
          pthread_mutex_lock (&stream->mutex);
          update_client_list (stream, &sender_addr);
          pthread_mutex_unlock (&stream->mutex);
          continue;  /* Skip control packets, get next packet */
        }
      
      /* Skip non-data packets for unicast clients (keepalives, etc) */
      if (packet.packet_type != PACKET_DATA)
        {
          continue;  /* Transparently filter, get next packet */
        }
      
      /* Process data packet */
      if (info)
        {
          memset (info, 0, sizeof (*info));
          info->sequence = ntohl (packet.sequence);
          info->timestamp = packet.timestamp;
        }
      
      ssize_t plain_size = process_received_data (stream, packet.data,
                                                packet.data_size, buffer, size, info);
      
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