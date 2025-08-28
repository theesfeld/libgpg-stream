/* libgpg-stream.h - Simplified GNU-Standard GPG Streaming API
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

#ifndef LIBGPG_STREAM_H
#define LIBGPG_STREAM_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================
 * CORE TYPES - Following GNU coding standards
 * ======================================================================== */

typedef struct gpg_stream_t gpg_stream_t;

/* Packet metadata exposed to user */
typedef struct {
  uint32_t sequence;           /* Packet sequence number */
  double timestamp;            /* Unix timestamp */
  char *sender_fingerprint;    /* GPG fingerprint (malloc'd, user must free) */
  char *sender_email;          /* Email address (malloc'd, user must free) */
  bool signature_valid;        /* True if signature is valid */
  bool was_signed;             /* True if packet was signed at all */
  size_t data_size;           /* Size of decrypted data */
} gpg_packet_info_t;

/* Stream source types - Unix philosophy: everything is a file */
typedef enum {
  GPG_SOURCE_STDIN,           /* Read from stdin */
  GPG_SOURCE_FILE,            /* Read from file path */
  GPG_SOURCE_PIPE,            /* Read from named pipe */
  GPG_SOURCE_FD,              /* Read from file descriptor */
  GPG_SOURCE_COMMAND,         /* Read from command output (popen) */
  GPG_SOURCE_FUNCTION         /* Read from user function */
} gpg_source_type_t;

/* User-provided data function */
typedef ssize_t (*gpg_data_func_t)(void *context, char *buffer, size_t size);

/* Logging callback */
typedef void (*gpg_log_func_t)(int level, const char *message);

/* Log levels */
#define GPG_LOG_ERROR   0
#define GPG_LOG_WARN    1  
#define GPG_LOG_INFO    2
#define GPG_LOG_DEBUG   3

/* ========================================================================
 * INITIALIZATION - Simple, automatic key detection
 * ======================================================================== */

/* Create stream context - auto-detects GPG keys */
gpg_stream_t *gpg_stream_new (void);

/* Create with specific multicast address/port */
gpg_stream_t *gpg_stream_new_address (const char *address, int port);

/* Destroy stream context */
void gpg_stream_free (gpg_stream_t *stream);

/* Set logging callback and level */
void gpg_stream_set_logging (gpg_stream_t *stream, gpg_log_func_t callback, int level);

/* ========================================================================
 * KEY MANAGEMENT - Automatic with overrides
 * ======================================================================== */

/* Auto-detect and use first available key pair */
bool gpg_stream_auto_keys (gpg_stream_t *stream);

/* Set specific sender key (for signing) */
bool gpg_stream_set_sender (gpg_stream_t *stream, const char *key_id);

/* Add recipient key (for encryption) */
bool gpg_stream_add_recipient (gpg_stream_t *stream, const char *key_id);

/* List available keys */
int gpg_stream_list_keys (gpg_stream_t *stream, char ***key_list);

/* ========================================================================
 * SENDING - Universal input, automatic formatting
 * ======================================================================== */

/* Send single data buffer */
bool gpg_stream_send (gpg_stream_t *stream, const void *data, size_t size);

/* Send null-terminated string */
bool gpg_stream_send_string (gpg_stream_t *stream, const char *str);

/* Send from file descriptor */
bool gpg_stream_send_fd (gpg_stream_t *stream, int fd);

/* Send from file path */
bool gpg_stream_send_file (gpg_stream_t *stream, const char *path);

/* Send from stdin */
bool gpg_stream_send_stdin (gpg_stream_t *stream);

/* Send from pipe */
bool gpg_stream_send_pipe (gpg_stream_t *stream, const char *pipe_path);

/* Send from command output */
bool gpg_stream_send_command (gpg_stream_t *stream, const char *command);

/* Send from user function */
bool gpg_stream_send_function (gpg_stream_t *stream, gpg_data_func_t func, void *context);

/* Start continuous streaming from source */
bool gpg_stream_start_source (gpg_stream_t *stream, gpg_source_type_t type, 
                              const void *source, double interval);

/* Stop continuous streaming */
void gpg_stream_stop_source (gpg_stream_t *stream);

/* ========================================================================
 * RECEIVING - Automatic session management, full metadata
 * ======================================================================== */

/* Start receiving (auto-joins any active sessions) */
bool gpg_stream_start_receive (gpg_stream_t *stream);

/* Stop receiving */
void gpg_stream_stop_receive (gpg_stream_t *stream);

/* Receive next packet with full metadata */
ssize_t gpg_stream_receive (gpg_stream_t *stream, void *buffer, size_t size, 
                           gpg_packet_info_t *info, int timeout_ms);

/* Receive as null-terminated string */
char *gpg_stream_receive_string (gpg_stream_t *stream, gpg_packet_info_t *info, int timeout_ms);

/* Write received data to file descriptor */
bool gpg_stream_receive_to_fd (gpg_stream_t *stream, int fd, gpg_packet_info_t *info, int timeout_ms);

/* Write received data to file */
bool gpg_stream_receive_to_file (gpg_stream_t *stream, const char *path, gpg_packet_info_t *info, int timeout_ms);

/* Continuous receive with callback */
typedef void (*gpg_receive_callback_t)(const void *data, size_t size, const gpg_packet_info_t *info, void *context);
bool gpg_stream_receive_continuous (gpg_stream_t *stream, gpg_receive_callback_t callback, void *context);

/* ========================================================================
 * UTILITIES - GNU-standard error handling and debugging
 * ======================================================================== */

/* Get last error message */
const char *gpg_stream_error (gpg_stream_t *stream);

/* Clear last error */
void gpg_stream_clear_error (gpg_stream_t *stream);

/* Get statistics */
typedef struct {
  uint64_t packets_sent;
  uint64_t packets_received;
  uint64_t bytes_sent;
  uint64_t bytes_received;
  uint64_t decrypt_failures;
  uint64_t signature_failures;
} gpg_stream_stats_t;

bool gpg_stream_get_stats (gpg_stream_t *stream, gpg_stream_stats_t *stats);

/* Reset statistics */
void gpg_stream_reset_stats (gpg_stream_t *stream);

/* Free packet info memory (call after each receive) */
void gpg_packet_info_free (gpg_packet_info_t *info);

#ifdef __cplusplus
}
#endif

#endif /* LIBGPG_STREAM_H */