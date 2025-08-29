/* example-receiver.c - GNU-standard simple receiver example 
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
 *
 * Usage examples:
 *   ./example-receiver                        # Receive with auto-detected keys
 *   ./example-receiver --address 239.0.0.2    # Custom multicast address
 *   ./example-receiver --key mykey@email.com  # Specific decryption key
 *   ./example-receiver --verbose              # Show detailed packet info
 *   ./example-receiver --file output.txt      # Write to file instead of stdout
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <libgpg-stream.h>

static volatile bool running = true;
static bool verbose = false;

static void
signal_handler (int sig)
{
  (void)sig; /* Suppress unused parameter warning */
  printf ("\nShutting down...\n");
  running = false;
}

static void
log_callback (int level, const char *message)
{
  const char *level_names[] = {"ERROR", "WARN", "INFO", "DEBUG"};
  printf ("[%s] %s\n", level_names[level], message);
}

static void
show_usage (const char *program)
{
  printf ("Usage: %s [OPTIONS]\n\n", program);
  printf ("GNU-standard GPG multicast receiver - Unix philosophy in action\n\n");
  printf ("Options:\n");
  printf ("  --address ADDR       Multicast address (default: 239.0.0.1)\n");
  printf ("  --port PORT          Multicast port (default: 5555)\n");
  printf ("  --key KEY            Decryption key ID (auto-detected if not specified)\n");
  printf ("  --file PATH          Write output to file instead of stdout\n");
  printf ("  --timeout SECS       Receive timeout in seconds (default: no timeout)\n");
  printf ("  --verbose            Show detailed packet information\n");
  printf ("  --debug              Enable debug logging\n");
  printf ("  --stats              Show periodic statistics\n");
  printf ("  --help               Show this help\n");
  printf ("\nExamples:\n");
  printf ("  %s                            # Basic receiver with auto-keys\n", program);
  printf ("  %s --verbose --stats          # Detailed output with statistics\n", program);
  printf ("  %s --file log.txt             # Save to file\n", program);
  printf ("  %s --address 239.0.0.2        # Custom multicast group\n", program);
}

static void
print_packet_info (const gpg_packet_info_t *info)
{
  if (!verbose || !info)
    return;
    
  printf ("--- Packet #%u ---\n", info->sequence);
  printf ("Timestamp: %.0f\n", info->timestamp);
  printf ("Data size: %zu bytes\n", info->data_size);
  
  if (info->was_signed)
    {
      printf ("Signature: %s\n", info->signature_valid ? "VALID" : "INVALID");
      if (info->sender_fingerprint)
        printf ("Sender fingerprint: %s\n", info->sender_fingerprint);
      if (info->sender_email)
        printf ("Sender email: %s\n", info->sender_email);
    }
  else
    {
      printf ("Signature: NONE (unsigned packet)\n");
    }
  
  printf ("--- Content ---\n");
}

int
main (int argc, char *argv[])
{
  const char *address = NULL;
  int port = 0;
  const char *key_id = NULL;
  const char *output_file = NULL;
  int timeout_ms = 0;
  bool show_stats = false;
  int log_level = GPG_LOG_WARN;
  
  static struct option long_options[] = {
    {"address", required_argument, 0, 'a'},
    {"port", required_argument, 0, 'p'},
    {"key", required_argument, 0, 'k'},
    {"file", required_argument, 0, 'f'},
    {"timeout", required_argument, 0, 't'},
    {"verbose", no_argument, 0, 'v'},
    {"debug", no_argument, 0, 'd'},
    {"stats", no_argument, 0, 's'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
  };
  
  int opt;
  while ((opt = getopt_long (argc, argv, "a:p:k:f:t:vdsh", long_options, NULL)) != -1)
    {
      switch (opt)
        {
        case 'a':
          address = optarg;
          break;
        case 'p':
          port = atoi (optarg);
          break;
        case 'k':
          key_id = optarg;
          break;
        case 'f':
          output_file = optarg;
          break;
        case 't':
          timeout_ms = atoi (optarg) * 1000;
          break;
        case 'v':
          verbose = true;
          log_level = GPG_LOG_INFO;
          break;
        case 'd':
          log_level = GPG_LOG_DEBUG;
          break;
        case 's':
          show_stats = true;
          break;
        case 'h':
          show_usage (argv[0]);
          return 0;
        default:
          show_usage (argv[0]);
          return 1;
        }
    }
  
  /* Set up signal handling */
  signal (SIGINT, signal_handler);
  signal (SIGTERM, signal_handler);
  
  /* Create stream context */
  gpg_stream_t *stream;
  if (address || port > 0)
    stream = gpg_stream_new_address (address ? address : "239.0.0.1", port ? port : 5555);
  else
    stream = gpg_stream_new ();
    
  if (!stream)
    {
      fprintf (stderr, "Failed to create stream context\n");
      return 1;
    }
    
  /* Set up logging */
  gpg_stream_set_logging (stream, log_callback, log_level);
  
  /* Set up keys */
  if (key_id)
    {
      if (!gpg_stream_add_recipient (stream, key_id))
        {
          fprintf (stderr, "Failed to add decryption key '%s': %s\n", 
                   key_id, gpg_stream_error (stream));
          gpg_stream_free (stream);
          return 1;
        }
    }
  else
    {
      if (!gpg_stream_auto_keys (stream))
        {
          fprintf (stderr, "Failed to auto-detect keys: %s\n", gpg_stream_error (stream));
          gpg_stream_free (stream);
          return 1;
        }
    }
  
  /* Start receiving */
  if (!gpg_stream_start_receive (stream))
    {
      fprintf (stderr, "Failed to start receiving: %s\n", gpg_stream_error (stream));
      gpg_stream_free (stream);
      return 1;
    }
  
  printf ("=== GNU GPG Stream Receiver ===\n");
  printf ("Listening for encrypted streams...\n");
  if (verbose)
    printf ("Press Ctrl+C to stop.\n\n");
  
  /* Open output file if specified */
  FILE *output = stdout;
  if (output_file)
    {
      output = fopen (output_file, "a");
      if (!output)
        {
          fprintf (stderr, "Failed to open output file: %s\n", output_file);
          gpg_stream_stop_receive (stream);
          gpg_stream_free (stream);
          return 1;
        }
      printf ("Writing output to: %s\n", output_file);
    }
  
  /* Main receive loop */
  char buffer[8192];
  uint64_t packet_count = 0;
  uint64_t last_stats = 0;
  
  while (running)
    {
      gpg_packet_info_t info = {0};
      
      ssize_t received = gpg_stream_receive (stream, buffer, sizeof (buffer) - 1, 
                                             &info, timeout_ms);
      
      if (received == 0)
        {
          if (timeout_ms > 0)
            {
              printf ("Receive timeout after %d seconds\n", timeout_ms / 1000);
              break;
            }
          continue; /* No timeout set, keep trying */
        }
      
      if (received < 0)
        {
          fprintf (stderr, "Receive error: %s\n", gpg_stream_error (stream));
          continue;
        }
      
      /* Process received data */
      buffer[received] = '\0';
      packet_count++;
      
      print_packet_info (&info);
      
      /* Write data */
      fprintf (output, "%s", buffer);
      if (output != stdout)
        fflush (output);
      
      if (!verbose)
        printf ("%s", buffer);
      
      /* Clean up packet info */
      gpg_packet_info_free (&info);
      
      /* Show periodic statistics */
      if (show_stats && (packet_count % 10 == 0 || packet_count != last_stats))
        {
          gpg_stream_stats_t stats;
          if (gpg_stream_get_stats (stream, &stats))
            {
              printf ("\n--- Statistics ---\n");
              printf ("Packets received: %lu\n", stats.packets_received);
              printf ("Bytes received: %lu\n", stats.bytes_received);
              printf ("Decrypt failures: %lu\n", stats.decrypt_failures);
              printf ("Signature failures: %lu\n", stats.signature_failures);
              printf ("--- End Stats ---\n\n");
            }
          last_stats = packet_count;
        }
    }
  
  /* Clean up */
  if (output != stdout)
    fclose (output);
    
  gpg_stream_stop_receive (stream);
  
  /* Final statistics */
  if (show_stats || verbose)
    {
      gpg_stream_stats_t stats;
      if (gpg_stream_get_stats (stream, &stats))
        {
          printf ("\n=== Final Statistics ===\n");
          printf ("Packets received: %lu\n", stats.packets_received);
          printf ("Bytes received: %lu\n", stats.bytes_received);
          printf ("Decrypt failures: %lu\n", stats.decrypt_failures);
          printf ("Signature failures: %lu\n", stats.signature_failures);
          printf ("Success rate: %.1f%%\n", 
                  stats.packets_received > 0 ? 
                  100.0 * (stats.packets_received - stats.decrypt_failures) / stats.packets_received : 0.0);
        }
    }
  
  gpg_stream_free (stream);
  
  printf ("Receiver stopped.\n");
  return 0;
}