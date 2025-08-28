/* example-sender.c - GNU-standard simple sender example
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
 *   ./example-sender "Hello World"              # Send single message
 *   echo "data" | ./example-sender --stdin      # Send from stdin  
 *   ./example-sender --file myfile.txt          # Send file contents
 *   ./example-sender --command "journalctl -f"  # Stream from journalctl
 *   ./example-sender --pipe /var/log/messages   # Stream from pipe
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <libgpg-stream.h>

static void
log_callback (int level, const char *message)
{
  const char *level_names[] = {"ERROR", "WARN", "INFO", "DEBUG"};
  printf ("[%s] %s\n", level_names[level], message);
}

static void
show_usage (const char *program)
{
  printf ("Usage: %s [OPTIONS] [MESSAGE]\n\n", program);
  printf ("GNU-standard GPG multicast sender - Unix philosophy in action\n\n");
  printf ("Input Sources (pick one):\n");
  printf ("  MESSAGE               Send single message string\n");
  printf ("  --stdin              Read from standard input\n");  
  printf ("  --file PATH          Read from file\n");
  printf ("  --pipe PATH          Read from named pipe\n");
  printf ("  --command CMD        Read from command output\n");
  printf ("  --fd FD              Read from file descriptor\n");
  printf ("\nOptions:\n");
  printf ("  --address ADDR       Multicast address (default: 239.0.0.1)\n");
  printf ("  --port PORT          Multicast port (default: 5555)\n");
  printf ("  --sender KEY         Sender key ID (auto-detected if not specified)\n");
  printf ("  --recipient KEY      Add recipient key (can be used multiple times)\n");
  printf ("  --interval SECS      Streaming interval for continuous sources\n");
  printf ("  --verbose           Enable verbose logging\n");
  printf ("  --debug             Enable debug logging\n");
  printf ("  --help              Show this help\n");
  printf ("\nExamples:\n");
  printf ("  %s \"Hello World\"                    # Send single message\n", program);
  printf ("  echo \"data\" | %s --stdin             # Send from stdin\n", program);  
  printf ("  %s --file /var/log/messages           # Send file contents\n", program);
  printf ("  %s --command \"journalctl -f\"         # Stream from journalctl\n", program);
  printf ("  %s --pipe /tmp/mypipe --interval 1    # Stream from pipe every second\n", program);
}

int
main (int argc, char *argv[])
{
  const char *address = NULL;
  int port = 0;
  const char *sender_key = NULL;
  char recipients[16][256];
  int recipient_count = 0;
  double interval = 1.0;
  int log_level = GPG_LOG_INFO;
  bool use_stdin = false;
  const char *file_path = NULL;
  const char *pipe_path = NULL;
  const char *command = NULL;
  int fd = -1;
  
  static struct option long_options[] = {
    {"address", required_argument, 0, 'a'},
    {"port", required_argument, 0, 'p'},
    {"sender", required_argument, 0, 's'},
    {"recipient", required_argument, 0, 'r'},
    {"interval", required_argument, 0, 'i'},
    {"stdin", no_argument, 0, 1001},
    {"file", required_argument, 0, 1002},
    {"pipe", required_argument, 0, 1003},
    {"command", required_argument, 0, 1004},
    {"fd", required_argument, 0, 1005},
    {"verbose", no_argument, 0, 'v'},
    {"debug", no_argument, 0, 'd'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
  };
  
  int opt;
  while ((opt = getopt_long (argc, argv, "a:p:s:r:i:vdh", long_options, NULL)) != -1)
    {
      switch (opt)
        {
        case 'a':
          address = optarg;
          break;
        case 'p':
          port = atoi (optarg);
          break;
        case 's':
          sender_key = optarg;
          break;
        case 'r':
          if (recipient_count < 16)
            strncpy (recipients[recipient_count++], optarg, 255);
          break;
        case 'i':
          interval = atof (optarg);
          break;
        case 1001:
          use_stdin = true;
          break;
        case 1002:
          file_path = optarg;
          break;
        case 1003:
          pipe_path = optarg;
          break;
        case 1004:
          command = optarg;
          break;
        case 1005:
          fd = atoi (optarg);
          break;
        case 'v':
          log_level = GPG_LOG_INFO;
          break;
        case 'd':
          log_level = GPG_LOG_DEBUG;
          break;
        case 'h':
          show_usage (argv[0]);
          return 0;
        default:
          show_usage (argv[0]);
          return 1;
        }
    }
  
  // Create stream context
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
    
  // Set up logging
  gpg_stream_set_logging (stream, log_callback, log_level);
  
  // Set up keys
  if (sender_key)
    {
      if (!gpg_stream_set_sender (stream, sender_key))
        {
          fprintf (stderr, "Failed to set sender key: %s\n", gpg_stream_error (stream));
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
    
  // Add recipients
  for (int i = 0; i < recipient_count; i++)
    {
      if (!gpg_stream_add_recipient (stream, recipients[i]))
        {
          fprintf (stderr, "Failed to add recipient '%s': %s\n", 
                   recipients[i], gpg_stream_error (stream));
          gpg_stream_free (stream);
          return 1;
        }
    }
  
  printf ("=== GNU GPG Stream Sender ===\n");
  
  bool success = false;
  
  // Handle different input sources
  if (use_stdin)
    {
      printf ("Reading from stdin...\n");
      success = gpg_stream_send_stdin (stream);
    }
  else if (file_path)
    {
      printf ("Reading from file: %s\n", file_path);
      success = gpg_stream_send_file (stream, file_path);
    }
  else if (pipe_path)
    {
      printf ("Reading from pipe: %s (interval: %.1fs)\n", pipe_path, interval);
      success = gpg_stream_start_source (stream, GPG_SOURCE_PIPE, pipe_path, interval);
      if (success)
        {
          printf ("Press Ctrl+C to stop...\n");
          pause (); // Wait for signal
          gpg_stream_stop_source (stream);
        }
    }
  else if (command)
    {
      printf ("Reading from command: %s (interval: %.1fs)\n", command, interval);
      success = gpg_stream_start_source (stream, GPG_SOURCE_COMMAND, command, interval);
      if (success)
        {
          printf ("Press Ctrl+C to stop...\n");
          pause (); // Wait for signal
          gpg_stream_stop_source (stream);
        }
    }
  else if (fd >= 0)
    {
      printf ("Reading from file descriptor: %d\n", fd);
      success = gpg_stream_send_fd (stream, fd);
    }
  else if (optind < argc)
    {
      // Send message from command line argument
      const char *message = argv[optind];
      printf ("Sending message: %s\n", message);
      success = gpg_stream_send_string (stream, message);
    }
  else
    {
      fprintf (stderr, "No input source specified. Use --help for usage.\n");
      gpg_stream_free (stream);
      return 1;
    }
  
  if (!success)
    {
      fprintf (stderr, "Send failed: %s\n", gpg_stream_error (stream));
      gpg_stream_free (stream);
      return 1;
    }
    
  printf ("Send completed successfully.\n");
  
  // Show statistics
  gpg_stream_stats_t stats;
  if (gpg_stream_get_stats (stream, &stats))
    {
      printf ("\nStatistics:\n");
      printf ("  Packets sent: %lu\n", stats.packets_sent);
      printf ("  Bytes sent: %lu\n", stats.bytes_sent);
    }
  
  gpg_stream_free (stream);
  return 0;
}