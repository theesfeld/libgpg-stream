# libgpg-stream

[![License: GPL v3+](https://img.shields.io/badge/License-GPL%20v3+-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Version](https://img.shields.io/badge/version-dynamic-green.svg)](https://github.com/theesfeld/libgpg-stream/releases)
[![C Standard](https://img.shields.io/badge/C-99-blue.svg)](https://en.wikipedia.org/wiki/C99)
[![Build System](https://img.shields.io/badge/build-GNU%20Autotools-orange.svg)](https://www.gnu.org/software/automake/)

A flexible, GNU-standard GPG streaming library for secure multicast communication with multiple encryption modes, multi-channel support, and universal data streaming.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Dependencies](#dependencies)
- [Installation](#installation)
  - [From Source](#from-source)
  - [Configuration Options](#configuration-options)
- [Quick Start](#quick-start)
  - [Basic Sender](#basic-sender)
  - [Basic Receiver](#basic-receiver)
- [API Reference](#api-reference)
  - [Initialization](#initialization)
  - [Key Management](#key-management)
  - [Sending Data](#sending-data)
  - [Receiving Data](#receiving-data)
  - [Error Handling](#error-handling)
  - [Memory Management](#memory-management)
- [Data Structures](#data-structures)
- [Examples](#examples)
- [Thread Safety](#thread-safety)
- [License](#license)
- [Contributing](#contributing)
- [Support](#support)

## Overview

The **libgpg-stream** library provides flexible, secure multicast communication using GPG (GNU Privacy Guard). It follows GNU coding standards and implements the Unix philosophy of doing one thing well.

The library supports multiple GPG modes (plain text, sign-only, encrypt-only, or sign+encrypt), automatic key management with mid-stream key changes, multi-channel communication, multi-recipient encryption, and **internet streaming via unicast UDP**. It automatically detects multicast addresses for local networks or unicast addresses for internet streaming, handling all GPG operations while providing a simple, functional API that **always streams data regardless of encryption success** - embracing the Unix philosophy of robustness.

## Features

### Core Capabilities
- **Flexible GPG Modes**: Plain text, sign-only, encrypt-only, or sign+encrypt
- **Universal Data Streaming**: Always streams data - never drops packets regardless of decryption success
- **Multi-Channel Communication**: Different addresses for separate channels
- **Multi-Recipient Encryption**: Encrypt to multiple keys independently  
- **Mid-Stream Key Changes**: Change encryption/signing keys without missing data
- **Internet-Ready Streaming**: Automatic mode detection for local networks and internet

### Networking & Streaming
- **Dual Mode Support**: Automatic multicast (local) and unicast (internet) detection
- **Client Registration**: Automatic registration system for internet streaming
- **Transparent Keepalive**: Maintains connections without user intervention
- **Address Detection**: 224-239.x.x.x = multicast, others = unicast streaming
- **Global Accessibility**: Stream across NAT, firewalls, and the internet

### Security & Cryptography  
- **GPG Integration**: Full GPG encryption, decryption, and signature verification
- **Auto-Detection**: Receivers automatically detect plain/signed/encrypted data
- **Key Management**: Automatic key detection with manual override options
- **Signature Verification**: Comprehensive signature validation with metadata

### Development & Deployment
- **GNU Compliant**: Follows GNU coding standards and philosophy
- **Thread Safe**: Safe for multi-threaded applications when using separate contexts
- **Zero Dependencies**: Only requires standard libraries and GPGME
- **Multiple Input Methods**: Send strings, files, stdin, pipes, or command output
- **Comprehensive API**: Simple functional interface with detailed packet metadata

## Dependencies

- **libgpgme** (>= 1.0.0) - GPG Made Easy library
- **pthread** - POSIX threads for internal synchronization
- **Standard C Library** - Math library for timing functions

### Installation of Dependencies

#### Debian/Ubuntu
```bash
sudo apt-get install libgpgme-dev
```

#### Red Hat/Fedora/CentOS
```bash
sudo yum install gpgme-devel
# or on newer systems:
sudo dnf install gpgme-devel
```

#### macOS
```bash
brew install gpgme
```

## Installation

### ARCH LINUX
1. **Install from AUR**
   ```bash
   yay -s libgpg-stream
   ```

### From Source

1. **Clone the repository**:
   ```bash
   git clone https://github.com/theesfeld/libgpg-stream.git
   cd libgpg-stream
   ```

2. **Generate build system**:
   ```bash
   ./autogen.sh
   ```

3. **Configure**:
   ```bash
   ./configure
   ```

4. **Build**:
   ```bash
   make
   ```

5. **Install** (optional):
   ```bash
   sudo make install
   ```

### Configuration Options

- `--enable-debug` - Enable debug build with extra logging
- `--enable-examples` - Build example programs
- `--enable-docs` - Generate documentation
- `--prefix=/path` - Set installation prefix (default: `/usr/local`)

Example with options:
```bash
./configure --enable-examples --enable-debug --prefix=/usr/local
```

## Quick Start

### Plain Text Sender
```c
#include <libgpg-stream.h>

int main() {
    gpg_stream_t *stream = gpg_stream_new();
    if (!stream) return 1;

    // Set plain text mode - no encryption or signing
    gpg_stream_set_mode(stream, GPG_MODE_PLAIN);
    bool success = gpg_stream_send_string(stream, "Hello, World!");

    gpg_stream_free(stream);
    return success ? 0 : 1;
}
```

### Multi-Recipient Encrypted Sender
```c
#include <libgpg-stream.h>

int main() {
    gpg_stream_t *stream = gpg_stream_new();
    if (!stream) return 1;

    // Set up sender key and multiple recipients
    gpg_stream_set_sender(stream, "sender@example.com");
    gpg_stream_add_recipient(stream, "alice@example.com");
    gpg_stream_add_recipient(stream, "bob@example.com");
    gpg_stream_add_recipient(stream, "carol@example.com");
    
    // Any of the three recipients can decrypt this message
    gpg_stream_set_mode(stream, GPG_MODE_SIGN_AND_ENCRYPT);
    bool success = gpg_stream_send_string(stream, "Secret message!");

    gpg_stream_free(stream);
    return success ? 0 : 1;
}
```

### Universal Receiver (Handles All Modes)
```c
#include <libgpg-stream.h>

int main() {
    gpg_stream_t *stream = gpg_stream_new();
    if (!stream) return 1;

    gpg_stream_auto_keys(stream);
    if (!gpg_stream_start_receive(stream)) {
        gpg_stream_free(stream);
        return 1;
    }

    char buffer[4096];
    gpg_packet_info_t info = {0};

    // Receive always succeeds - handles all modes automatically  
    ssize_t received = gpg_stream_receive(stream, buffer,
                                          sizeof(buffer)-1, &info, 5000);

    if (received > 0) {
        buffer[received] = '\0';
        printf("Received: %s\n", buffer);
        printf("Encrypted: %s\n", info.was_encrypted ? "Yes" : "No");
        printf("Signed: %s\n", info.was_signed ? "Yes" : "No");
        if (info.was_signed) {
            printf("Signature: %s\n", info.signature_valid ? "Valid" : "Invalid");
        }
        gpg_packet_info_free(&info);
    }

    gpg_stream_stop_receive(stream);
    gpg_stream_free(stream);
    return 0;
}
```

**Compile and link**:
```bash
gcc -o sender sender.c -lgpg-stream -lgpgme -lpthread -lm
gcc -o receiver receiver.c -lgpg-stream -lgpgme -lpthread -lm
```

## API Reference

### Initialization

#### `gpg_stream_t *gpg_stream_new(void)`
Creates a new stream context with default multicast address (239.0.0.1:5555).
- **Returns**: Pointer to stream context, or `NULL` on failure

#### `gpg_stream_t *gpg_stream_new_address(const char *address, int port)`
Creates a new stream context with specified multicast address and port.
- **Parameters**:
  - `address` - Multicast address string
  - `port` - Port number
- **Returns**: Pointer to stream context, or `NULL` on failure

#### `void gpg_stream_free(gpg_stream_t *stream)`
Destroys a stream context and frees all associated resources.
- **Parameters**: `stream` - Stream context to free

### Key Management

#### `bool gpg_stream_auto_keys(gpg_stream_t *stream)`
Automatically detects and configures the first available GPG key pair.
- **Returns**: `true` on success, `false` on failure
- **Note**: Recommended approach for most applications

#### `bool gpg_stream_set_sender(gpg_stream_t *stream, const char *key_id)`
Sets a specific GPG key for signing outgoing messages.
- **Parameters**: `key_id` - Key ID, fingerprint, or email address
- **Returns**: `true` on success, `false` on failure

#### `bool gpg_stream_add_recipient(gpg_stream_t *stream, const char *key_id)`
Adds a recipient key for encrypting outgoing messages.
- **Parameters**: `key_id` - Key ID, fingerprint, or email address
- **Returns**: `true` on success, `false` on failure
- **Note**: Call multiple times to add multiple recipients. Any recipient with any of the configured keys can decrypt messages independently.

#### `void gpg_stream_clear_recipients(gpg_stream_t *stream)`
Removes all recipient keys from the stream context.
- **Parameters**: `stream` - Stream context
- **Note**: Useful for changing encryption targets mid-stream

#### `bool gpg_stream_set_mode(gpg_stream_t *stream, gpg_mode_t mode)`
Sets the GPG operation mode for sending data.
- **Parameters**: 
  - `stream` - Stream context
  - `mode` - GPG mode: `GPG_MODE_PLAIN`, `GPG_MODE_SIGN_ONLY`, `GPG_MODE_ENCRYPT_ONLY`, or `GPG_MODE_SIGN_AND_ENCRYPT` (default)
- **Returns**: `true` on success, `false` on failure
- **Note**: Changes apply to all subsequent send operations

### Sending Data

#### `bool gpg_stream_send(gpg_stream_t *stream, const void *data, size_t size)`
Sends raw data buffer over the stream.
- **Parameters**:
  - `data` - Data buffer to send
  - `size` - Size of data in bytes
- **Returns**: `true` on success, `false` on failure
- **Note**: Data is processed according to the current GPG mode (plain, sign-only, encrypt-only, or sign+encrypt)

#### `bool gpg_stream_send_string(gpg_stream_t *stream, const char *str)`
Sends a null-terminated string over the stream.
- **Parameters**: `str` - String to send
- **Returns**: `true` on success, `false` on failure

#### `bool gpg_stream_send_file(gpg_stream_t *stream, const char *path)`
Reads and sends the contents of a file over the stream.
- **Parameters**: `path` - Path to file to send
- **Returns**: `true` on success, `false` on failure

#### `bool gpg_stream_send_stdin(gpg_stream_t *stream)`
Reads from standard input and sends the data over the stream.
- **Returns**: `true` on success, `false` on failure

### Receiving Data

#### `bool gpg_stream_start_receive(gpg_stream_t *stream)`
Begins listening for messages on the multicast stream.
- **Returns**: `true` on success, `false` on failure
- **Note**: Must be called before any receive operations

#### `ssize_t gpg_stream_receive(gpg_stream_t *stream, void *buffer, size_t size, gpg_packet_info_t *info, int timeout_ms)`
Receives a single message from the stream, automatically handling all GPG modes.
- **Parameters**:
  - `buffer` - Buffer to store received data  
  - `size` - Size of buffer
  - `info` - Structure to receive packet metadata
  - `timeout_ms` - Timeout in milliseconds (0 = no timeout)
- **Returns**: Number of bytes received, 0 on timeout, or -1 only on network errors
- **Note**: **Always streams data** - plain text, successfully decrypted data, or raw encrypted data (if decryption fails) is always returned to the caller

#### `void gpg_stream_stop_receive(gpg_stream_t *stream)`
Stops listening for messages and closes the receive socket.
- **Parameters**: `stream` - Stream context

### Error Handling

#### `const char *gpg_stream_error(gpg_stream_t *stream)`
Returns a string describing the last error that occurred.
- **Parameters**: `stream` - Stream context
- **Returns**: Error string, or `NULL` if no error
- **Note**: String is valid until next library function call on same context

### Memory Management

#### `void gpg_packet_info_free(gpg_packet_info_t *info)`
Frees memory allocated for packet metadata.
- **Parameters**: `info` - Packet info structure to free
- **Note**: Must be called after each successful receive operation

## Data Structures

### `gpg_packet_info_t`
Contains metadata about received packets:

- **`sequence`** - Packet sequence number
- **`timestamp`** - Unix timestamp when packet was created
- **`sender_fingerprint`** - GPG fingerprint of sender (must be freed)
- **`sender_email`** - Email address of sender (must be freed)
- **`signature_valid`** - `true` if signature is valid
- **`was_signed`** - `true` if packet was signed
- **`was_encrypted`** - `true` if packet was encrypted  
- **`data_size`** - Size of received data

### GPG Modes (`gpg_mode_t`)
Available GPG operation modes:

- **`GPG_MODE_PLAIN`** - No encryption or signing (plain text)
- **`GPG_MODE_SIGN_ONLY`** - Sign but don't encrypt
- **`GPG_MODE_ENCRYPT_ONLY`** - Encrypt but don't sign
- **`GPG_MODE_SIGN_AND_ENCRYPT`** - Both sign and encrypt (default)

## Examples

See the `examples/` directory for complete working examples:

- **`example-sender.c`** - Demonstrates various sending methods with all GPG modes
- **`example-receiver.c`** - Shows how to receive and process messages with metadata

Build examples:
```bash
./configure --enable-examples
make
```

### Advanced Examples

#### Mid-Stream Key Change
```c
gpg_stream_t *stream = gpg_stream_new();
gpg_stream_auto_keys(stream);

// Send with initial keys
gpg_stream_send_string(stream, "Message 1");

// Change keys mid-stream - no data loss
gpg_stream_clear_recipients(stream);
gpg_stream_add_recipient(stream, "newuser@example.com");
gpg_stream_set_sender(stream, "newsender@example.com");

// Continue sending with new keys  
gpg_stream_send_string(stream, "Message 2");
```

#### Internet Streaming (Unicast)
```c
// Server: Bind to all interfaces for internet access
gpg_stream_t *server = gpg_stream_new_address("0.0.0.0", 5555);
gpg_stream_auto_keys(server);
gpg_stream_send_string(server, "Hello Internet!");

// Client: Connect from anywhere on the internet
gpg_stream_t *client = gpg_stream_new_address("myserver.com", 5555);
gpg_stream_auto_keys(client);
gpg_stream_start_receive(client);

char buffer[4096];
gpg_packet_info_t info = {0};
ssize_t received = gpg_stream_receive(client, buffer, sizeof(buffer)-1, &info, 5000);

if (received > 0) {
    buffer[received] = '\0';
    printf("Received from internet: %s\n", buffer);
    gpg_packet_info_free(&info);
}
```

#### Multi-Channel Communication
```c
// Create separate channels - multicast and unicast
gpg_stream_t *local_channel = gpg_stream_new_address("239.0.0.1", 5555);   // Local network
gpg_stream_t *inet_channel = gpg_stream_new_address("myserver.com", 5556); // Internet

// Configure different keys/modes per channel
gpg_stream_set_mode(local_channel, GPG_MODE_PLAIN);
gpg_stream_set_mode(inet_channel, GPG_MODE_SIGN_AND_ENCRYPT);

// Send different data on different channels
gpg_stream_send_string(local_channel, "Local network announcement");  
gpg_stream_send_string(inet_channel, "Internet encrypted data");
```

#### Universal Receiver with Metadata
```c
ssize_t received = gpg_stream_receive(stream, buffer, sizeof(buffer)-1, &info, 5000);

if (received > 0) {
    buffer[received] = '\0';
    
    // Stream data regardless of encryption success
    printf("Data: %s\n", buffer);
    
    // Check what security was applied
    if (info.was_encrypted && info.was_signed) {
        printf("Security: Encrypted + Signed (%s)\n", 
               info.signature_valid ? "Valid" : "Invalid");
    } else if (info.was_encrypted) {
        printf("Security: Encrypted only\n");
    } else if (info.was_signed) {
        printf("Security: Signed only (%s)\n", 
               info.signature_valid ? "Valid" : "Invalid");
    } else {
        printf("Security: Plain text\n");
    }
    
    gpg_packet_info_free(&info);
}
```

## Thread Safety

The library is thread-safe when different threads use different stream contexts. A single stream context should not be used concurrently by multiple threads without external synchronization.

## License

Copyright (C) 2025 William Theesfeld <william@theesfeld.net>

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Follow GNU coding standards
4. Add tests for new functionality
5. Ensure all tests pass
6. Commit your changes (`git commit -am 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## Support

- **Email**: william@theesfeld.net
- **GitHub Issues**: https://github.com/theesfeld/libgpg-stream/issues
- **Documentation**: https://github.com/theesfeld/libgpg-stream

For bug reports, please include:
- Operating system and version
- Compiler version
- GPGME version
- Steps to reproduce the issue
- Expected vs actual behavior