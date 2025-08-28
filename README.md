# libgpg-stream

[![License: GPL v3+](https://img.shields.io/badge/License-GPL%20v3+-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/theesfeld/libgpg-stream/releases)
[![C Standard](https://img.shields.io/badge/C-99-blue.svg)](https://en.wikipedia.org/wiki/C99)
[![Build System](https://img.shields.io/badge/build-GNU%20Autotools-orange.svg)](https://www.gnu.org/software/automake/)

GNU-standard GPG streaming library for secure multicast communication.

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

The **libgpg-stream** library provides secure, encrypted multicast communication using GPG (GNU Privacy Guard). It follows GNU coding standards and implements the Unix philosophy of doing one thing well.

The library automatically handles GPG key management, encryption, decryption, and signature verification while providing a simple, functional API for streaming data over multicast networks.

## Features

- **Secure Communication**: End-to-end encryption using GPG
- **Multicast Support**: Efficient one-to-many communication
- **Automatic Key Management**: Simplified GPG key handling
- **Signature Verification**: Authenticate message sources
- **Multiple Input Methods**: Send strings, files, or stdin
- **GNU Compliant**: Follows GNU coding standards
- **Thread Safe**: Safe for multi-threaded applications
- **Zero Dependencies**: Only requires standard libraries and GPGME

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

### Basic Sender

```c
#include <libgpg-stream.h>

int main() {
    gpg_stream_t *stream = gpg_stream_new();
    if (!stream) return 1;

    if (!gpg_stream_auto_keys(stream)) {
        gpg_stream_free(stream);
        return 1;
    }

    bool success = gpg_stream_send_string(stream, "Hello, World!");

    gpg_stream_free(stream);
    return success ? 0 : 1;
}
```

### Basic Receiver

```c
#include <libgpg-stream.h>

int main() {
    gpg_stream_t *stream = gpg_stream_new();
    if (!stream) return 1;

    if (!gpg_stream_auto_keys(stream) ||
        !gpg_stream_start_receive(stream)) {
        gpg_stream_free(stream);
        return 1;
    }

    char buffer[4096];
    gpg_packet_info_t info = {0};

    ssize_t received = gpg_stream_receive(stream, buffer,
                                          sizeof(buffer)-1, &info, 5000);

    if (received > 0) {
        buffer[received] = '\0';
        printf("Received: %s\n", buffer);
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
- **Note**: Call multiple times to add multiple recipients

### Sending Data

#### `bool gpg_stream_send(gpg_stream_t *stream, const void *data, size_t size)`
Sends raw data buffer over the encrypted stream.
- **Parameters**:
  - `data` - Data buffer to send
  - `size` - Size of data in bytes
- **Returns**: `true` on success, `false` on failure

#### `bool gpg_stream_send_string(gpg_stream_t *stream, const char *str)`
Sends a null-terminated string over the encrypted stream.
- **Parameters**: `str` - String to send
- **Returns**: `true` on success, `false` on failure

#### `bool gpg_stream_send_file(gpg_stream_t *stream, const char *path)`
Reads and sends the contents of a file over the encrypted stream.
- **Parameters**: `path` - Path to file to send
- **Returns**: `true` on success, `false` on failure

#### `bool gpg_stream_send_stdin(gpg_stream_t *stream)`
Reads from standard input and sends the data over the encrypted stream.
- **Returns**: `true` on success, `false` on failure

### Receiving Data

#### `bool gpg_stream_start_receive(gpg_stream_t *stream)`
Begins listening for encrypted messages on the multicast stream.
- **Returns**: `true` on success, `false` on failure
- **Note**: Must be called before any receive operations

#### `ssize_t gpg_stream_receive(gpg_stream_t *stream, void *buffer, size_t size, gpg_packet_info_t *info, int timeout_ms)`
Receives and decrypts a single message from the stream.
- **Parameters**:
  - `buffer` - Buffer to store decrypted data
  - `size` - Size of buffer
  - `info` - Structure to receive packet metadata
  - `timeout_ms` - Timeout in milliseconds (0 = no timeout)
- **Returns**: Number of bytes received, 0 on timeout, or -1 on error

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
- **`data_size`** - Size of decrypted data

## Examples

See the `examples/` directory for complete working examples:

- **`example-sender.c`** - Demonstrates various sending methods
- **`example-receiver.c`** - Shows how to receive and process messages

Build examples:
```bash
./configure --enable-examples
make
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