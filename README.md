# Abstract behaviour
## Protocol
This section defines the protocol used by the server and the client.

Everything defined as an interaction by this document implicitly is assumed to use _Little-Endian encoding_ unless explicitly specified otherwise.

A session begins by opening a _TCP socket_ and starting a connection with the server.
Then both the client and the server should proceed to exchanging keys using the _SSL/TLS protocol_.

Aftr establishing a secure connection, the client should proceed with sending a password to the server. The format of the password itself is not specifically defined. It can be a static password, combination of username and password, or any other combination of factors as long as it is within _**255** bytes_ in length.

The format of the authentication packet is the following:
```
+-----------------+---------------------------+
| Length [1 Byte] | Password [`Length` Bytes] |
+-----------------+---------------------------+
```

The authentication packet must be sent within a period of _2500 milliseconds_, _2.5 seconds_, after the _SSL/TLS session_ is established.
In the case, where it isn't, the server _may/should close the connection_ with the client as this can be considered as a _timeout_.

In case, the authentication fails, the server should close the connection.
Otherwise, the _server should send back_ a packet consisting of _**one zero (`0`)** byte_.

From that moment client is considered authenticated and therefore able to access resources of/on the server.
This also means that the connection timeout time is at least _600 seconds_, _10 minutes_.

In order to keep the connection open in case of inactivity, the client should send a packet consisting of _one zero (`0`) byte_.
When such packet is received by the server, the client _should not_ expect any packet as a response as the server itself _should not_ send anything in response to such packet.

The following (main mode) commands are defined as part of this protocol:
Type | Packet format | Response format | Description
-|-|-|-
Keep alive | `0` | N/A | A command that effectively doesn't do anything apart from resetting the timeout timer.
List | `1` | `0`, count (**4 byte**), {is directory (**1 byte**; `0` = file, _otherwise_ = folder), length (**2 byte**), name (**"_length_" bytes**)}...**"_count_" times** | Lists all subdirectory and file entries.
Go to root directory | `2` | `0` | Changes the session scope to the root directory of the session.
Enter directory | `3`, length (**2 byte**), name (**"_length_" bytes**) | `0` | Changes the session scope to the subdirectory that was selected.
Leave directory | `4` | `0` | Changes the session scope to the (sub)directory in which the current subdirectory resides.
Download file | `5`, length (**2 byte**), name (**"_length_" bytes**) | `0`, file size (**8 byte**) | Changes session's mode from the main (this) one to the downloading one.

_Only_ entries which _contain only_ those characters _should_ be listed:
* Alphabetic characters.
* Numeric characters.
* Spacebar (`0x20`).
* Tab (`0x9`).
* Full stop, `.` (`0x2E`).
* Dash, `-` (`0x2D`).
* Underscore, `_` (`0x5F`).
* Equals, `=` (`0x3D`).
* Tilde, `~` (`0x7E`).
* Exclamation mark, `!` (`0x21`).
* Comma, `,` (`0x2C`).
* Parenthesis, `(` & `)` (`0x28` & `0x29`).
* Square brackets, `[` & `]` (`0x5B` & `0x5D`).
* Curly brackets, `{` & `}` (`0x7B` & `0x7D`).

A filename which is exactly equal to `..` _**has** to be treated as **invalid**_ as it poses a _**security threat**_.

Type | Packet format | Response format | Description
-|-|-|-
Keep alive | `0` | N/A | A command that effectively doesn't do anything apart from resetting the timeout timer.
Chunk count | `1`, chunk size (**2 byte**; represents high 16 bits of a 20 bit integer; this cannot be equal to _zero (`0`)_) | `0`, chunk count (**7 byte**), last chunk size (**3 byte**) | This command returns the chunk count and the last chunk size in case it is incomplete. Otherwise, _last chunk size_ is equal to _zero (`0`)_.
Chunk hash | `2`, index of the chunk (**7 byte**), chunk size (**2 byte**; represents high 16 bits) | `0`, segment hash (**32 byte**) | Returns the SHA2-256 hash of the chunk with the specified size and index.
Download chunk | `3`, index of the chunk (**7 byte**), chunk size (**2 byte**; represents high 16 bits) | `0`, returned chunk size (**3 byte**), chunk (**"_returned chunk size_" bytes**) | Returns the chunk with given size at the respective index, calculated as: `index * size`.
Close file | `4` | `0` | Closes file and returns to the main mode of operation.
