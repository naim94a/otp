[![Build Status](https://travis-ci.org/naim94a/otp.svg?branch=master)](https://travis-ci.org/naim94a/otp)

**libotp** implements RFC4226 and RFC6328.
These RFCs are implemented by Google's Google Authenticator.

OTP can increases the security for various things, such as web services, servers and even private computers.

## How OTP works
A secret is shared between the client and a device.
Passwords are generated based on the shared secret.

It is possible to work in two modes:
1. Counter based - The OTP is generated with a counter that is increased on each successful attempt.
2. Time based - The OTP is generated based on time. Codes are valid for a pre-configured amount of time.

## Features
* HTOP - HMAC One-Time-Password generation ([RFC4226](https://tools.ietf.org/html/rfc4226)).
    * Configurable HMAC - SHA1, SHA256 or SHA512.
* TOTP - Time based One-Time-Password generation ([RFC6328](https://tools.ietf.org/html/rfc6238)).
    * Configurable time step, RFC recommended is 30 seconds.
    * Configurable T0 (start time).
