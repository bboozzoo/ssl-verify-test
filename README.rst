SSL test tool
=============

A simple tool that I wrote when trying to figure out the process of
establishing a SSL connection with OpenSSL.

The code can be used as an example of how the handshake and
verification is performed. Hopefully the whole SSL call sequence is
correct, feel free to let me know if there are issues. OpenSSL
documentation does not make is particularly easy to figure out how the
respective bits go together, so most of the code is based on looking
at other people's code or OpenSSL apps (`s_client` and `s_server`).

Usage
=====

Make sure to have development headers for OpenSSL installed. Build the
code using CMake::

  mkdir build
  cd build
  cmake ..
  make

Run the program like this (assuming that you keep your certificate
store in `~/.cert`)::

  $ ./ssltest facebook.com 443 ~/.cert
  connect to facebook.com:443
  official name: facebook.com
  add type: IPv4
  resolved to: 173.252.120.6
  connect...
  connected on fd: 3
  connected: 3
  CA path: /home/maciek/.cert cert: (null)
  SSL options: 0x00000004
  verify: /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance EV Root CA
     depth: 2 preverify: 1 err: ok
  verify: /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance CA-3
     depth: 1 preverify: 1 err: ok
  verify: /C=US/ST=CA/L=Menlo Park/O=Facebook, Inc./CN=*.facebook.com
     depth: 0 preverify: 1 err: ok
  proto version: TLSv1.2
  cipher: ECDHE-ECDSA-AES128-GCM-SHA256
  verify result: ok
  certificate verified

In my case the *DigiCert High Assurance EV Root CA* certificate was
not in the store, so when `ssltest` ran for the first time it failed
like this::

  $ ./ssltest facebook.com 443 ~/.cert
  connect to facebook.com:443
  official name: facebook.com
  add type: IPv4
  resolved to: 173.252.120.6
  connect...
  connected on fd: 3
  connected: 3
  CA path: /home/maciek/.cert cert: (null)
  SSL options: 0x00000004
  verify: /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance CA-3
     depth: 1 preverify: 0 err: unable to get local issuer certificate
  SSL error: 1
  SSL connect failed: -1
  failed to perform handshake: 1

At this point, it's enough to run `ssltest -a ..` find the last
certificate in chain, grab it from the internet, and pass it as the
third parameter like this::

  $ ./ssltest facebook.com 443 ~/.cert/DigiCertHighAssuranceEVRootCA.pem
  ...
  CA path: (null) cert: /home/maciek/.cert/DigiCertHighAssuranceEVRootCA.pem
  ...
  verify: /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance EV Root CA
     depth: 2 preverify: 1 err: ok
  verify: /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert High Assurance CA-3
     depth: 1 preverify: 1 err: ok
  verify: /C=US/ST=CA/L=Menlo Park/O=Facebook, Inc./CN=*.facebook.com
     depth: 0 preverify: 1 err: ok
  ...
  verify result: ok
  certificate verified

