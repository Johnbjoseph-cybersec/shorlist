"""The network axis: rows whose product terminates a network protocol (OpenSSH, nginx, Apache
mod_ssl, OpenSSL s_server; strongSwan mapped but not measured) are planted as live servers in
containers and measured with network scanners. See wire.yaml for what must be seen on the wire,
harness.py for how a row is planted and scanned, scoring.py for the outcomes."""
