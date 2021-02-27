# ecdsa-microservice-go

golang microservice to create ecdsa keypairs and sign/verify strings

- - - - -

ECDSA GET/POST REST microservice written in go with routes to:

- ``/sk`` - seed a new secret key (SK) & associated public key (PK)
- ``/pk`` - get a PK from SK
- ``/sign`` - sign a message with a SK
- ``/verify`` - given a signed message and a PK, verify the validity of the signature

Rudimentary logging included.

This is unaudited code with limited testing undertaken: not recommended for production use.

## Running

1. Clone repository
2. ``go run .``
3. Runs on port 8080 by default
