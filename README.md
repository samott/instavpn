InstaVPN
========

Simple utility service that:

- Launches an EC2 instance
- Creates a SOCKS5 tunnel over SSH
- Terminates the instance on exit

Setup
-----

Create a config with credentials using the AWS CLI tool - or a file at
`~/.aws/credentials` that resembles this:

```
[default]
aws_access_key_id = XXXXXXXXXXXXXXXXXXXX
aws_secret_access_key = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```
