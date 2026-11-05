# netlink

This package contains a Go implementation of the [Linux Netlink](https://docs.kernel.org/userspace-api/netlink/intro.html) protocol, in inter-process communication standard for interacting with Linux kernel subsystems for network configuration.

> [!NOTE]
> This package is under active development, and should be considered unstable.
>
> It's api or behavior may change without warning during this development phase.


## Packages

### netlink

[![Go Reference](https://pkg.go.dev/badge/go.crhq.io/netlink.svg)](https://pkg.go.dev/go.crhq.io/netlink)

```sh
go get go.crhq.io/netlink
```

Package `netlink` implements the Linux Kernel Netlink protocol, for interacting with the systems network configuration.


### genetlink

[![Go Reference](https://pkg.go.dev/badge/go.crhq.io/netlink/genetlink.svg)](https://pkg.go.dev/go.crhq.io/netlink/genetlink)

```sh
go get go.crhq.io/netlink/genetlink
```

Package `genetlink` implements a wrapper around the Netlink client for the Generic Netlink protocol, which supports dynamic registration of servers.
