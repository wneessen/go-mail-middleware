<!--
SPDX-FileCopyrightText: The go-mail Authors

SPDX-License-Identifier: MIT
-->

# A collection of message middlewares for go-mail
[![GoDoc](https://godoc.org/github.com/thib-d/go-mail-middleware?status.svg)](https://pkg.go.dev/github.com/thib-d/go-mail-middleware)
[![codecov](https://codecov.io/gh/wneessen/go-mail-middleware/branch/main/graph/badge.svg?token=1XC87Z6QX4)](https://codecov.io/gh/wneessen/go-mail-middleware)
[![Go Report Card](https://goreportcard.com/badge/github.com/thib-d/go-mail-middleware)](https://goreportcard.com/report/github.com/thib-d/go-mail-middleware)
[![#go-mail on Discord](https://img.shields.io/badge/Discord-%23gomail-blue.svg)](https://discord.gg/dbfQyC4s)
[![REUSE status](https://api.reuse.software/badge/github.com/thib-d/go-mail-middleware)](https://api.reuse.software/info/github.com/thib-d/go-mail-middleware)
<a href="https://ko-fi.com/D1D24V9IX"><img src="https://uploads-ssl.webflow.com/5c14e387dab576fe667689cf/5cbed8a4ae2b88347c06c923_BuyMeACoffee_blue.png" height="20" alt="buy ma a coffee"></a>

### What is this?

This repository is a collection of different useful middlewares for [go-mail](https://github.com/thib-d/go-mail). 
Since we want to keep `go-mail` free of third party dependencies and only depend on the Go Standard Library, we 
introduce a Middleware concept in version v0.2.8. This allows the user to alter a `mail.Msg` according to their 
needs by simple implementing tool that satisfies the `mail.Middleware` interface and provide it to the `mail.Msg`
with the `mail.WithMiddleware()` option. This allows the use of 3rd party libraries with `go-mail` mail messages, 
while keeping `go-mail` itself dependancy free.

### List of currently supported middlewares

* [dkim](dkim): DKIM (DomainKeys Identified Mail) middleware to sign mail messages
* [openpgp](openpgp): OpenPGP middleware to digitally encrypt and sign mail messages (Experimental/Development on hold)
* [subject_capitalize](subject_capitalize): Capitalizes the subject of the message matching the given language
