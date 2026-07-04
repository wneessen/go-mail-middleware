<!--
SPDX-FileCopyrightText: The go-mail Authors

SPDX-License-Identifier: MIT
-->

> [!IMPORTANT]
> ## This repository has been sunset and archived
>
> `go-mail-middleware` originally served as a starting point and reference implementation for [go-mail](https://github.com/wneessen/go-mail) users who
> wanted to build their own message middlewares. Since then most of the middlewares provided here are now natively supported in go-mail itself.
>
> The `mail.Middleware` interface and the `mail.WithMiddleware()` option still exist in go-mail, so you can absolutely keep writing your own custom
> middlewares - but there is no longer a good reason to maintain this separate collection.
>
> What this means:
>
> - **The repository is now archived and read-only.** All existing code will remain online for reference and for anyone who still depends on it, but
>   it will not receive any further updates, bug fixes, or new features.
> - **You don't need to migrate anything urgently** - existing imports will continue to work. However, we recommend checking whether the functionality
>   you need is already built into [go-mail](https://github.com/wneessen/go-mail) directly, and switching to the native implementation where available.
> - **Questions and discussion** should be directed to the main [go-mail](https://github.com/wneessen/go-mail) project.
>
> Thank you to everyone who used, contributed to, and drew inspiration from this repository. ❤️

# A collection of message middlewares for go-mail

### What is this?

This repository is a collection of different useful middlewares for [go-mail](https://github.com/wneessen/go-mail). 
Since we want to keep `go-mail` free of third party dependencies and only depend on the Go Standard Library, we 
introduce a Middleware concept in version v0.2.8. This allows the user to alter a `mail.Msg` according to their 
needs by simple implementing tool that satisfies the `mail.Middleware` interface and provide it to the `mail.Msg`
with the `mail.WithMiddleware()` option. This allows the use of 3rd party libraries with `go-mail` mail messages, 
while keeping `go-mail` itself dependancy free.

### List of currently supported middlewares

* [dkim](dkim): DKIM (DomainKeys Identified Mail) middleware to sign mail messages
* [openpgp](openpgp): OpenPGP middleware to digitally encrypt and sign mail messages (Experimental/Development on hold)
* [subject_capitalize](subject_capitalize): Capitalizes the subject of the message matching the given language
