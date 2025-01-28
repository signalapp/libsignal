# Introduction

libsignal contains platform-agnostic APIs used by the official Signal clients and servers, exposed as a Java, Swift, or TypeScript library. The underlying implementations are written in Rust.

This documentation is meant primarily for developers working at Signal who will be calling the libsignal APIs, and secondarily for those who maintain libsignal itself. It's meant to be a high-level guide to what's available, and generally won't contain implementation details or detailed API-by-API descriptions. It's *not* meant to be any sort of promise or commitment across versions of the library.

That is, if you're outside of Signal, please don't read too much into these.


## Viewing the book

First, [install mdBook](https://rust-lang.github.io/mdBook/guide/installation.html). Then, from the `doc` directory:

```console
% mdbook serve
2025-01-21 18:05:27 [INFO] (mdbook::book): Book building has started
2025-01-21 18:05:27 [INFO] (mdbook::book): Running the html backend
2025-01-21 18:05:27 [INFO] (mdbook::cmd::serve): Serving on: http://localhost:3000
2025-01-21 18:05:27 [INFO] (mdbook::cmd::watch::poller): Watching for changes...
2025-01-21 18:05:27 [INFO] (warp::server): Server::run; addr=[::1]:3000
2025-01-21 18:05:27 [INFO] (warp::server): listening on http://[::1]:3000
```

Now you can open the URL listed (probably <http://localhost:3000>) and view the rendered book. This is also a "watch" mode, which is convenient when editing the book---just save and watch the page reload.
