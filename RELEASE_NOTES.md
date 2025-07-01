v0.76.2

- Java: Fix lifetime management for bridged objects used with async functions; previously there was a window where they could get prematurely deallocated, leading to undefined behavior.

- Java: Simplify and fix the finalization of incremental mac streams.
