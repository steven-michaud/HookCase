# HookCase

HookCase is a tool for debugging and reverse engineering applications
on macOS (aka OS X), and the operating system itself. It re-implements
and extends
[Apple's `DYLD_INSERT_LIBRARIES` functionality](https://books.google.com/books?id=K8vUkpOXhN4C&pg=PA73&lpg=PA73&dq="dyld+interposing"+Singh.).
It can be used to hook any method in any module (even non-exported
ones, and even those that don't have an entry in their own module's
symbol table). In a single operation, it can be applied to a parent
process and all its child processes, whether or not the child
processes inherit their parent's environment. It supports
watchpoints. So HookCase is considerably more powerful than
`DYLD_INSERT_LIBRARIES`. It also doesn't have the restrictions Apple
has placed on `DYLD_INSERT_LIBRARIES`. So, for example, HookCase can
be used with applications that have
[entitlements](https://developer.apple.com/library/content/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AboutEntitlements.html).
HookCase runs on OS X 10.9 (Mavericks) through macOS 10.15 (Catalina).

Steven Michaud, 7/2020

## Table of Contents

* [What's New](0-whats-new.md)

* [More About HookCase](1-more-about.md)

* [Building](2-building.md)

* [Installing](3-installing.md)

* [Using](4-using.md)

* [Resources](5-resources.md)

* [Example Hook Libraries](6-examples.md)
