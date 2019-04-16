# bpfjit-sys

Rust bindings to NetBSD's cBPF JIT engine

**Version:** 1.0.0<br/>
**Author:** Alex Forster \<alex@alexforster.com\><br/>
**License:** BSD-2-Clause

[![Build Status](https://travis-ci.org/alexforster/bpfjit-sys.svg?branch=master)](https://travis-ci.org/alexforster/bpfjit-sys)

### Usage

```
static PACKET: &'static [u8] = &[...];

let filter = BpfJit::new("udp dst port 123")?;

if filter.matches(PACKET) {
	...
}
```

### Attributions

#### `sljit`

Copyright © Zoltan Herczeg \<hzmester@freemail.hu\>. All rights reserved.

Distributed under the 2-clause BSD license (BSD-2-Clause).

#### `bpfjit`

Copyright © Alexander Nasonov \<alnsn@yandex.ru\>. All rights reserved.

Distributed under the 2-clause BSD license (BSD-2-Clause).
