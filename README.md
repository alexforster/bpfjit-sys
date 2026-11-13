# bpfjit-sys

Rust bindings to NetBSD's cBPF JIT engine

**Author:** Alex Forster \<alex@alexforster.com\><br/>
**License:** BSD-2-Clause

[![CI](https://github.com/alexforster/bpfjit-sys/actions/workflows/ci.yml/badge.svg)](https://github.com/alexforster/bpfjit-sys/actions/workflows/ci.yml)

### Usage

```rust
use bpfjit_sys::{BpfJit, Linktype};

static PACKET: &'static [u8] = &[
	// 0xDE, 0xAD, 0xBE, 0xEF, ...
];

fn main() {
	let filter = BpfJit::new("udp dst port 123", Linktype::Ethernet)?;
	
	if filter.matches(PACKET) {
		// ...
	}
}
```

### Attributions

#### `sljit`

Copyright © Zoltan Herczeg \<hzmester@freemail.hu\>. All rights reserved.

Distributed under the 2-clause BSD license (BSD-2-Clause).

#### `bpfjit`

Copyright © Alexander Nasonov \<alnsn@yandex.ru\>. All rights reserved.

Distributed under the 2-clause BSD license (BSD-2-Clause).
