# bpfjit-sys

Rust bindings to NetBSD's cBPF JIT engine

**Author:** Alex Forster \<alex@alexforster.com\><br/>
**License:** BSD-2-Clause

[![CI](https://github.com/alexforster/bpfjit-sys/actions/workflows/ci.yml/badge.svg)](https://github.com/alexforster/bpfjit-sys/actions/workflows/ci.yml)

### Prerequisites

Install the Rust toolchain, a C compiler, `patch`, and libpcap development files. On Debian or Ubuntu, run `sudo apt-get install build-essential libpcap-dev patch` for the C compiler, `patch`, and libpcap development files.

### Usage

```rust
use bpfjit_sys::{BpfJit, Linktype};

static PACKET: &'static [u8] = &[
	// 0xDE, 0xAD, 0xBE, 0xEF, ...
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
	let filter = BpfJit::new("udp dst port 123", Linktype::Ethernet)?;
	
	if filter.matches(PACKET) {
		// ...
	}
	Ok(())
}
```

### Vendored sources

`bpfjit` and its matching SLJIT are vendored from the same [NetBSD `src` snapshot](https://github.com/NetBSD/src/tree/88b7858091c9fbc32bd7e475ea5a138a1a3b4819): [`sys/net/bpfjit.c`](https://github.com/NetBSD/src/blob/88b7858091c9fbc32bd7e475ea5a138a1a3b4819/sys/net/bpfjit.c) and [`sys/external/bsd/sljit/dist/sljit_src`](https://github.com/NetBSD/src/tree/88b7858091c9fbc32bd7e475ea5a138a1a3b4819/sys/external/bsd/sljit/dist/sljit_src). The tracked NetBSD C sources are pristine files from that snapshot. Local userspace adaptations are maintained separately in [`patches/netbsd-bpfjit.patch`](patches/netbsd-bpfjit.patch) and [`patches/netbsd-sljit.patch`](patches/netbsd-sljit.patch); the build applies these patches to copies of the vendored sources and does not modify the original files. When updating either component, update both from the same NetBSD snapshot.

### Attributions

#### `sljit`

Copyright © Zoltan Herczeg \<hzmester@freemail.hu\>. All rights reserved.

Distributed under the 2-clause BSD license (BSD-2-Clause).

#### `bpfjit`

Copyright © Alexander Nasonov \<alnsn@yandex.ru\>. All rights reserved.

Distributed under the 2-clause BSD license (BSD-2-Clause).
