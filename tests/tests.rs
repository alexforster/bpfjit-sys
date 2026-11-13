// tests/tests.rs

#[cfg(test)]
mod tests {
    use bpfjit_sys::*;

    static UDP_123_PACKET: &'static [u8] = &[
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x08, 0x00, 0x45, 0x00, 0x00, 0x4c,
        0x00, 0x00, 0x40, 0x00, 0x35, 0x11, 0x03, 0x44, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0xc9, 0x21,
        0x00, 0x7b, 0x00, 0x38, 0xa2, 0xa2, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x32, 0x01, 0xe6, 0x58, 0xd4, 0xfd, 0xf3,
    ];

    #[test]
    fn test_udp_123_packet() {
        let l2_filter = BpfJit::new("udp dst port 123", Linktype::Ethernet).unwrap();
        assert_eq!(l2_filter.matches(UDP_123_PACKET), true);
        assert_eq!(l2_filter.matches(TCP_NULL_PACKET), false);
        let l3_filter = BpfJit::new("udp dst port 123", Linktype::Ip).unwrap();
        assert_eq!(l3_filter.matches(&UDP_123_PACKET[14..]), true);
        assert_eq!(l3_filter.matches(&TCP_NULL_PACKET[14..]), false);
        let raw_filter = BpfJit::raw(&[
            Opcode(40, 0, 0, 12),
            Opcode(21, 0, 4, 34525),
            Opcode(48, 0, 0, 20),
            Opcode(21, 0, 11, 17),
            Opcode(40, 0, 0, 56),
            Opcode(21, 8, 9, 123),
            Opcode(21, 0, 8, 2048),
            Opcode(48, 0, 0, 23),
            Opcode(21, 0, 6, 17),
            Opcode(40, 0, 0, 20),
            Opcode(69, 4, 0, 8191),
            Opcode(177, 0, 0, 14),
            Opcode(72, 0, 0, 16),
            Opcode(21, 0, 1, 123),
            Opcode(6, 0, 0, 262144),
            Opcode(6, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(raw_filter.matches(UDP_123_PACKET), true);
        assert_eq!(raw_filter.matches(TCP_NULL_PACKET), false);
    }

    static TCP_NULL_PACKET: &'static [u8] = &[
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x08, 0x00, 0x45, 0x28, 0x00, 0x28,
        0xf9, 0x41, 0x00, 0x00, 0xf4, 0x06, 0x74, 0x02, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0xb5, 0x58,
        0x02, 0x97, 0xcb, 0x86, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x52, 0xca, 0xff, 0xff, 0x64, 0xc1, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn test_tcp_null_packet() {
        let l2_filter = BpfJit::new("tcp src port 46424", Linktype::Ethernet).unwrap();
        assert_eq!(l2_filter.matches(TCP_NULL_PACKET), true);
        assert_eq!(l2_filter.matches(UDP_123_PACKET), false);
        let l3_filter = BpfJit::new("tcp src port 46424", Linktype::Ip).unwrap();
        assert_eq!(l3_filter.matches(&TCP_NULL_PACKET[14..]), true);
        assert_eq!(l3_filter.matches(&UDP_123_PACKET[14..]), false);
        let raw_filter = BpfJit::raw(&[
            Opcode(40, 0, 0, 12),
            Opcode(21, 0, 4, 34525),
            Opcode(48, 0, 0, 20),
            Opcode(21, 0, 11, 6),
            Opcode(40, 0, 0, 54),
            Opcode(21, 8, 9, 46424),
            Opcode(21, 0, 8, 2048),
            Opcode(48, 0, 0, 23),
            Opcode(21, 0, 6, 6),
            Opcode(40, 0, 0, 20),
            Opcode(69, 4, 0, 8191),
            Opcode(177, 0, 0, 14),
            Opcode(72, 0, 0, 14),
            Opcode(21, 0, 1, 46424),
            Opcode(6, 0, 0, 262144),
            Opcode(6, 0, 0, 0),
        ])
        .unwrap();
        assert_eq!(raw_filter.matches(TCP_NULL_PACKET), true);
        assert_eq!(raw_filter.matches(UDP_123_PACKET), false);
    }

    #[test]
    fn test_clone() {
        let filter = BpfJit::new("udp dst port 123", Linktype::Ethernet).unwrap();
        assert_eq!(filter.matches(UDP_123_PACKET), true);
        assert_eq!(filter.matches(TCP_NULL_PACKET), false);
        let cloned_filter = filter.clone();
        assert_eq!(cloned_filter.matches(UDP_123_PACKET), true);
        assert_eq!(cloned_filter.matches(TCP_NULL_PACKET), false);
    }

    #[test]
    fn raw_filter_returns_exact_values() {
        let ret_constant = BpfJit::raw(&[Opcode(0x06, 0, 0, 0x1234)]).unwrap();
        assert_eq!(ret_constant.value(&[]), 0x1234);

        let divide = BpfJit::raw(&[
            Opcode(0x00, 0, 0, 7), // LD IMM 7
            Opcode(0x34, 0, 0, 2), // DIV K 2
            Opcode(0x16, 0, 0, 0), // RET A
        ])
        .unwrap();
        assert_eq!(divide.value(&[]), 3);
    }

    #[test]
    fn raw_filter_recompiled_after_drop() {
        for value in [0x1234, 0x5678, 0x9abc, 0xdef0] {
            let filter = BpfJit::raw(&[Opcode(0x06, 0, 0, value)]).unwrap();
            assert_eq!(filter.value(&[]), value);
        }
    }

    #[test]
    fn raw_filter_returns_zero_for_truncated_loads() {
        let load_word = BpfJit::raw(&[
            Opcode(0x20, 0, 0, 2), // LD W ABS 2
            Opcode(0x16, 0, 0, 0), // RET A
        ])
        .unwrap();
        let packet = [0xaa, 0xbb, 0x12, 0x34, 0x56, 0x78];

        for captured_len in 0..packet.len() {
            assert_eq!(load_word.value(&packet[..captured_len]), 0);
        }
        assert_eq!(load_word.value(&packet), 0x1234_5678);
    }

    #[test]
    fn raw_filter_returns_packet_length() {
        let length = BpfJit::raw(&[
            Opcode(0x80, 0, 0, 0), // LD W LEN
            Opcode(0x16, 0, 0, 0), // RET A
        ])
        .unwrap();

        for packet_len in [0, 1, 31, 255] {
            let packet = vec![0; packet_len];
            assert_eq!(length.value(&packet), packet_len as u32);
        }
    }

    #[test]
    fn raw_filter_rejects_malformed_programs() {
        // An unconditional jump past the end of the program.
        assert!(BpfJit::raw(&[
            Opcode(0x05, 0, 0, 4),
            Opcode(0x06, 0, 0, 0),
            Opcode(0x06, 0, 0, 1),
            Opcode(0x06, 0, 0, 2),
            Opcode(0x06, 0, 0, 3),
        ])
        .is_err());

        // NetBSD's userspace validator accepts this backward JA edge: from
        // index 2, k wraps its target to index 0 and forms a loop; the JIT
        // rejects the out-of-range offset.
        assert!(BpfJit::raw(&[
            Opcode(0x05, 0, 0, 1),
            Opcode(0x06, 0, 0, 777),
            Opcode(0x05, 0, 0, u32::MAX - 2),
            Opcode(0x06, 0, 0, 0),
        ])
        .is_err());

        // Invalid conditional jump opcodes are rejected regardless of whether
        // their branch offsets are equal.
        for (jt, jf) in [(0, 1), (1, 1)] {
            assert!(BpfJit::raw(&[
                Opcode(0x80, 0, 0, 0),
                Opcode(0xf5, jt, jf, 7),
                Opcode(0x06, 0, 0, 10),
                Opcode(0x06, 0, 0, 11),
            ])
            .is_err());
        }

        // These unsupported terminal RET variants are rejected by the JIT.
        assert!(BpfJit::raw(&[
            Opcode(0x01, 0, 0, 13), // LDX W IMM 13
            Opcode(0x0e, 0, 0, 0),  // RET X
        ])
        .is_err());
        assert!(BpfJit::raw(&[
            Opcode(0x00, 0, 0, 13),  // LD IMM 13
            Opcode(0x8016, 0, 0, 0), // RET A with invalid opcode bits
        ])
        .is_err());

        // An unsupported RET in the middle is accepted; execution returns 0.
        let middle_bad_ret =
            BpfJit::raw(&[Opcode(0x00, 0, 0, 13), Opcode(0x8016, 0, 0, 0), Opcode(0x06, 0, 0, 31)]).unwrap();
        assert_eq!(middle_bad_ret.value(&[]), 0);
        assert!(BpfJit::raw(&[
            Opcode(0x00, 0, 0, 7),
            Opcode(0x34, 0, 0, 0), // DIV K 0
            Opcode(0x16, 0, 0, 0),
        ])
        .is_err());
    }

    #[repr(C)]
    struct PcapBpfInsn {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct PcapBpfProgram {
        bf_len: u32,
        bf_insns: *mut PcapBpfInsn,
    }

    #[repr(C)]
    struct PcapPacketHeader {
        ts: libc::timeval,
        caplen: u32,
        len: u32,
    }

    #[link(name = "pcap")]
    extern "C" {
        fn pcap_offline_filter(
            program: *const PcapBpfProgram,
            header: *const PcapPacketHeader,
            packet: *const u8,
        ) -> libc::c_int;
    }

    fn pcap_interpreter_value(insns: &[Opcode], packet: &[u8]) -> u32 {
        let mut native_insns: Vec<PcapBpfInsn> =
            insns.iter().map(|Opcode(code, jt, jf, k)| PcapBpfInsn { code: *code, jt: *jt, jf: *jf, k: *k }).collect();
        let program = PcapBpfProgram { bf_len: native_insns.len() as u32, bf_insns: native_insns.as_mut_ptr() };
        let header = PcapPacketHeader {
            ts: libc::timeval { tv_sec: 0, tv_usec: 0 },
            caplen: packet.len() as u32,
            len: packet.len() as u32,
        };

        // Both caplen and wire len match the byte slice because BpfJit::value
        // exposes only captured bytes and uses that length for BPF_LEN.
        let empty_packet = [0u8; 1];
        let packet_ptr = if packet.is_empty() { empty_packet.as_ptr() } else { packet.as_ptr() };
        unsafe { pcap_offline_filter(&program, &header, packet_ptr) as u32 }
    }

    #[test]
    fn raw_filter_matches_libpcap_interpreter_for_valid_instructions() {
        let insns = [
            Opcode(0x30, 0, 0, 0),    // LD B ABS 0
            Opcode(0x15, 0, 3, 0x12), // JEQ K 0x12, else skip to RET K 0
            Opcode(0x28, 0, 0, 1),    // LD H ABS 1
            Opcode(0x04, 0, 0, 1),    // ADD K 1
            Opcode(0x16, 0, 0, 0),    // RET A
            Opcode(0x06, 0, 0, 0),    // RET K 0
        ];
        let jit = BpfJit::raw(&insns).unwrap();
        let matching_packet = [0x12, 0x34, 0x56];
        let nonmatching_packet = [0x13, 0x34, 0x56];

        assert_eq!(jit.value(&matching_packet), 0x3457);
        assert_eq!(jit.value(&nonmatching_packet), 0);
        for packet in [&matching_packet[..], &nonmatching_packet[..]] {
            for captured_len in 0..=packet.len() {
                let slice = &packet[..captured_len];
                assert_eq!(jit.value(slice), pcap_interpreter_value(&insns, slice), "captured length {captured_len}");
            }
        }
    }
}
