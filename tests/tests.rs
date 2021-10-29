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
}
