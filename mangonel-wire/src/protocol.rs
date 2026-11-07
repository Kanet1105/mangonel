/// An IP protocol number, which IPv6 calls a next header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Protocol(pub u8);

impl Protocol {
    pub const HOP_BY_HOP: Self = Self(0);
    pub const ICMP: Self = Self(1);
    pub const IPV4: Self = Self(4);
    pub const TCP: Self = Self(6);
    pub const UDP: Self = Self(17);
    pub const IPV6: Self = Self(41);
    pub const ROUTING: Self = Self(43);
    pub const FRAGMENT: Self = Self(44);
    pub const ESP: Self = Self(50);
    pub const AH: Self = Self(51);
    pub const ICMPV6: Self = Self(58);
    pub const NO_NEXT_HEADER: Self = Self(59);
    pub const DESTINATION_OPTIONS: Self = Self(60);
}
