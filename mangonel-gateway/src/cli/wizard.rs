//! The setup questions and the order they are asked in.

use std::{
    fmt,
    io,
    net::IpAddr,
};

use thiserror::Error;

use crate::{
    cli::device::Device,
    config::{
        self,
        Addressing,
        Cidr,
        Family,
        Invalid,
        Lan,
        Method,
        Pool,
        Role,
        Setup,
        Subnet,
        Wan,
    },
};

/// A value that is typed rather than picked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Field {
    /// The address and its prefix length together.
    Cidr,

    Gateway,

    PoolStart,

    PoolEnd,
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Field::Cidr => "address (CIDR)",
            Field::Gateway => "gateway",
            Field::PoolStart => "DHCP start address",
            Field::PoolEnd => "DHCP end address",
        })
    }
}

/// An answer, or a request to return to the previous question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reply<T> {
    Answer(T),

    Back,
}

impl<T> Reply<T> {
    /// Turns an answer into what `f` makes of it.
    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> Reply<U> {
        match self {
            Reply::Answer(answer) => Reply::Answer(f(answer)),
            Reply::Back => Reply::Back,
        }
    }
}

/// Why the wizard ended without a setup.
#[derive(Debug, Error)]
pub(crate) enum Error {
    /// The user quit.
    #[error("setup interrupted")]
    Interrupted,

    #[error("setup is interactive and needs a terminal")]
    NotATerminal,

    #[error("terminal I/O failed: {0}")]
    Io(#[from] io::Error),
}

/// Puts the wizard's questions to whoever answers them.
pub(crate) trait Prompt {
    /// Asks which of `candidates` takes `role`, by position; `back` is false for the first
    /// question, which has none to go back to.
    fn device(
        &mut self,
        role: Role,
        candidates: &[&Device],
        initial: Option<usize>,
        back: bool,
    ) -> Result<Reply<usize>, Error>;

    /// Asks how `device` gets its `family` address; `optional` puts having none on offer, as
    /// `None`.
    fn method(
        &mut self,
        role: Role,
        family: Family,
        device: &Device,
        initial: Option<Method>,
        optional: bool,
    ) -> Result<Reply<Option<Method>>, Error>;

    /// Asks whether `device` gets a `family` address.
    fn addressed(
        &mut self,
        role: Role,
        family: Family,
        device: &Device,
        initial: bool,
    ) -> Result<Reply<bool>, Error>;

    /// Asks for the `family` value of `field` as text until `parse` accepts it; `earlier` is the
    /// answer given before, to start from.
    fn text<T: fmt::Display>(
        &mut self,
        role: Role,
        family: Family,
        field: Field,
        earlier: Option<T>,
        parse: impl Fn(&str) -> Result<T, Invalid> + Copy + 'static,
    ) -> Result<Reply<T>, Error>;

    /// Asks whether the router is the `family` DHCP server on `device`.
    fn dhcp_server(
        &mut self,
        role: Role,
        family: Family,
        device: &Device,
        initial: bool,
    ) -> Result<Reply<bool>, Error>;

    /// Asks whether to add another LAN; `available` is false once every device is taken.
    fn another_lan(&mut self, available: bool, initial: bool) -> Result<Reply<bool>, Error>;
}

/// How the WAN gets its address in one family, as answered so far.
#[derive(Clone, Copy)]
struct AddressingDraft {
    /// `None` leaves the WAN without an address in the family.
    method: Option<Method>,
    cidr: Option<Cidr>,
    gateway: Option<IpAddr>,
}

impl AddressingDraft {
    /// The finished answers; `None` if the family was left out.
    fn finish(&self) -> Option<Addressing> {
        Some(match (self.method?, self.cidr, self.gateway) {
            (Method::Dhcp, ..) => Addressing::Dhcp,
            (Method::Static, Some(cidr), Some(gateway)) => Addressing::Static { cidr, gateway },
            (Method::Static, ..) => {
                panic!("a static WAN was finished before its values were asked. This is a bug.")
            }
        })
    }
}

/// The WAN's answers so far.
struct WanDraft {
    /// Index into the device list.
    device: usize,
    ipv4: AddressingDraft,
    ipv6: AddressingDraft,
}

impl WanDraft {
    /// Starts on `device` with DHCP in both families.
    fn new(device: usize) -> Self {
        let dhcp = AddressingDraft {
            method: Some(Method::Dhcp),
            cidr: None,
            gateway: None,
        };

        Self {
            device,
            ipv4: dhcp,
            ipv6: dhcp,
        }
    }

    fn family_mut(&mut self, family: Family) -> &mut AddressingDraft {
        match family {
            Family::V4 => &mut self.ipv4,
            Family::V6 => &mut self.ipv6,
        }
    }

    /// The finished answers, for the WAN on the device called `device`.
    fn finish(&self, device: String) -> Wan {
        let ipv4 = self.ipv4.finish();

        Wan {
            device,
            ipv4: ipv4.expect("the WAN was finished without IPv4. This is a bug."),
            ipv6: self.ipv6.finish(),
        }
    }
}

/// A LAN's subnet in one family, as answered so far.
#[derive(Clone, Copy)]
struct SubnetDraft {
    cidr: Option<Cidr>,
    /// Whether the router serves DHCP there.
    serve: bool,
    pool_start: Option<IpAddr>,
    pool_end: Option<IpAddr>,
}

impl SubnetDraft {
    /// The finished answers.
    fn finish(&self) -> Subnet {
        let (cidr, pool) = match (self.cidr, self.serve, self.pool_start, self.pool_end) {
            (Some(cidr), false, ..) => (cidr, None),
            (Some(cidr), true, Some(start), Some(end)) => (cidr, Some(Pool { start, end })),
            _ => panic!("a LAN was finished before its values were asked. This is a bug."),
        };

        Subnet { cidr, pool }
    }
}

/// A LAN's answers so far.
struct LanDraft {
    /// Index into the device list.
    device: usize,
    ipv4: SubnetDraft,
    /// Whether the LAN gets an IPv6 address; `ipv6` counts only if it does.
    use_ipv6: bool,
    ipv6: SubnetDraft,
}

impl LanDraft {
    /// Starts on `device` without IPv6 and with the router as DHCP server.
    fn new(device: usize) -> Self {
        let subnet = SubnetDraft {
            cidr: None,
            serve: true,
            pool_start: None,
            pool_end: None,
        };

        Self {
            device,
            ipv4: subnet,
            use_ipv6: false,
            ipv6: subnet,
        }
    }

    fn family_mut(&mut self, family: Family) -> &mut SubnetDraft {
        match family {
            Family::V4 => &mut self.ipv4,
            Family::V6 => &mut self.ipv6,
        }
    }

    /// The finished answers, for the LAN on the device called `device`.
    fn finish(&self, device: String) -> Lan {
        Lan {
            device,
            ipv4: self.ipv4.finish(),
            ipv6: self.use_ipv6.then(|| self.ipv6.finish()),
        }
    }
}

/// The question to ask next; one about a LAN carries the LAN's number.
#[derive(Clone, Copy)]
enum Step {
    WanDevice,

    WanMethod(Family),

    WanCidr(Family),

    /// Checked against the address just given.
    WanGateway(Family, Cidr),

    LanDevice(usize),

    /// Whether the LAN gets an IPv6 address.
    LanIpv6(usize),

    LanCidr(usize, Family),

    /// Whether the router serves DHCP on the LAN.
    Serve(usize, Family, Cidr),

    /// The first address of the DHCP pool, which has to fit the subnet just given.
    PoolStart(usize, Family, Cidr),

    /// The last address of a pool that begins at the one just given.
    PoolEnd(usize, Family, Cidr, IpAddr),

    /// Whether another LAN follows this one.
    Another(usize),
}

impl Step {
    /// What follows the WAN's `family` questions.
    fn after_wan(family: Family) -> Self {
        match family {
            Family::V4 => Step::WanMethod(Family::V6),
            Family::V6 => Step::LanDevice(0),
        }
    }

    /// What follows the `family` questions of the `n`-th LAN.
    fn after_lan(n: usize, family: Family) -> Self {
        match family {
            Family::V4 => Step::LanIpv6(n),
            Family::V6 => Step::Another(n),
        }
    }
}

/// Asks for the WAN and one or more LANs out of `devices`, which must hold at least two.
pub(crate) fn run(devices: &[Device], prompt: &mut impl Prompt) -> Result<Setup, Error> {
    let default_route = devices.iter().position(|device| device.default_route);
    let mut wan = WanDraft::new(default_route.unwrap_or(0));
    // Drafts past the current step are earlier answers, kept so that a question asked again starts
    // from the earlier answer.
    let mut lans: Vec<LanDraft> = Vec::new();
    // The questions answered on the way to `step`, which going back retraces.
    let mut answered: Vec<Step> = Vec::new();
    let mut step = Step::WanDevice;

    loop {
        let reply = match step {
            Step::WanDevice => {
                let offered: Vec<usize> = (0..devices.len()).collect();
                let current = Some(wan.device);
                ask_device(prompt, devices, Role::Wan, &offered, current, false)?.map(|device| {
                    wan.device = device;

                    Step::WanMethod(Family::V4)
                })
            }

            Step::WanMethod(family) => {
                let device = &devices[wan.device];
                let draft = wan.family_mut(family);
                // Only the IPv6 address can be left out.
                let optional = family == Family::V6;
                prompt
                    .method(Role::Wan, family, device, draft.method, optional)?
                    .map(|method| {
                        draft.method = method;

                        match method {
                            Some(Method::Static) => Step::WanCidr(family),
                            Some(Method::Dhcp) | None => Step::after_wan(family),
                        }
                    })
            }

            Step::WanCidr(family) => {
                let draft = wan.family_mut(family);
                let parse = move |text: &str| config::cidr(text, family);
                prompt
                    .text(Role::Wan, family, Field::Cidr, draft.cidr, parse)?
                    .map(|cidr| {
                        draft.cidr = Some(cidr);

                        Step::WanGateway(family, cidr)
                    })
            }

            Step::WanGateway(family, cidr) => {
                let draft = wan.family_mut(family);
                let parse = move |text: &str| config::gateway(text, cidr);
                prompt
                    .text(Role::Wan, family, Field::Gateway, draft.gateway, parse)?
                    .map(|gateway| {
                        draft.gateway = Some(gateway);

                        Step::after_wan(family)
                    })
            }

            Step::LanDevice(n) => {
                let offered = unused(devices.len(), wan.device, &lans[..n]);
                let current = lans.get(n).map(|lan| lan.device);
                ask_device(prompt, devices, Role::Lan(n), &offered, current, true)?.map(|device| {
                    match lans.get_mut(n) {
                        Some(lan) => lan.device = device,
                        None => lans.push(LanDraft::new(device)),
                    }

                    Step::LanCidr(n, Family::V4)
                })
            }

            Step::LanIpv6(n) => {
                let lan = &mut lans[n];
                let device = &devices[lan.device];
                prompt
                    .addressed(Role::Lan(n), Family::V6, device, lan.use_ipv6)?
                    .map(|use_ipv6| {
                        lan.use_ipv6 = use_ipv6;

                        if use_ipv6 {
                            Step::LanCidr(n, Family::V6)
                        } else {
                            Step::Another(n)
                        }
                    })
            }

            Step::LanCidr(n, family) => {
                let subnet = lans[n].family_mut(family);
                let parse = move |text: &str| config::cidr(text, family);
                prompt
                    .text(Role::Lan(n), family, Field::Cidr, subnet.cidr, parse)?
                    .map(|cidr| {
                        subnet.cidr = Some(cidr);

                        Step::Serve(n, family, cidr)
                    })
            }

            Step::Serve(n, family, cidr) => {
                let lan = &mut lans[n];
                let device = &devices[lan.device];
                let subnet = lan.family_mut(family);
                prompt
                    .dhcp_server(Role::Lan(n), family, device, subnet.serve)?
                    .map(|serve| {
                        subnet.serve = serve;

                        if serve {
                            Step::PoolStart(n, family, cidr)
                        } else {
                            Step::after_lan(n, family)
                        }
                    })
            }

            Step::PoolStart(n, family, cidr) => {
                let subnet = lans[n].family_mut(family);
                let parse = move |text: &str| config::pool_start(text, cidr);
                prompt
                    .text(
                        Role::Lan(n),
                        family,
                        Field::PoolStart,
                        subnet.pool_start,
                        parse,
                    )?
                    .map(|start| {
                        subnet.pool_start = Some(start);

                        Step::PoolEnd(n, family, cidr, start)
                    })
            }

            Step::PoolEnd(n, family, cidr, start) => {
                let subnet = lans[n].family_mut(family);
                let parse = move |text: &str| config::pool_end(text, cidr, start);
                prompt
                    .text(Role::Lan(n), family, Field::PoolEnd, subnet.pool_end, parse)?
                    .map(|end| {
                        subnet.pool_end = Some(end);

                        Step::after_lan(n, family)
                    })
            }

            Step::Another(n) => {
                let available = !unused(devices.len(), wan.device, &lans[..=n]).is_empty();
                match prompt.another_lan(available, lans.len() > n + 1)? {
                    Reply::Answer(true) => Reply::Answer(Step::LanDevice(n + 1)),
                    Reply::Answer(false) => {
                        let name = |device: usize| devices[device].name.clone();
                        let lans = lans[..=n].iter().map(|lan| lan.finish(name(lan.device)));

                        return Ok(Setup {
                            wan: wan.finish(name(wan.device)),
                            lans: lans.collect(),
                        });
                    }
                    Reply::Back => Reply::Back,
                }
            }
        };

        step = match reply {
            Reply::Answer(next) => {
                answered.push(step);

                next
            }
            // There is nothing before the first question, so going back from it asks it again.
            Reply::Back => answered.pop().unwrap_or(Step::WanDevice),
        };
    }
}

/// Asks for one of the `offered` devices, starting on `current` if it is among them.
fn ask_device(
    prompt: &mut impl Prompt,
    devices: &[Device],
    role: Role,
    offered: &[usize],
    current: Option<usize>,
    back: bool,
) -> Result<Reply<usize>, Error> {
    let candidates: Vec<&Device> = offered.iter().map(|&device| &devices[device]).collect();
    let initial = current.and_then(|current| offered.iter().position(|&device| device == current));
    let reply = prompt.device(role, &candidates, initial, back)?;

    Ok(reply.map(|position| {
        *offered
            .get(position)
            .expect("the prompt picked a device it was not offered. This is a bug.")
    }))
}

/// The devices, out of `count`, that neither the WAN nor any of `lans` uses.
fn unused(count: usize, wan: usize, lans: &[LanDraft]) -> Vec<usize> {
    (0..count)
        .filter(|&device| device != wan && lans.iter().all(|lan| lan.device != device))
        .collect()
}
