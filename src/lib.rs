use libc::{__c_anonymous_ifr_ifru, ifreq, IFF_NO_PI, IFF_TAP, IFF_TUN};
use std::error::Error;
use std::fmt::Display;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::io::Error as IoError;

nix::ioctl_write_int!(tunsetiff, b'T', 202);

#[derive(Debug)]
pub enum TTError {
    OpenTun(IoError),
    Ioctl(String),
}

impl Display for TTError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TTError::OpenTun(value) => {
                write!(f, "OpenTun: {}", value)
            }
            TTError::Ioctl(value) => {
                write!(f, "Ioctl: {}", value)
            }
        }
    }
}
impl Error for TTError {}

pub struct TT<'a> {
    pub name: &'a str,
    dev_tun: &'a str,
    pub tap: bool,
}

impl<'a> TT<'a> {
    pub fn build(&self) -> Result<File, TTError> {
        let fd: File = match OpenOptions::new().read(true).write(true).open(self.dev_tun) {
            Ok(value) => value,
            Err(e) => return Err(TTError::OpenTun(e)),
        };

        let mut ifr = ifreq {
            ifr_name: [0i8; 16],
            ifr_ifru: {
                __c_anonymous_ifr_ifru {
                    ifru_flags: (if self.tap {
                        IFF_TAP
                    } else {
                        IFF_TUN | IFF_NO_PI
                    }) as i16,
                }
            },
        };

        for (i, c) in self.name.as_bytes().bytes().enumerate() {
            if let Ok(value) = c {
                ifr.ifr_name[i] = value as i8;
            }
        }
        if let Err(e) = unsafe { tunsetiff(fd.as_raw_fd(), &ifr as *const _ as _) } {
            return Err(TTError::Ioctl(e.to_string()));
        }
        Ok(fd)
    }
}

impl Default for TT<'static> {
    fn default() -> Self {
        Self {
            name: "tt0",
            dev_tun: "/dev/net/tun",
            tap: false,
        }
    }
}

#[derive(Debug, Default)]
pub enum IPI {
    #[default]
    None,
    IPV4 {
        ip_source: [u8; 4],
        ip_destination: [u8; 4],
        /// 1=ICMP 2=IGMP 6=TCP 17=UDP
        ip_protocol: u8,
    },
}
impl IPI {
    pub fn de(a: &[u8]) -> Self {
        if a.len() < 20 {
            return Self::None;
        }

        if ((a[0]) >> 4) == 4 {
            let mut ip_s = [0u8; 4];
            let mut ip_d = [0u8; 4];
            ip_s.copy_from_slice(&a[12..16]);
            ip_d.copy_from_slice(&a[16..20]);
            let ip_p = a[9];
            return Self::IPV4 {
                ip_source: ip_s,
                ip_destination: ip_d,
                ip_protocol: ip_p,
            };
        }
        Self::None
    }
}
