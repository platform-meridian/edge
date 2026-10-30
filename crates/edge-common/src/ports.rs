//! The ports the unit's host-network daemons listen on, on one network
//! namespace: one enum, so a port given twice does not compile.

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostPort {
    UpdateApi = 7443,
    UpdateHealth = 7444,
    SignerHealth = 9750,
    SignerAccess = 9751,
    IdleHealth = 9752,
}

impl HostPort {
    pub const fn port(self) -> u16 {
        self as u16
    }

    /// Every address.
    pub fn any(self) -> String {
        format!("0.0.0.0:{}", self.port())
    }

    /// Loopback alone.
    pub fn loopback(self) -> String {
        format!("127.0.0.1:{}", self.port())
    }
}
