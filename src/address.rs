
#[derive(Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct ProtocolAddress {
    name: String,
    device_id: u32
}

impl ProtocolAddress {

    pub fn new(name: String, device_id: u32) -> Self {
        ProtocolAddress { name, device_id }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn device_id(&self) -> u32 {
        self.device_id
    }

}
