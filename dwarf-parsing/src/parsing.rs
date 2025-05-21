use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_hex::{CompactPfx, SerHex};

use crate::module_map::ModuleMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct DiscovererJson {
    #[serde(with = "serde_functions")]
    pub functions: HashMap<u64, Vec<u64>>,
    pub modules: ModuleMap,
}

#[derive(Eq, Hash, PartialEq)]
struct HexU64(u64);

impl<'de> Deserialize<'de> for HexU64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let num: u64 = SerHex::<CompactPfx>::deserialize(deserializer)?;
        Ok(HexU64(num))
    }
}

impl Serialize for HexU64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let num = self.0;
        SerHex::<CompactPfx>::serialize(&num, serializer)
    }
}

impl From<u64> for HexU64 {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl Into<u64> for HexU64 {
    fn into(self) -> u64 {
        self.0
    }
}

pub mod serde_functions {
    use serde::{Deserializer, Serializer};
    use std::{collections::HashMap, iter::FromIterator};

    use super::HexU64;

    pub fn serialize<'a, T, S>(target: T, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: IntoIterator<Item = (&'a u64, &'a Vec<u64>)>,
    {
        let container: HashMap<_, _> = target.into_iter().collect();
        serde::Serialize::serialize(&container, ser)
    }

    pub fn deserialize<'de, T, D>(des: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: FromIterator<(u64, Vec<u64>)>,
    {
        let container: HashMap<HexU64, Vec<HexU64>> = serde::Deserialize::deserialize(des)?;
        let iter = container
            .into_iter()
            .map(|(k, v)| return (k.into(), v.into_iter().map(|v| v.into()).collect()));
        Ok(T::from_iter(iter))
    }
}

pub fn hex_to_num(s: &str) -> Option<u64> {
    let s = s.trim_start_matches("0x");
    u64::from_str_radix(s, 16).ok()
}
