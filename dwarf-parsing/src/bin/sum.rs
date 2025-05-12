use std::{collections::HashMap, fs::read_to_string};

use anyhow::Context;

fn main() -> anyhow::Result<()> {
    let path = "../data/symbols3.json";
    let text = read_to_string(path)?;
    let value: HashMap<String, serde_json::Value> = serde_json::from_str(&text)?;

    let mut sum = 0;
    for (_, count) in value {
        let count = count.as_number().context("")?.as_u64().context("")?;
        sum += count;
    }

    println!("Sum: {sum}");
    Ok(())
}
