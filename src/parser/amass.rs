use serde::{Deserialize};
use serde_json::from_str;


//pub struct Amass {
//    pub entries: Vec<AmassEntry>,
//}


//impl Amass {
//    pub fn new::<T: AsRef<Path>>(path: T) -> Result<Self> {
//
//    }
//}



#[derive(Debug, Deserialize)]
pub struct AmassEntry {
    pub name: String,
    pub domain: String,
    pub addresses: Vec<Address>,
    pub tag: String,
    pub sources: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Address {
    pub ip: String,
    pub cidr: String,
    pub asn: u32,
    pub desc: String,
}





#[cfg(test)]
mod tests {
    use super::*;


    const AMASS_JSON: &str = r#"{"name":"1.thumbs.4chan.org","domain":"4chan.org","addresses":[{"ip":"104.19.129.108","cidr":"104.16.0.0/14","asn":13335,"desc":"CLOUDFLARENET - Cloudflare, Inc."},{"ip":"104.19.128.108","cidr":"104.16.0.0/14","asn":13335,"desc":"CLOUDFLARENET - Cloudflare, Inc."}],"tag":"api","sources":["AlienVault"]}
{"name":"blog.4chan.org","domain":"4chan.org","addresses":[{"ip":"74.114.154.18","cidr":"74.114.152.0/22","asn":2635,"desc":"AUTOMATTIC - Automattic, Inc"},{"ip":"74.114.154.22","cidr":"74.114.152.0/22","asn":2635,"desc":"AUTOMATTIC - Automattic, Inc"}],"tag":"api","sources":["AlienVault"]}
{"name":"4chan.org","domain":"4chan.org","addresses":[{"ip":"104.19.128.108","cidr":"104.16.0.0/14","asn":13335,"desc":"CLOUDFLARENET - Cloudflare, Inc."},{"ip":"104.19.129.108","cidr":"104.16.0.0/14","asn":13335,"desc":"CLOUDFLARENET - Cloudflare, Inc."}],"tag":"dns","sources":["DNS","AlienVault","SonarSearch"]}"#;

     #[test]
    fn parse_amass_address() {
	let addr_json = r#"{"ip":"74.114.154.18","cidr":"74.114.152.0/22","asn":2635,"desc":"AUTOMATTIC - Automattic, Inc"}"#;
	let addr: Address = from_str(&addr_json).unwrap();

	assert!(addr.ip == "74.114.154.18");
    }

   
    #[test]
    fn parse_amass_entry() {
	let entry_json = r#"{"name":"1.thumbs.4chan.org","domain":"4chan.org","addresses":[{"ip":"104.19.129.108","cidr":"104.16.0.0/14","asn":13335,"desc":"CLOUDFLARENET - Cloudflare, Inc."},{"ip":"104.19.128.108","cidr":"104.16.0.0/14","asn":13335,"desc":"CLOUDFLARENET - Cloudflare, Inc."}],"tag":"api","sources":["AlienVault"]}"#;


	let entry: AmassEntry = from_str(&entry_json).unwrap();
	assert!(entry.name == "1.thumbs.4chan.org");

    }

    #[test]
    fn parse_amass_entries() {

	let entries: Vec<AmassEntry> = AMASS_JSON.lines()
	    .map(|line| from_str(&line).unwrap())
	    .collect(); 
	assert!(entries.len() == 3);
	assert!(entries[2].name == "4chan.org");
	assert!(entries[2].addresses[0].ip == "104.19.128.108");

    }


}
