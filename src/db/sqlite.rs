use std::path::Path;

use sqlite::{self, Connection};
use sqlite::Value::{Integer, String};

use crate::parser::nmap::*;



type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct Db {
   pub conn: Connection
}

impl Db {
    pub fn new<T: AsRef<Path>>(path: T) -> Result<Self> {
	Ok(Self {
	    conn: sqlite::open(&path)?,
	})
    }

    pub fn create_table(&self) -> Result<()> {
	self.conn.execute("
CREATE TABLE IF NOT EXISTS domain  (
ip TEXT NOT NULL,
domain TEXT NOT NULL,
cidr TEXT,
asn NUMERIC,
description TEXT,
amass_tag TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS domain_unique_idx ON domain (domain, ip);

CREATE TABLE IF NOT EXISTS service (
ip TEXT NOT NULL, 
port NUMERIC NOT NULL, 
protocol TEXT,
service_name TEXT, 
service_product TEXT,
service_method TEXT, 
service_conf NUMERIC,
state TEXT,
state_reason TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS service_unique_idx ON service (ip, port); 
")?;
	Ok(())
    }

    pub fn insert_nmap_scan(&self, nmap: &NmapRun) -> Result<u32> {
	// TODO: merge/update excisting entries

	let mut cursor = self.conn.prepare(
	    "INSERT INTO service VALUES (:ip, :port, :service, :name, :prod, :method, :conf, :state, :reason)")?
	    .into_cursor();
	let mut counter = 0;
	for host in &nmap.hosts {
	    match host {
		RunElement::Host(host) => {
		    for port in &host.ports.ports {
			cursor.bind_by_name(vec![
			    (":ip", String(host.address.addr.clone())),
			    (":port", Integer(port.portid as i64)),
			    (":service", String(port.protocol.clone())),
			    (":name", String(port.service.name.clone())),
			    (":prod", String(port.service.product.clone().unwrap_or("".into()))),
			    (":method", String(port.service.method.clone())),
			    (":conf", Integer(port.service.conf as i64)),
			    (":state", String(port.state.state.clone())),
			    (":reason", String(port.state.reason.clone())),
			])?;
			counter += 1;
			cursor.next()?;
		    }
		},
		_ => continue,
	    };
	}
	Ok(counter)
    }

}




#[cfg(test)]
mod tests {
    use super::*;
    use serde_xml_rs::from_str;
    

    const NMAP_XML: &str = r#"
<nmaprun scanner="nmap" args="nmap -sTV -iL ips.lst -oA asdf" start="1643060432" startstr="Mon Jan 24 21:40:32 2022" version="7.92" xmloutputversion="1.05">

<host starttime="1643060432" endtime="1643060451">
<status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="104.19.128.108" addrtype="ipv4"/>
<ports>
    <port protocol="tcp" portid="80">
    	<state state="open" reason="syn-ack" reason_ttl="0"/>
    	<service name="http" product="Cloudflare http proxy" method="probed" conf="10"/>
    </port>
    <port protocol="tcp" portid="443">
    	<state state="open" reason="syn-ack" reason_ttl="0"/>
    	<service name="http" product="Cloudflare http proxy" tunnel="ssl" method="probed" conf="10"/>
    </port>
    <port protocol="tcp" portid="8080">
    	<state state="open" reason="syn-ack" reason_ttl="0"/>
    	<service name="http" product="Cloudflare http proxy" method="probed" conf="10"/>
    </port>
    <port protocol="tcp" portid="8443">
    	<state state="open" reason="syn-ack" reason_ttl="0"/>
    	<service name="http" product="Cloudflare http proxy" tunnel="ssl" method="probed" conf="10"/>
    </port>
</ports>
</host>
</nmaprun>
"#;
	

    #[test]
    fn create_table() {
	let db = Db::new(":memory:").unwrap();
	assert!(db.create_table().is_ok());
    }

    #[test]
    fn insert_nmap_scan() {
	let db = Db::new(":memory:").unwrap();
	db.create_table().unwrap();

	let nmap = from_str::<NmapRun>(&NMAP_XML).unwrap();
	let count = db.insert_nmap_scan(&nmap);
	assert!(count.is_ok());
	assert!(count.unwrap() == 4);

	let mut cursor = db.conn.prepare("SELECT ip, port, service_name, state FROM service").unwrap().into_cursor();
	let mut count = 0;
	while let Some(row) = cursor.next().unwrap() {
	    assert!(row[3].as_string() == "open".into());
	    count += 1;
	}
	assert!(count == 4);
	
    }

    
}
