use std::path::Path;

use sqlite::{self, Connection};
use sqlite::Value::{Integer, String};

use crate::parser::nmap::*;
use crate::parser::amass::*;



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

    pub fn insert_nmap_scan(&self, nmap: Nmap) -> Result<u32> {
	// TODO: merge/update existing entries

	let mut cursor = self.conn.prepare(
	    "INSERT INTO service VALUES (:ip, :port, :service, :name, :prod, :method, :conf, :state, :reason)")?
	    .into_cursor();
	let mut counter = 0;
	for host in nmap.hosts {
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


    pub fn insert_amass_scan(&self, amass: Amass) -> Result<u32> {
	// TODO: merge/update existing entries

	let mut cursor = self.conn.prepare(
	    "INSERT INTO domain VALUES (:ip, :domain, :cidr, :asn, :description, :amass_tag)")?
	    .into_cursor();
	let mut counter = 0;
	for entry in &amass.entries {
	    for addr in &entry.addresses { 
		cursor.bind_by_name(vec![
		    (":ip", String(addr.ip.clone())),
		    (":domain", String(entry.name.clone())),
		    (":cidr", String(addr.cidr.clone())),
		    (":asn", Integer(addr.asn as i64)),
		    (":description", String(addr.desc.clone())),
		    (":amass_tag", String(entry.tag.clone())),
		])?;
		counter += 1;
		cursor.next()?;
	    }
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
    const AMASS_JSON: &str = r#"{"name":"1.thumbs.4chan.org","domain":"4chan.org","addresses":[{"ip":"104.19.129.108","cidr":"104.16.0.0/14","asn":13335,"desc":"CLOUDFLARENET - Cloudflare, Inc."},{"ip":"104.19.128.108","cidr":"104.16.0.0/14","asn":13335,"desc":"CLOUDFLARENET - Cloudflare, Inc."}],"tag":"api","sources":["AlienVault"]}
{"name":"blog.4chan.org","domain":"4chan.org","addresses":[{"ip":"74.114.154.18","cidr":"74.114.152.0/22","asn":2635,"desc":"AUTOMATTIC - Automattic, Inc"},{"ip":"74.114.154.22","cidr":"74.114.152.0/22","asn":2635,"desc":"AUTOMATTIC - Automattic, Inc"}],"tag":"api","sources":["AlienVault"]}
{"name":"4chan.org","domain":"4chan.org","addresses":[{"ip":"104.19.128.108","cidr":"104.16.0.0/14","asn":13335,"desc":"CLOUDFLARENET - Cloudflare, Inc."},{"ip":"104.19.129.108","cidr":"104.16.0.0/14","asn":13335,"desc":"CLOUDFLARENET - Cloudflare, Inc."}],"tag":"dns","sources":["DNS","AlienVault","SonarSearch"]}"#;



    #[test]
    fn create_table() {
	let db = Db::new(":memory:").unwrap();
	assert!(db.create_table().is_ok());
    }

    #[test]
    fn insert_nmap_scan() {
	let db = Db::new(":memory:").unwrap();
	db.create_table().unwrap();

	let nmap = Nmap::new(NMAP_XML.as_bytes()).unwrap();
	let count = db.insert_nmap_scan(nmap);
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

    #[test]
    fn insert_amass_scan() {
	let db = Db::new(":memory:").unwrap();
	db.create_table().unwrap();

	let amass = Amass::new(AMASS_JSON.as_bytes()).unwrap();
	let count = db.insert_amass_scan(amass);
	assert!(&count.is_ok());
	assert!(count.unwrap() == 6);

	let mut cursor = db.conn.prepare("SELECT ip, domain, cidr, asn, description, amass_tag FROM domain WHERE domain = '4chan.org'")
	    .unwrap()
	    .into_cursor();
	let mut count = 0;
	while let Some(row) = cursor.next().unwrap() {
	    assert!(row[1].as_string().unwrap() == "4chan.org");
	    assert!(row[3].as_integer().unwrap() == 13335);
	    count += 1;
	}
	assert!(count == 2);
    }

   
}
