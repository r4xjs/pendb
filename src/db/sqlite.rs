use std::path::Path;

use sqlite::{self, Connection};
use sqlite::Value;

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
    amass_tag TEXT);
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
    state_reason TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS service_unique_idx ON service (ip, port); 

CREATE TABLE IF NOT EXISTS script (
    ip TEXT NOT NULL,
    port NUMERIC NOT NULL,
    script_id TEXT NOT NULL,
    script_output TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS script_unique_idx ON script (ip, port, script_id); 
")?;
	Ok(())
    }

    fn merge<'t>(old_row: &[Value], new_row: &[(&'t str, Value)]) -> Vec<(&'t str, Value)> {
	assert!(old_row.len() == new_row.len());
	vec![]
    }

    pub fn insert_nmap_scan(&self, nmap: Nmap) -> Result<u32> {
	// TODO: merge/update existing entries
	// 
	// if entry exist then goto update path, else insert new entry
	// update path:
	// - check which fields should be upated --> merge_heuristic(old_row, new_row) -> update_columns
	// - create single update stmt via --> update_service(update_columns)
	//   UPDATE service SET X = 1, Y = 2,.. WHERE ip = <ip> AND port = <port>;

	let mut counter = 0;
	let mut insert_service = self.conn.prepare(
	    "INSERT INTO service VALUES (:ip, :port, :protocol, :name, :product, :method, :conf, :state, :reason)")?
	    .into_cursor();
	let mut insert_script = self.conn.prepare("INSERT OR IGNORE INTO script VALUES (:ip, :port, :script_id, :script_output)")?
	    .into_cursor();
	let mut select_cursor = self.conn.prepare("SELECT * FROM service WHERE ip = :ip AND port = :port")?
	    .into_cursor();
	let mut update_service = self.conn.prepare(r#"
UPDATE service SET 
    ip = :ip, 
    port = :port, 
    protocol = :protocol, 
    service_name = :name, 
    service_product = :product, 
    service_method = :method, 
    service_conf = :conf, 
    state = :state, 
    state_reason = :reason  
WHERE ip = :ip AND port = :port"#)?.into_cursor();
	
	for host in nmap.hosts {
	    match host {
		RunElement::Host(host) => {
		    for port in &host.ports.ports {
			select_cursor.bind_by_name(vec![
			    (":ip", Value::String(host.address.addr.clone())),
			    (":port", Value::Integer(port.portid as i64))
			])?;
			let old_row = select_cursor.next()?;
			let new_row = vec![
				(":ip", Value::String(host.address.addr.clone())),
				(":port", Value::Integer(port.portid as i64)),
				(":protocol", Value::String(port.protocol.clone())),
				(":name", Value::String(port.service.name.clone())),
				(":product", Value::String(port.service.product.clone().unwrap_or("".into()))),
				(":method", Value::String(port.service.method.clone())),
				(":conf", Value::Integer(port.service.conf as i64)),
				(":state", Value::String(port.state.state.clone())),
				(":reason", Value::String(port.state.reason.clone())),
			];

			// insert or update service
			if old_row.is_none() {
			    // we have new data, just insert it
			    insert_service.bind_by_name(new_row)?;
			    counter += 1;
			    insert_service.next()?;
			} else {
			    // we already have the service in the db, merge and update the row
			    //assert!(select_cursor.next()?.is_none());
			    let old_row = old_row.unwrap();
			    let update_row = Db::merge(&old_row, &new_row);
			    update_service.bind_by_name(update_row)?;
			    update_service.next()?;
			}

			// insert script tags
			if let Some(ref scripts) = port.scripts {
			    for script in scripts {
				insert_script.bind_by_name(vec![
				    (":ip", Value::String(host.address.addr.clone())),
				    (":port", Value::Integer(port.portid as i64)),
				    (":script_id", Value::String(script.id.clone())),
				    (":script_output", Value::String(script.output.clone())),
				])?;
				insert_script.next()?;
			    }
			}
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
		    (":ip", Value::String(addr.ip.clone())),
		    (":domain", Value::String(entry.name.clone())),
		    (":cidr", Value::String(addr.cidr.clone())),
		    (":asn", Value::Integer(addr.asn as i64)),
		    (":description", Value::String(addr.desc.clone())),
		    (":amass_tag", Value::String(entry.tag.clone())),
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
    <port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="52"/><service name="http" product="OpenResty web app server" method="probed" conf="10"><cpe>cpe:/a:openresty:ngx_openresty</cpe></service><script id="http-methods" output="&#xa;  Supported Methods: GET HEAD POST OPTIONS"><table key="Supported Methods">
<elem>GET</elem>
<elem>HEAD</elem>
<elem>POST</elem>
<elem>OPTIONS</elem>
</table>
</script><script id="http-server-header" output="openresty"><elem>openresty</elem>
</script><script id="http-title" output="Not found."><elem key="title">Not found.</elem>
</script></port>
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
	//count.unwrap();
	assert!(count.is_ok());
	assert!(count.unwrap() == 4);

	let mut cursor = db.conn.prepare("SELECT ip, port, service_name, state FROM service").unwrap().into_cursor();
	let mut count = 0;
	while let Some(row) = cursor.next().unwrap() {
	    assert!(row[3].as_string() == "open".into());
	    count += 1;
	}
	assert!(count == 4);

	// check if we also have the script tags added to the db
	let mut cursor = db.conn.prepare(r#"
SELECT sc.ip, sc.port, sc.script_id, sc.script_output, s.service_name, s.state
FROM script as sc, service as s 
WHERE sc.ip = s.ip AND 
      sc.port = s.port
"#).unwrap().into_cursor();
	let script_ids = &["http-methods", "http-server-header", "http-title"];
	let mut count = 0;
	while let Some(row) = cursor.next().unwrap() {
	    assert!(script_ids.contains(&row[2].as_string().unwrap()));
	    count += 1; 
	}
	assert!(count == 3);
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
