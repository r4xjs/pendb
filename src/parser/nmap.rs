use serde::{Deserialize};

// <nmaprun scanner="nmap"
//    args="nmap -sTV -iL ips.lst -oA asdf"
//    start="1643060432"
//    startstr="Mon Jan 24 21:40:32 2022"
//    version="7.92"
//    xmloutputversion="1.05">
#[derive(Debug, Deserialize)]
pub struct NmapRun {
    pub args: String,
    pub start: u32,
    pub startstr: String,
    pub version: String,
    pub xmloutputversion: f32,
    #[serde(rename = "host", default)]
    pub hosts: Vec<Host>,
}

#[derive(Debug, Deserialize)]
pub struct Host {
    pub starttime: u32,
    pub endtime: u32,
    pub address: Address,
    pub ports: Ports,
}
#[derive(Debug, Deserialize)]
pub struct Ports {
    #[serde(rename = "port", default)]
    pub ports: Vec<Port>,
}

// <address addr="104.19.128.108" addrtype="ipv4"/>
#[derive(Debug, Deserialize)]
pub struct Address {
    pub addr: String,
    pub addrtype: String,
}

// <status state="up" reason="syn-ack" reason_ttl="0"/>
#[derive(Debug, Deserialize)]
pub struct Status {
    pub state: String,
    pub reason: String,
    pub reason_ttl: u32,
}

// <service name="http" product="Cloudflare http proxy" method="probed" conf="10"/>
#[derive(Debug, Deserialize)]
pub struct Service {
    pub name: String,
    pub product: String,
    pub method: String,
    pub conf: u32,
}

// <port protocol="tcp" portid="80">
//   <state state="open" reason="syn-ack" reason_ttl="0"/>
//   <service name="http" product="Cloudflare http proxy" method="probed" conf="10"/>
// </port>
#[derive(Debug, Deserialize)]
pub struct Port {
    pub protocol: String,
    pub portid: u32,
    pub state: Status,
    pub service: Service,
}


#[cfg(test)]
mod tests {
    use super::*;
    use serde_xml_rs::from_str;

    #[test]
    fn parse_address() {
	let addr_str = r#"<address addr="104.19.128.108" addrtype="ipv4"/>"#;
	let addr: Address = from_str(&addr_str).unwrap();
	assert!(addr.addr == "104.19.128.108");
	assert!(addr.addrtype == "ipv4");
    }

    #[test]
    fn parse_status() {
	let xml = r#"
<status state="up" reason="syn-ack" reason_ttl="0"/>
"#;
	let status: Status = from_str(&xml).unwrap();
	assert!(status.state == "up");

    }


    #[test]
    fn parse_port() {
	let xml = r#"
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack" reason_ttl="0"/>
<service name="http" product="Cloudflare http proxy" method="probed" conf="10"/>
</port>
"#;
	let port: Port = from_str(&xml).unwrap();
	assert!(port.protocol == "tcp");
	assert!(port.portid == 80);
	assert!(port.state.state == "open");
	assert!(port.service.name == "http");
    }

    #[test]
    fn parse_host() {
	let xml = r#"
<host starttime="1643060432" endtime="1643060451">
<status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="104.19.128.108" addrtype="ipv4"/>
<ports>
    <!-- <port protocol="tcp" portid="80">
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
    </port> -->
</ports>
</host>
"#;
	let host: Host = from_str(&xml).unwrap();
	assert!(host.address.addr == "104.19.128.108");
	assert!(host.address.addrtype == "ipv4");
	assert!(host.starttime == 1643060432);
	assert!(host.endtime == 1643060451);
	for port in &host.ports.ports {
	    assert!(port.protocol == "tcp");
	    assert!(port.service.name == "http");
	}
    }

    #[test]
    fn parse_nmap_run() {
	let xml = r#"
<nmaprun scanner="nmap" args="nmap -sTV -iL ips.lst -oA asdf" start="1643060432" startstr="Mon Jan 24 21:40:32 2022" version="7.92" xmloutputversion="1.05">

<host starttime="1643060432" endtime="1643060451">
<status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="104.19.128.108" addrtype="ipv4"/>
<ports>
    <!-- <port protocol="tcp" portid="80">
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
    </port> -->
</ports>
</host>
</nmaprun>
"#;
	let nmap_run: NmapRun= from_str(&xml).unwrap();
	assert!(nmap_run.hosts.len() == 1);
	for host in &nmap_run.hosts {
	    for port in &host.ports.ports {
		assert!(port.protocol == "tcp");
		assert!(port.service.name == "http");
	    }
	}
    }


}
