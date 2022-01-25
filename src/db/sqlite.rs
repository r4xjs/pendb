use std::path::Path;

use sqlite::{self, Value, Connection};



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
                      domain TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS domain_unique_idx ON domain (domain, ip_id);

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

}




#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_table() {
	let db = Db::new(":memory:").unwrap();
	db.create_table().unwrap();
    }

    
}
