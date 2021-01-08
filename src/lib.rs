// Copyright 2018-2021 pwrdwnsys.
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Lookup MAC/EUI48 OUI vendor name information from the [Wireshark manufacturer database](https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf).
//!
//! This library allows you to provide a MAC/EUI48 address and returns information
//! on the vendor registered to the [Organizationally Unique Identifier (OUI)](https://en.wikipedia.org/wiki/Organizationally_unique_identifier)
//! component of the supplied address. For each entry in the Wireshark database, this will be at a minimum the
//! vendor's Wireshark short name, but most entries include the full organization/company name
//! and some also include a descriptive comment.
//! 
//! Where IEEE Registration Authority blocks have been sub-divided, the specific manufacturer is returned. Note 
//! that a vendor/organization may have been allocated multiple blocks by the IEEE - these are each treated 
//! independently, should a vendor sub-division be later re-allocated or renamed following acquisition.
//!
//! Example wget command to download the manufacturer database:
//! `wget -O manuf.txt 'https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf'`
//!

#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;

use byteorder::{NetworkEndian, ReadBytesExt};
use eui48::MacAddress;
use failure::{Error, ResultExt};
use regex::Regex;

type OuiMap = BTreeMap<(u64, u64), OuiEntry>;

/// OUI entry
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct OuiEntry {
    /// Wireshark's short name identifier for the organization [REQUIRED]
    pub name_short: String,
    /// Organization full name (usually present) [OPTIONAL]
    pub name_long: Option<String>,
    /// Wireshark comment field [OPTIONAL]
    pub comment: Option<String>,
}

impl Default for OuiEntry {
    fn default() -> OuiEntry {
        OuiEntry {
            name_short: String::new(),
            name_long: None,
            comment: None,
        }
    }
}

/// OUI Database
pub struct OuiDatabase {
    database: OuiMap,
}

impl OuiDatabase {
    /// Create a new database from a Wireshark database file
    pub fn new_from_file(dbfile: &str) -> Result<OuiDatabase, Error> {
        let db = create_oui_db_from_file(dbfile)?;
        info!("Created a new OUI Vendor database from file {}", dbfile);
        Ok(OuiDatabase { database: db })
    }

    /// Create a new database from a previously exported `Vec<u8>`
    pub fn new_from_export(data: &[u8]) -> Result<OuiDatabase, Error> {
        let deserialized = bincode::deserialize(data).context("could not deserialize data")?;
        info!("Created a new OUI Vendor database from previously exported data");
        Ok(OuiDatabase {
            database: deserialized,
        })
    }

    /// Export the database to a `Vec<u8>` of bincode bytes
    pub fn export(&self) -> Result<Vec<u8>, Error> {
        let data = bincode::serialize(&self.database).context("could not serialize database")?;
        info!("Created a dump of the OUI Vendor database for export");
        Ok(data)
    }

    /// Query the database by `Eui48::MacAddress`
    pub fn query_by_mac(&self, mac_addr: &MacAddress) -> Result<Option<OuiEntry>, Error> {
        let mac_int = mac_to_u64(mac_addr)?;
        debug!(
            "Querying OUI Vendor database for {:?} ({})",
            mac_addr, mac_int
        );
        self.query(&mac_int)
    }

    /// Query the database by `&str`
    pub fn query_by_str(&self, mac_str: &str) -> Result<Option<OuiEntry>, Error> {
        let mac_addr = MacAddress::parse_str(&mac_str)
            .context(format!("could not parse MAC address from str: {}", mac_str))?;
        self.query_by_mac(&mac_addr)
    }

    /// Returns total number of entries in the database as `usize`
    pub fn len(&self) -> usize {
        self.database.len()
    }

    /// Returns true if there are zero entries in the database, or false for 1+ entries
    pub fn is_empty(&self) -> bool {
        self.database.is_empty()
    }

    /// Queries the database using a u64 representation from the wrapper query functions
    fn query(&self, query: &u64) -> Result<Option<OuiEntry>, Error> {
        // It is possible to have multiple matches for a MAC - this is owing to the
        // IEEE Registration Authority sub-dividing blocks down for new vendors, which
        // results in the first hit being against the larger block, then the manufacturer
        // specific block matching afterwards. There should never (?!) be more than two matches,
        // so we'll use the second one if it exists as this wil be the exact manufacturer.
        let mut results = Vec::<((u64, u64), OuiEntry)>::new();

        for ((lo, hi), value) in &self.database {
            if query >= lo && query <= hi {
                results.push(((*lo, *hi), value.clone()));
            }
        }

        if results.len() > 2 {
            return Err(format_err!(
                "more than two oui matches - possible database error? {:?}",
                results
            ));
        }
        // Get the last value from the search, and return it
        match results.pop() {
            Some(oui_res) => Ok(Some(oui_res.1)),
            _ => Ok(None),
        }
    }
}

/// Converts a MAC Address to a u64 value
fn mac_to_u64(mac: &MacAddress) -> Result<u64, Error> {
    let mac_bytes = mac.as_bytes();

    let padded = vec![
        0,
        0,
        mac_bytes[0],
        mac_bytes[1],
        mac_bytes[2],
        mac_bytes[3],
        mac_bytes[4],
        mac_bytes[5],
    ];

    let mut padded_mac = &padded[..8];
    let mac_num = padded_mac.read_u64::<NetworkEndian>().context(format!(
        "could not read_u64 from padded MAC byte array: {:?}",
        padded_mac
    ))?;
    Ok(mac_num)
}

/// Opens and parses a Wireshark data file into a `OuiMap`
fn create_oui_db_from_file(dbfile: &str) -> Result<OuiMap, Error> {
    let file = File::open(dbfile).context(format!("could not open database file: {}", dbfile))?;
    let re = Regex::new("[\t]+").context("could not compile regex")?;

    let mut vendor_data = OuiMap::new();

    for line in BufReader::new(file).lines() {
        let entry = line.context("could not get data line")?;
        // Only process lines with data
        if !(entry.starts_with('#') || entry.is_empty()) {
            let data = re.replace_all(&entry, "|");
            let fields_raw: Vec<&str> = data.split('|').collect();
            let fields_cleaned: Vec<_> = fields_raw
                .into_iter()
                .map(|field| {
                    // Clean up (for comment field)
                    let f = field.replace('#', "");
                    f.trim().to_owned()
                })
                .collect();

            if !(fields_cleaned.len() >= 2 && fields_cleaned.len() <= 4) {
                return Err(format_err!(
                    "unexpected number of fields extracted: {:?}",
                    fields_cleaned
                ));
            }

            let mask: u8;

            let oui_and_mask: Vec<_> = fields_cleaned[0].split('/').collect();
            match oui_and_mask.len() {
                1 => mask = 24,
                2 => {
                    mask = u8::from_str_radix(&oui_and_mask[1], 10)
                        .context(format!("could not parse mask: {}", &oui_and_mask[1]))?;
                    if !(mask >= 8 && mask <= 48) {
                        return Err(format_err!("incorrect mask value: {}", mask));
                    }
                }
                _ => {
                    return Err(format_err!(
                        "invalid number of mask separators: {:?}",
                        oui_and_mask
                    ))
                }
            };

            // Get the whole MAC string
            let oui = oui_and_mask[0]
                .to_owned()
                .to_uppercase()
                .replace(":", "")
                .replace("-", "")
                .replace(".", "");
            let oui_int = u64::from_str_radix(&oui, 16)
                .context(format!("could not parse stripped OUI: {}", oui))?;

            // If it's a 24-bit mask (undecorated default), shift over as non-24
            // pads are fully written out in the file.
            let oui_start: u64;
            if mask == 24 {
                oui_start = oui_int << 24;
            } else {
                oui_start = oui_int
            };

            // Find the end of this OUI entry range
            let oui_end: u64 = oui_start | 0xFFFF_FFFF_FFFF >> mask;

            // 4 fields, so has a "comment"
            let comment: Option<String>;
            if fields_cleaned.len() == 4 {
                comment = Some(fields_cleaned[3].to_owned())
            } else {
                comment = None
            }

            // 3 fields, so has a "long name"
            let name_long: Option<String>;
            if fields_cleaned.len() >= 3 {
                name_long = Some(fields_cleaned[2].to_owned())
            } else {
                name_long = None
            }

            // second field is the "short name"
            let name_short: String = fields_cleaned[1].to_owned();

            let entry_data = OuiEntry {
                name_short,
                name_long,
                comment,
            };

            trace!(
                "Inserting entry for vendor: Range {}-{} is {:?}",
                oui_start,
                oui_end,
                entry_data
            );
            vendor_data.insert((oui_start, oui_end), entry_data);
        };
    }

    Ok(vendor_data)
}
