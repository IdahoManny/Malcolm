module IANA_service;

@load base/frameworks/input

# Define key used to look up IANA service (proto + port)
type Iana_Service_Key: record {
  proto: string &optional;
  port: count &optional;
};

# Define the value structure (service name + description)
type Iana_Service_Value: record {
  service: string &optional;
  description: string &optional;
};

# Table to hold the lookup data
global iana_table: table[Iana_Service_Key] of Iana_Service_Value = table();

# Path to the IANA lookup table
global iana_map_filespec: string = @DIR + "/IANA_lookuptable.txt";

# Populate table on init
event zeek_init() {
  Input::add([
    name = "iana_lookup",
    reader = Input::READER_CSV,
    path = iana_map_filespec,
    mode = Input::REREAD,
    fields = {
      ["proto"] = "proto",
      ["dport"] = "port",
      ["sport"] = "unused",
      ["name"] = "service",
      ["category"] = "description"
    },
    ev = IANA_enrichment
  ]);
}

# Callback to load each line
event IANA_enrichment(rec: Input::CSV::Record) {
  local key: Iana_Service_Key = [$proto=rec["proto"], $port=to_count(rec["port"])];
  local val: Iana_Service_Value = [$service=rec["service"], $description=rec["description"]];
  iana_table[key] = val;
}

# Add to conn.log
redef record Conn::Info += {
  iana_service: string &log &optional;
  iana_description: string &log &optional;
};

# Do enrichment at end of connection
event connection_state_remove(c: connection) {
  local key: Iana_Service_Key = [$proto=fmt("%s", c$id$proto), $port=c$id$resp_p];
  if (key in iana_table) {
    c$iana_service = iana_table[key]$service;
    c$iana_description = iana_table[key]$description;
  }
}
