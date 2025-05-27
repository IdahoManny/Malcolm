module SimpleEnrich;

export {
  redef enum Log::ID += { LOG };

  type Simple_Info: record {
    fun_service: string &log &optional;
    fun_description: string &log &optional;
  };
}

type Simple_Key: record {
  proto: transport_proto;
  dport: count;
  sport: count;
};

global simple_table: table[Simple_Key] of Simple_Info = table();

event zeek_init() {
  Input::add_table([
    $source = fmt("%s/Simple_lookuptable.txt", @DIR),
    $name = "simple_map",
    $idx = Input::INDEX_VAL,
    $reader = Input::READER_TAB,
    $mode = Input::MODE_MANUAL,
    $fields = {
      ["proto"] = Input::READER_STRING,
      ["dport"] = Input::READER_COUNT,
      ["sport"] = Input::READER_COUNT,
      ["name"] = Input::READER_STRING,
      ["description"] = Input::READER_STRING
    },
    $set = function(rec: Input::Record) {
      local key: Simple_Key = [$proto=rec["proto"] == "tcp" ? tcp : udp, $dport=rec["dport"], $sport=rec["sport"]];
      simple_table[key] = [$fun_service=rec["name"], $fun_description=rec["description"]];
    }
  ]);
}

event Conn::log_conn(rec: Conn::Info) {
  local key: Simple_Key = [$proto=rec$id$proto, $dport=rec$id$resp_p, $sport=rec$id$orig_p];
  if ( key in simple_table ) {
    local info = simple_table[key];
    rec["fun_service"] = info$fun_service;
    rec["fun_description"] = info$fun_description;
  }
}
