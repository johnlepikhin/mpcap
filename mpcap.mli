exception Error of string

type handle

type packet = {
	len : int;
	caplen : int;
	data : string;
}

module Stats : sig
	type t = {
		recv : int64;
		drop : int64;
		ifdrop : int64;
	}
	
	external get : handle -> t = "stub_pcap_stats"
end

external create : string -> handle = "stub_pcap_create"

external open_live : string -> int -> handle = "stub_pcap_open_live"

external close : handle -> unit = "stub_pcap_close"

external set_buffer_size : handle -> int -> unit = "stub_pcap_set_buffer_size"

external set_snaplen : handle -> int -> unit = "stub_pcap_set_snaplen"

external activate : handle -> unit = "stub_pcap_activate"

external next : handle -> packet = "stub_pcap_next"
