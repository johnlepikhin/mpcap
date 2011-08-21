#include <pcap.h>

#include <stdio.h>
#include <string.h>

#include <caml/mlvalues.h>
#include <caml/fail.h>
#include <caml/callback.h>
#include <caml/memory.h>
#include <caml/alloc.h>

void raise_error (char *msg) {
	caml_raise_with_string (*caml_named_value ("mpcap_exn"), msg);
}

CAMLprim value
stub_pcap_open_live (value p_device, value p_snaplen)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device;
	int snaplen;
	pcap_t *ret;

	device = String_val (p_device);
	snaplen = Int_val (p_snaplen);

	ret = pcap_open_live (device, snaplen, 1, 0, errbuf);
	if (ret == NULL) {
		raise_error (errbuf);
	}

	return (value) ret;
}

CAMLprim value
stub_pcap_create (value p_device)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device;
	pcap_t *ret;

	device = String_val (p_device);

	ret = pcap_create (device, errbuf);
	if (ret == NULL) {
		raise_error (errbuf);
	}

	return (value) ret;
}

CAMLprim value
stub_pcap_close (value p_p)
{
	pcap_t *p;

	p = (pcap_t *) p_p;

	pcap_close (p);

	return Val_unit;
}

CAMLprim value
stub_pcap_set_buffer_size (value p_p, value p_size)
{
	int size;
	pcap_t *p;

	p = (pcap_t *) p_p;
	size = Int_val (p_size);

	if (pcap_set_buffer_size (p, size)) {
		raise_error ("Cannot set buffer size. Already activated");
	}

	return Val_unit;
}

CAMLprim value
stub_pcap_set_snaplen (value p_p, value p_size)
{
	int size;
	pcap_t *p;

	p = (pcap_t *) p_p;
	size = Int_val (p_size);

	if (pcap_set_snaplen (p, size)) {
		raise_error ("Cannot set snapshot length. Already activated");
	}

	return Val_unit;
}

CAMLprim value
stub_pcap_activate (value p_p)
{
	pcap_t *p;

	p = (pcap_t *) p_p;

	if (pcap_activate (p)) {
		raise_error (pcap_geterr (p));
	}

	return Val_unit;
}

CAMLprim value
stub_pcap_stats (value p_p)
{
	CAMLparam1 (p_p);
	CAMLlocal1 (ret);
	pcap_t *p;
	struct pcap_stat ps;

	p = (pcap_t *) p_p;

	if (pcap_stats(p, &ps)) {
		raise_error (pcap_geterr (p));
	}

	ret = caml_alloc (3, 0);

	Store_field (ret, 0, copy_int64 (ps.ps_recv));
	Store_field (ret, 1, copy_int64 (ps.ps_drop));
	Store_field (ret, 2, copy_int64 (ps.ps_ifdrop));

	CAMLreturn (ret);
}

CAMLprim value
stub_pcap_next (value p_p)
{
	CAMLparam1 (p_p);
	CAMLlocal2 (ret, ml_data);
	pcap_t *p;
	const u_char *packet;
	struct pcap_pkthdr header;

	p = (pcap_t *) p_p;

	packet = pcap_next(p, &header);

	if (packet == NULL) {
		raise_error ("No next packet received");
	}

	ret = caml_alloc (3, 0);

	Store_field (ret, 0, Val_int (header.len));
	Store_field (ret, 1, Val_int (header.caplen));

	ml_data = caml_alloc_string (header.caplen);
	memcpy (String_val(ml_data), packet, header.caplen);
	Store_field (ret, 2, ml_data);

	CAMLreturn (ret);
}
