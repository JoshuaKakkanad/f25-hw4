"""
resolve.py: a recursive resolver built using dnspython
"""

import argparse

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

# current as of 25 October 2018
ROOT_SERVERS = ("198.41.0.4",
                "199.9.14.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")


def collect_results(name: str) -> dict:
    """
    This function parses final answers into the proper data structure that
    print_results requires. The main work is done within the `lookup` function.
    """
    full_response = {}
    target_name = dns.name.from_text(name)
    # lookup CNAME
    response = lookup(target_name, dns.rdatatype.CNAME)
    cnames = []
    tmp = name
    for answers in response.answer:
        for answer in answers:
            cnames.append({"name": answer, "alias": tmp})
            tmp = answer
    # lookup A
    response = lookup(target_name, dns.rdatatype.A)
    arecords = []
    for answers in response.answer:
        a_name = answers.name
        for answer in answers:
            if answer.rdtype == 1:  # A record
                arecords.append({"name": a_name, "address": str(answer)})
    # lookup AAAA
    response = lookup(target_name, dns.rdatatype.AAAA)
    aaaarecords = []
    for answers in response.answer:
        aaaa_name = answers.name
        for answer in answers:
            if answer.rdtype == 28:  # AAAA record
                aaaarecords.append({"name": aaaa_name, "address": str(answer)})
    # lookup MX
    response = lookup(target_name, dns.rdatatype.MX)
    mxrecords = []
    for answers in response.answer:
        mx_name = answers.name
        for answer in answers:
            if answer.rdtype == 15:  # MX record
                mxrecords.append({"name": mx_name,
                                  "preference": answer.preference,
                                  "exchange": str(answer.exchange)})

    full_response["CNAME"] = cnames
    full_response["A"] = arecords
    full_response["AAAA"] = aaaarecords
    full_response["MX"] = mxrecords

    return full_response


# Global cache for answers and intermediate results
CACHE = {}

def lookup(target_name: dns.name.Name, qtype: dns.rdata.Rdata) -> dns.message.Message:
    """
    A fully recursive DNS resolver that starts from root servers and resolves
    the given name without using any recursive resolver.
    Includes caching, CNAME handling, and timeout/error handling.
    """

    def cached_lookup(name_text, qtype_val):
        key = (name_text.lower(), qtype_val)
        return CACHE.get(key)

    def cache_store(name_text, qtype_val, response):
        key = (name_text.lower(), qtype_val)
        CACHE[key] = response

    def send_query(server_ip, qname, qtype_val):
        try:
            query = dns.message.make_query(qname, qtype_val)
            return dns.query.udp(query, server_ip, timeout=3)
        except Exception:
            return None

    def extract_ns_ips(response):
        """Extract NS target names and any glue A records if available."""
        ns_names = []
        glue_ips = {}
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NS:
                for rr in rrset:
                    ns_names.append(str(rr.target).rstrip("."))
        for rrset in response.additional:
            if rrset.rdtype == dns.rdatatype.A:
                glue_ips[str(rrset.name).rstrip(".")] = [str(rr.address) for rr in rrset]
        return ns_names, glue_ips

    def resolve_ns_ip(ns_name):
        """Resolve the A record for a nameserver (unglued)."""
        if (ns_name.lower(), dns.rdatatype.A) in CACHE:
            resp = CACHE[(ns_name.lower(), dns.rdatatype.A)]
            if resp.answer:
                for rrset in resp.answer:
                    if rrset.rdtype == dns.rdatatype.A:
                        return [str(rr.address) for rr in rrset]
        # Resolve recursively
        ns_resp = lookup(dns.name.from_text(ns_name), dns.rdatatype.A)
        if ns_resp and ns_resp.answer:
            for rrset in ns_resp.answer:
                if rrset.rdtype == dns.rdatatype.A:
                    return [str(rr.address) for rr in rrset]
        return []

    def recursive_resolve(name_obj, qtype_val):
        name_text = str(name_obj).rstrip(".")
        cached = cached_lookup(name_text, qtype_val)
        if cached:
            return cached

        # start from roots
        next_servers = list(ROOT_SERVERS)

        while True:
            found_response = None
            for server in next_servers:
                response = send_query(server, name_obj, qtype_val)
                if response is None:
                    continue

                # if we got an answer, check if it’s final
                if response.answer:
                    found_response = response
                    break

                # otherwise, get new NS
                ns_names, glue_ips = extract_ns_ips(response)
                if not ns_names:
                    continue

                new_servers = []
                for ns in ns_names:
                    if ns in glue_ips:
                        new_servers.extend(glue_ips[ns])
                    else:
                        resolved_ips = resolve_ns_ip(ns)
                        new_servers.extend(resolved_ips)
                if new_servers:
                    next_servers = new_servers
                    break
            else:
                # if no servers responded
                return dns.message.make_response(dns.message.make_query(name_obj, qtype_val))

            if found_response:
                # handle CNAME restarts
                cname_target = None
                for rrset in found_response.answer:
                    if rrset.rdtype == dns.rdatatype.CNAME:
                        cname_target = str(rrset[0].target)
                        cname_resp = recursive_resolve(dns.name.from_text(cname_target), qtype_val)
                        # merge CNAME chain + final answer
                        combined = dns.message.make_response(
                            dns.message.make_query(name_obj, qtype_val)
                        )
                        combined.answer = found_response.answer + cname_resp.answer
                        cache_store(name_text, qtype_val, combined)
                        return combined

                # cache and return
                cache_store(name_text, qtype_val, found_response)
                return found_response

    # main recursive call
    try:
        return recursive_resolve(target_name, qtype)
    except Exception:
        # graceful failure (never crash)
        return dns.message.make_response(dns.message.make_query(target_name, qtype))



def print_results(results: dict) -> None:
    """
    take the results of a `lookup` and print them to the screen like the host
    program would.
    """

    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))


def main():
    """
    if run from the command line, take args and call
    printresults(lookup(hostname))
    """
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")
    argument_parser.add_argument("-v", "--verbose",
                                 help="increase output verbosity",
                                 action="store_true")
    program_args = argument_parser.parse_args()
    for a_domain_name in program_args.name:
        print_results(collect_results(a_domain_name))

if __name__ == "__main__":
    main()
