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

_LAST_NAMESERVERS = list(ROOT_SERVERS)

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


# Global cache (simple dict)
CACHE = {}

def lookup(target_name: dns.name.Name,
           qtype: dns.rdata.Rdata) -> dns.message.Message:
    """
    Recursive DNS resolver with caching, CNAME handling, unglued NS resolution,
    and intermediate caching for efficiency.
    """
    global _LAST_NAMESERVERS

    key = (str(target_name), qtype)
    if key in CACHE:
        return CACHE[key]

    # --- NEW: Try to reuse cached NS records for parent zones ---
    parent = target_name
    while parent.labels:
        parent = parent.parent()
        ns_key = (str(parent), dns.rdatatype.NS)
        if ns_key in CACHE:
            ns_resp = CACHE[ns_key]
            next_ns_ips = []
            for rrset in getattr(ns_resp, "authority", []):
                if rrset.rdtype == dns.rdatatype.NS:
                    for rr in rrset:
                        ns_name = str(rr.target)
                        a_key = (ns_name, dns.rdatatype.A)
                        if a_key in CACHE:
                            a_resp = CACHE[a_key]
                            for aset in getattr(a_resp, "answer", []):
                                if aset.rdtype == dns.rdatatype.A:
                                    for rr2 in aset:
                                        ipv4 = str(rr2)
                                        if ":" not in ipv4 and ipv4 not in next_ns_ips:
                                            next_ns_ips.append(ipv4)
            if next_ns_ips:
                _LAST_NAMESERVERS = list(next_ns_ips)
                break
    # --- END NEW BLOCK ---

    nameservers = list(_LAST_NAMESERVERS)
    tried = set()
    fail_count = 0
    MAX_FAILS = 4

    while nameservers:
        for ns in nameservers:
            if ns in tried:
                continue
            tried.add(ns)

            try:
                query = dns.message.make_query(target_name, qtype)
                response = dns.query.udp(query, ns, timeout=3)
                fail_count = 0
            except Exception:
                fail_count += 1
                if fail_count >= MAX_FAILS:
                    _LAST_NAMESERVERS = list(ROOT_SERVERS)
                    nameservers = list(ROOT_SERVERS)
                    fail_count = 0
                continue

            # --- Case 1: Direct Answer ---
            if response.answer:
                _LAST_NAMESERVERS = [ns]
                for rrset in response.answer:
                    # --- Handle CNAME Restart ---
                    if rrset.rdtype == dns.rdatatype.CNAME:
                        cname_target = rrset[0].target
                        cname_response = lookup(cname_target, qtype)
                        a_response = lookup(cname_target, dns.rdatatype.A)
                        aaaa_response = lookup(cname_target, dns.rdatatype.AAAA)

                        merged = dns.message.make_response(query)
                        merged.answer.extend(response.answer)
                        merged.answer.extend(cname_response.answer)
                        merged.answer.extend(a_response.answer)
                        merged.answer.extend(aaaa_response.answer)

                        CACHE[(str(target_name), dns.rdatatype.CNAME)] = response
                        CACHE[key] = merged
                        return merged

                CACHE[key] = response
                return response

            # --- Case 2: Referral (with or without glue) ---
            next_ns_ips = []

            # Collect glue (A records in additional)
            for rrset in response.additional:
                if rrset.rdtype == dns.rdatatype.A:
                    for rr in rrset:
                        ipv4 = str(rr)
                        if ipv4 not in next_ns_ips:
                            next_ns_ips.append(ipv4)
                            CACHE[(str(rrset.name), dns.rdatatype.A)] = rr

            # Collect NS names if no glue provided
            ns_names = []
            for rrset in response.authority:
                if rrset.rdtype == dns.rdatatype.NS:
                    for rr in rrset:
                        ns_name = str(rr.target)
                        if ns_name not in ns_names:
                            ns_names.append(ns_name)
                    # Cache delegation info (intermediate caching)
                    CACHE[(str(rrset.name), dns.rdatatype.NS)] = response

            # Resolve unglued NS to A records
            if not next_ns_ips and ns_names:
                for ns_name in ns_names:
                    ns_key = (ns_name, dns.rdatatype.A)
                    if ns_key in CACHE:
                        ns_resp = CACHE[ns_key]
                    else:
                        try:
                            ns_resp = lookup(dns.name.from_text(ns_name), dns.rdatatype.A)
                            CACHE[ns_key] = ns_resp
                        except Exception:
                            continue

                    for rrset in getattr(ns_resp, "answer", []):
                        if rrset.rdtype == dns.rdatatype.A:
                            for rr in rrset:
                                ipv4 = str(rr)
                                if ":" not in ipv4 and ipv4 not in next_ns_ips:
                                    next_ns_ips.append(ipv4)

            # If no next NS IPs found, restart from roots
            if not next_ns_ips:
                _LAST_NAMESERVERS = list(ROOT_SERVERS)
                nameservers = list(ROOT_SERVERS)
                break

            # Cache intermediate glue results
            for rrset in response.additional:
                if rrset.rdtype == dns.rdatatype.A:
                    for rr in rrset:
                        CACHE[(str(rrset.name), dns.rdatatype.A)] = rr

            # Continue recursion to next layer
            _LAST_NAMESERVERS = list(next_ns_ips)
            nameservers = next_ns_ips
            break
        else:
            break

    # --- Fallback Empty Response ---
    empty = dns.message.make_response(dns.message.make_query(target_name, qtype))
    CACHE[key] = empty
    return empty




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
