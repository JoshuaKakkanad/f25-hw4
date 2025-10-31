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


# Simple in-memory cache for duplicate queries
CACHE = {}

def lookup(target_name: dns.name.Name,
           qtype: dns.rdata.Rdata) -> dns.message.Message:
    """
    Recursive DNS resolver implemented only with modules provided in resolve.py.
    Walks from root servers down to authoritative nameservers.
    """

    key = (str(target_name), qtype)
    if key in CACHE:
        return CACHE[key]

    nameservers = list(ROOT_SERVERS)
    tried = set()

    while True:
        for ns in nameservers:
            if ns in tried:
                continue
            tried.add(ns)

            # Build and send query
            query = dns.message.make_query(target_name, qtype)
            try:
                response = dns.query.udp(query, ns, timeout=3)
            except Exception:
                # skip failed or timed-out server
                continue

            # --- Case 1: direct answer found ---
            if response.answer:
                CACHE[key] = response
                # Handle CNAME chains (restart for the alias)
                for rrset in response.answer:
                    if rrset.rdtype == dns.rdatatype.CNAME:
                        cname_target = rrset[0].target
                        return lookup(cname_target, qtype)
                return response

            # --- Case 2: referral with glue in Additional section ---
            next_ns_ips = []
            for rrset in response.additional:
                if rrset.rdtype == dns.rdatatype.A:
                    for rr in rrset:
                        next_ns_ips.append(str(rr))

            # --- Case 3: referral without glue (Authority only) ---
            if not next_ns_ips and response.authority:
                ns_names = []
                for rrset in response.authority:
                    if rrset.rdtype == dns.rdatatype.NS:
                        for rr in rrset:
                            ns_names.append(str(rr.target))
                # resolve NS hostnames into IPs
                for ns_name in ns_names:
                    ns_response = lookup(dns.name.from_text(ns_name),
                                         dns.rdatatype.A)
                    for rrset in ns_response.answer:
                        if rrset.rdtype == dns.rdatatype.A:
                            for rr in rrset:
                                next_ns_ips.append(str(rr))

            # --- Cache intermediate results (authority + glue) ---
            for rrset in response.authority + response.additional:
                CACHE[(str(rrset.name), rrset.rdtype)] = response

            # Move to next level if we have IPs
            if next_ns_ips:
                nameservers = next_ns_ips
                break  # restart the loop at lower level

        else:
            # no more servers to try → return an empty response
            empty_resp = dns.message.make_response(query)
            CACHE[key] = empty_resp
            return empty_resp


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
