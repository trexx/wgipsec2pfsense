# wgipsec2pfsense - BOVPN_report2csv.py
# Parse the WatchGuard branch office report and spit out a CSV

import itertools as it
import re

header = "iketype,interface,p1protocol,remote_gateway,p1descr,p1mode,myid_data,myid_type,peerid_data,peerid_type,Pre-Shared Key,encryption_algorithm_name,encryption_algorithm_keylen,hash_algorithm,p1lifetime,dhgroup,p2mode,localid_type,localid_address,localid_netbits,remoteid_type,remoteid_address,remoteid_netbits,p2descr,p2protocol,encryption_algorithm_option_name,encryption_algorithm_option_keylen,hash_algorithm_option,pfsgroup,p2lifetime\n"

with open("BOVPN_Report.txt", "r") as input:
    with open("CSV_Report.csv", "w") as output:
        output.write(header)
        for key,group in it.groupby(input,lambda line: line.startswith('===============================================================================')):
            if not key:
                for line in group:
                    linesplit = line.split(":")

                    ### Phase 1 information
                    iketype = "ikev1"
                    interface = "wan"
                    p1protocol = "inet"
                    p1lifetime = "28800"
                    nat_traversal = "on"
                    mobike = "off"
                    dpd_delay = "10"
                    dpd_maxfail = "5"

                    if re.match("    Remote IP Address$", linesplit[0]) is not None :
                        remote_gateway = linesplit[1].strip().lower()

                    if re.match("BOVPN Gateway Settings$", linesplit[0]) is not None :
                        p1descr = linesplit[1].strip().lower()

                    if re.match("  Mode$", linesplit[0]) is not None :
                        p1mode = linesplit[1].strip().lower()

                    if re.match("    Local ID$", linesplit[0]) is not None :
                        myid_data = re.search(' (.+?) ',linesplit[1]).group(1).lower()

                        if re.match(".*Domain Name.*", linesplit[1]) is not None :
                            myid_type = "fqdn"
                        elif re.match(".*IP Address.*", linesplit[1]) is not None :
                            myid_type = "address"

                    if re.match("    Remote ID$", linesplit[0]) is not None :
                        peerid_data = re.search(' (.+?) ',linesplit[1]).group(1).lower()

                        if re.match(".*Domain Name.*", linesplit[1]) is not None :
                            peerid_type = "fqdn"
                        elif re.match(".*IP Address.*", linesplit[1]) is not None :
                            peerid_type = "address"

                    if re.match("      Encryption$", linesplit[0]) is not None :
                        if re.match(" .*3DES", linesplit[1]) is not None :
                            encryption_algorithm_name = "3des"
                            encryption_algorithm_keylen = "N/A"
                        else:
                            encryption_algorithm_name = "aes"
                            encryption_algorithm_keylen = re.search(' *\((.+?)-bit\)',linesplit[1]).group(1).lower()

                    if re.match("      Authentication$", linesplit[0]) is not None :
                        hash_algorithm = linesplit[1].strip().lower()

                    if re.match("      Key Group$", linesplit[0]) is not None :
                        if re.match(" .*Diffie-Hellman Group1", linesplit[1]) is not None :
                           dhgroup = "1"
                        elif re.match(" .*Diffie-Hellman Group2", linesplit[1]) is not None :
                           dhgroup = "2"
                        elif re.match(" .*Diffie-Hellman Group5", linesplit[1]) is not None :
                           dhgroup = "5"
                        else:
                            dhgroup = "0"

                    ### Phase 2 information
                    p2mode = "tunnel"
                    localid_type = "network"
                    remoteid_type = "network"
                    p2lifetime = "3600"


                    if re.match("      Local$", linesplit[0]) is not None :
                        localid_address = linesplit[1].split("/")[0].strip().lower()
                        localid_netbits = linesplit[1].split("/")[1].strip().lower()

                    if re.match("      Remote$", linesplit[0]) is not None :
                        remoteid_address = linesplit[1].split("/")[0].strip().lower()
                        remoteid_netbits = linesplit[1].split("/")[1].strip().lower()

                    if re.match("BOVPN Tunnel Settings$", linesplit[0]) is not None :
                        p2descr = linesplit[1].strip().lower()

                    if re.match("        Type$", linesplit[0]) is not None :
                        p2protocol = linesplit[1].strip().lower()

                    if re.match("        Encryption$", linesplit[0]) is not None :
                        if re.match(" .*3DES", linesplit[1]) is not None :
                            encryption_algorithm_option_name = "3des"
                            encryption_algorithm_option_keylen = "N/A"
                        else:
                            encryption_algorithm_option_name = re.search(' (.+?) ',linesplit[1]).group(1).lower()
                            encryption_algorithm_option_keylen = re.search(' *\((.+?)-bit\)',linesplit[1]).group(1).lower()

                    if re.match("        Authentication$", linesplit[0]) is not None :
                        if re.match("SHA1", linesplit[1].strip()) is not None :
                            hash_algorithm_option = "hmac_sha1"

                    if re.match("    Perfect Forward Secrecy$", linesplit[0]) is not None :
                        if re.match(" .*\(Diffie-Hellman Group1\)", linesplit[1]) is not None :
                            pfsgroup = "1"
                        elif re.match(" .*\(Diffie-Hellman Group2\)", linesplit[1]) is not None :
                            pfsgroup = "2"
                        elif re.match(" .*\(Diffie-Hellman Group5\)", linesplit[1]) is not None :
                            pfsgroup = "5"
                        else:
                            pfsgroup = "0"

                ### Export here
                record = iketype + "," + interface + "," + p1protocol + "," + \
                    remote_gateway + "," + p1descr + "," + p1mode + "," + myid_data + "," + myid_type + "," + \
                    peerid_data + "," + peerid_type + "," + "<PSK>" + "," + encryption_algorithm_name + "," + encryption_algorithm_keylen + "," + \
                    hash_algorithm + "," + p1lifetime + "," + dhgroup + "," + p2mode + "," + localid_type + "," + localid_address + "," + localid_netbits + "," + \
                    remoteid_type + "," + remoteid_address + "," + remoteid_netbits + "," + p2descr + "," + p2protocol + "," + \
                    encryption_algorithm_option_name + "," + encryption_algorithm_option_keylen + "," + hash_algorithm_option + "," + \
                    pfsgroup + "," + p2lifetime + "\n"

                output.write(record)
