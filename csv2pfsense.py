# wgipsec2pfsense - csv2pfsense.py
# Parse the CSV and spit out the configuration compatible with the pfSense Developer Shell

import csv
import random

p1count = 31
ikeid = 32

p2count = 41
reqid = 42

with open("CSV_Report.csv", "r") as input:
    with open("pfSense_Import.txt", "w") as output:
        next(input)
        for row in csv.reader(input):
            ### PHASE 1
            tunnel = "$config['ipsec']['phase1'][" + str(p1count) + "]['ikeid'] = \"" + str(ikeid) + "\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['iketype'] = \"" + row[0] + "\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['interface'] = \"" + row[1] + "\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['protocol'] = \"" + row[2] + "\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['remote-gateway'] = \"" + row[3] + "\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['descr'] = \"" + row[4] + "\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['mode'] = \"" + row[5] + "\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['myid_data'] = \"" + row[6] + "\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['myid_type'] = \"" + row[7] + "\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['peerid_data'] = \"" + row[8] + "\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['peerid_type'] = \"" + row[9] + "\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['pre-shared-key'] = \"" + row[10] + "\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['encryption-algorithm']['name'] = \"" + row[11] + "\";\n"
            if "aes" in row[11]:
                tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['encryption-algorithm']['keylen'] = \"" + row[12] + "\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['hash-algorithm'] = \"" + row[13] + "\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['lifetime'] = \"" + row[14] + "\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['dhgroup'] = \"" + row[15] + "\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['authentication_method'] = \"pre_shared_key\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['nat_traversal'] = \"on\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['mobike'] = \"off\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['dpd_delay'] = \"10\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['dpd_maxfail'] = \"5\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['private-key'] = \"\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['certref'] = \"\";\n"
            tunnel += "$config['ipsec']['phase1'][" + str(p1count) + "]['caref'] = \"\";\n"

            ### PHASE 2
            tunnel += "$config['ipsec']['phase2'][" + str(p2count) + "]['reqid'] = \"" + str(reqid) + "\";\n"
            tunnel += "$config['ipsec']['phase2'][" + str(p2count) + "]['uniqid'] = \"" + ''.join(random.choice('0123456789ABCDEF').lower() for i in range(13)) + "\";\n"
            tunnel += "$config['ipsec']['phase2'][" + str(p2count) + "]['ikeid'] = \"" + str(ikeid) + "\";\n"
            tunnel += "$config['ipsec']['phase2'][" + str(p2count) + "]['mode'] = \"" + row[16] + "\";\n"
            tunnel += "$config['ipsec']['phase2'][" + str(p2count) + "]['localid']['type'] = \"" + row[17] + "\";\n"
            tunnel += "$config['ipsec']['phase2'][" + str(p2count) + "]['localid']['address'] = \"" + row[18] + "\";\n"
            tunnel += "$config['ipsec']['phase2'][" + str(p2count) + "]['localid']['netbits'] = \"" + row[19] + "\";\n"
            tunnel += "$config['ipsec']['phase2'][" + str(p2count) + "]['remoteid']['type'] = \"" + row[20] + "\";\n"
            tunnel += "$config['ipsec']['phase2'][" + str(p2count) + "]['remoteid']['address'] = \"" + row[21] + "\";\n"
            tunnel += "$config['ipsec']['phase2'][" + str(p2count) + "]['remoteid']['netbits'] = \"" + row[22] + "\";\n"
            tunnel += "$config['ipsec']['phase2'][" + str(p2count) + "]['descr'] = \"" + row[23] + "\";\n"
            tunnel += "$config['ipsec']['phase2'][" + str(p2count) + "]['protocol'] = \"" + row[24] + "\";\n"
            tunnel += "$config['ipsec']['phase2'][" + str(p2count) + "]['encryption-algorithm-option'][0]['name'] = \"" + row[25] + "\";\n"
            if "aes" in row[25]:
                tunnel += "$config['ipsec']['phase2'][" + str(p2count) + "]['encryption-algorithm-option'][0]['keylen'] = \"" + row[26] + "\";\n"
            tunnel += "$config['ipsec']['phase2'][" + str(p2count) + "]['hash-algorithm-option'][0] = \"" + row[27] + "\";\n"
            tunnel += "$config['ipsec']['phase2'][" + str(p2count) + "]['pfsgroup'] = \"" + row[28] + "\";\n"
            tunnel += "$config['ipsec']['phase2'][" + str(p2count) + "]['lifetime'] = \"" + row[29] + "\";\n"
            tunnel += "$config['ipsec']['phase2'][" + str(p2count) + "]['pinghost'] = \"\";\n"
            tunnel += "\n"

            p1count += 1
            p2count += 1 
            ikeid += 1
            reqid += 1

            output.write(tunnel)
