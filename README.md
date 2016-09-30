# Watchguard IPsec migration scripts to CSV & pfSense
These Python scripts were put to gether to assist with a migration to pfSense from WatchGuard.  
We have approximately 360 (and growing) IPsec tunnels and needed a quick way of moving them across.

The latest version of WatchGuard System Manager (we used v11.11) is able to generate a report on branch office gateways and tunnels giving us all the information we need to migrate tunnels to pfSense with the exception of the pre-shared key.

```bovpn_report2csv.py``` will parse the plain text report and covert it to CSV. Here you can do some sanity checks, add in the PSKs (perhaps by using a vlookup), etc.

```csv2pfsense.py``` will parse the CSV and create a file which can be used in the pfSense Developer Shell

### Process
Once you have your final config, pfSense Developer Shell steps are as follows.
```
parse_config(true);
<contents of pfSense_Import.txt>
write_config();
system_reboot_sync();
exec;
```

### Note
If you have existing tunnels on your pfSense install, edit ```export.py``` and change the following variables to avoid overwriting existing tunnel configuration.
```
p1count
ikeid
p2count
reqid
```

You can get these numbers from the pfSense Developer Shell
```
parse_config(true);
print_r($config);
exec;
```

### Alternative Methods
Another way of migrating the configuration maybe to parse the WatchGuard configuration file contained in an xml file.

### Additional Information
https://doc.pfsense.org/index.php/Using_the_PHP_pfSense_Shell
