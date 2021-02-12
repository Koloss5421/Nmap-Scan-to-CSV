# Nmap-XML-Parser
Converts Nmap XML output to csv file. Forked from [laconicwolf/Nmap-Scan-to-CSV](https://github.com/laconicwolf/Nmap-Scan-to-CSV) to simplify for my needs and not ignore hosts.

## Usage

### Exmaple nmap run:
`sudo nmap -Pn -sT 169.254.0.0/8 -p 80,443 -oX nmap_scan.xml`

### Convert Nmap output to csv file
`python3 nmap_xml_parser.py -f nmap_scan.xml -csv nmap_scan.csv`

### Display scan information to the terminal
`python3 nmap_xml_parser.py -f nmap_scan.xml -p`

### Display only IP addresses
`python3 nmap_xml_parser.py -f nmap_scan.xml -ip`
