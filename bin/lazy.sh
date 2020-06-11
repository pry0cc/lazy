#!/bin/bash

mkdir -p "$HOME/work/$1/logs"
LOG="$HOME/work/$1/logs/log.txt"
# Reset
export NC='\033[0m'       # Text Reset

# Regular Colors
export Black='\033[0;30m'        # Black
export Red='\033[0;31m'          # Red
export Green='\033[0;32m'        # Green
export Yellow='\033[0;33m'       # Yellow
export Blue='\033[0;34m'         # Blue
export Purple='\033[0;35m'       # Purple
export Cyan='\033[0;36m'         # Cyan
export White='\033[0;37m'        # White

# Bold
export BBlack='\033[1;30m'       # Black
export BRed='\033[1;31m'         # Red
export BGreen='\033[1;32m'       # Green
export BYellow='\033[1;33m'      # Yellow
export BBlue='\033[1;34m'        # Blue
export BPurple='\033[1;35m'      # Purple
export BCyan='\033[1;36m'        # Cyan
export BWhite='\033[1;37m'       # White


echo_info_n() {
    msg="$1"
    echo "$(date "+%Y-%m-%d %H:%M:%S") INFO: $msg" >> $LOG
    echo -n -e "${Blue}[+] $msg${NC}"
}

echo_info() {
    msg="$1"
    echo "$(date "+%Y-%m-%d %H:%M:%S") INFO: $msg" >> $LOG
    echo -e "${Blue}[+] $msg${NC}"
}

echo_success() {
    msg="$1"
    echo "$(date "+%Y-%m-%d %H:%M:%S") SUCCESS: $msg" >> $LOG
    echo -e "${BGreen}[*] $msg${NC}"
}

echo_error() {
    msg="$1"
    echo "$(date "+%Y-%m-%d %H:%M:%S") ERROR: $msg" >> $LOG
    echo -e "${Red}[-] $msg${NC}"
}

ok() {
    if [ $? -eq 0 ]; then
        echo -e "[ ${Green}OK${NC} ]"
    else
        echo -e "[ ${Red}FAIL${NC} ]"
    fi
    
}

echo_success "Launching enumeration against $1"
echo_info_n "Creating folder structure... "
TARGET="$1"
HOME_DIR="$HOME/work/$TARGET"

mkdir -p $HOME_DIR
mkdir -p $HOME_DIR/dns
mkdir -p $HOME_DIR/http
mkdir -p $HOME_DIR/http/js
mkdir -p $HOME_DIR/flags
mkdir -p $HOME_DIR/scans/domains
mkdir -p $HOME_DIR/scans/ip
mkdir -p $HOME_DIR/http/aquatone

flags="$HOME_DIR/flags"
domains="$HOME_DIR/dns/domains"
takeover="$HOME_DIR/dns/takeover"
responsive="$HOME_DIR/dns/responsive"
all_urls="$HOME_DIR/http/all_urls"
interestingsubs="$HOME_DIR/flags/interestingsubs"
ip_uniq="$HOME_DIR/dns/ip_uniq"
resolved="$HOME_DIR/dns/resolved"
javascript_files="$HOME_DIR/http/javascript_files"
js="$HOME_DIR/http/js"
aquatone="$HOME_DIR/http/aquatone"

cd $HOME_DIR
ok

#finding subdomains

echo_info_n "Running DNS enumeration... "
subfinder -silent -d $1 | tee -a $domains &>> $LOG
assetfinder -subs-only $1 | tee -a $domains &>> $LOG
curl -s "https://crt.sh/?q=%25.$1&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | tee -a $domains &>> $LOG
# This needs serious work - I'm sorry vict0ni :)
#cat ~/lists/jhaddix-all.txt | subgen -d "$1" |  zdns A  | jq '.[].answers?[]?' | jq -r 'select(.type == "A") | .name' | tee -a domains
ok

#sorting/uniq
echo_info_n "Sorting domain files... "
sort -u $domains > $HOME_DIR/dns/dom2;rm $domains;mv $HOME_DIR/dns/dom2 $domains
ok

echo_success "Found $(wc -l $domains | awk '{ print $1 }') unique domains!"

#account takeover scanning
echo_info_n "Scanning for domain takeovers... "
subjack -w $domains -t 100 -timeout 30 -ssl -c $GOPATH/src/github.com/haccer/subjack/fingerprints.json -v | tee -a $takeover &>> $LOG
ok

#httprobing 
echo_info_n "Probing for interactive hosts... "
cat $domains | httprobe | sort -u | tee -a $responsive &>> $LOG
gf interestingsubs $responsive > $interestingsubs
ok

echo_success "Found $(wc -l $responsive| awk '{ print $1 }') responsive hosts!"

#resolving
echo_info_n "Resolving domains... "
cat $domains | dnsprobe -silent | tee -a $resolved &>> $LOG
cat $resolved | sed 's/ /,/g' | tee -a $resolved.formatted &>> $LOG
cat $resolved | awk '{ print $2 }' | sort -u > $ip_uniq
ok

echo_success "Launching full IP scan"

for ip in $(cat $ip_uniq)
do
    masscan_outfile="$HOME_DIR/scans/ip/$ip.masscan"
    nmap_outfile="$HOME_DIR/scans/ip/$ip.nmap.xml"

    if [ ! -f "$nmap_outfile" ]
    then
        echo_info_n "Running full vulnerability scan against $ip...(Can take some time)... "
        sudo masscan -p0-65535 --banners --rate=10000 "$ip" -oG "$masscan_outfile" &>> $LOG 
        ports=$(cat "$masscan_outfile" | grep -v "#" | sed 's/\// /g' | awk '{ print $5 }'  | sort -u | tr '\n' ',' | rev | cut -c 2- | rev)
        nmap -Pn -T5 -sV -p$ports --script vulners -oX "$nmap_outfile" "$ip" &>> $LOG
        ok
    fi
done

ok
echo_info_n "Converting scans and parsing to json... "

for line in $(cat $resolved.formatted)
do
    domain=$(echo $line | cut -d "," -f 1)
    ip=$(echo $line | cut -d "," -f 2)

    nmap_outfile="$HOME_DIR/scans/ip/$ip.nmap.xml"
    domain_outfile="$HOME_DIR/scans/domains/$domain.json"

    if [[ -f "$nmap_outfile" && ! -f "$domain_outfile" ]]
    then
        nmap2json convert "$nmap_outfile" > $domain_outfile 
        cat $domain_outfile | jq -C '.[].host.ports[] | .[] | .service.port=.portid | .service.script=.script | .service' > $domain_outfile.detailed
    fi
done

ok


#endpoint discovery
echo_info_n "Crawling detected URLs... "
cat $responsive | gau | tee -a $all_urls &>> $LOG
cat $responsive | hakrawler --depth 3 --plain | tee -a $all_urls &>> $LOG
ok

#extracting all responsive js files
echo_info "Scanning javascript files for secrets... "
grep "\.js$" $all_urls | anti-burl | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort -u | tee -a $javascript_files
ok

#analyzing js files for secrets
echo_info "Scanning javascript files for secrets... "
wget -nc -i $javascript_files -P "$js" &>> $LOG
cat $js/* >> $js/gf-all
gf sec $js/gf-all > $flags/secrets 
ok

echo_info "Running aquatone against all endpoints... "
if [ ! -f "$aquatone/aquatone_report.html" ]
then
    cat $domains | aquatone -out $aquatone -ports 80,443,7443,8080,8000,8443,8081 -scan-timeout 20000
fi
ok

#grabing endpoints that include juicy parameters
gf redirect $all_urls | anti-burl > $flags/redirects
gf idor $all_urls | anti-burl > $flags/idor
gf rce $all_urls | anti-burl > $flags/rce
gf lfi $all_urls | anti-burl > $flags/lfi
gf xss $all_urls | anti-burl > $flags/xss
gf ssrf $all_urls | anti-burl > $flags/ssrf
