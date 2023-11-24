#! /bin/bash
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[Info]${Font_color_suffix}"
Error="${Red_font_prefix}[Error]${Font_color_suffix}"
shell_version="1.1.1"
ct_new_ver="2.11.2" # 2.x no longer follows official updates
gost_conf_path="/etc/gost/config.json"
raw_conf_path="/etc/gost/rawconf"

function checknew() {
  checknew=$(gost -V 2>&1 | awk '{print $2}')
  # check_new_ver
  echo "Your gost version is: ""$checknew"""
  echo -n "Do you want to update? (y/n): "
  read checknewnum
  if test $checknewnum = "y"; then
    cp -r /etc/gost /tmp/
    Install_ct
    rm -rf /etc/gost
    mv /tmp/gost /etc/
    systemctl restart gost
  else
    exit 0
  fi
}

function check_sys() {
  if [[ -f /etc/redhat-release ]]; then
    release="centos"
  elif cat /etc/issue | grep -q -E -i "debian"; then
    release="debian"
  elif cat /etc/issue | grep -q -E -i "ubuntu"; then
    release="ubuntu"
  elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
    release="centos"
  elif cat /proc/version | grep -q -E -i "debian"; then
    release="debian"
  elif cat /proc/version | grep -q -E -i "ubuntu"; then
    release="ubuntu"
  elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
    release="centos"
  fi
  bit=$(uname -m)
  if test "$bit" != "x86_64"; then
    echo "Please enter your architecture: /386/armv5/armv6/armv7/armv8"
    read bit
  else
    bit="amd64"
  fi
}

function Installation_dependency() {
  gzip_ver=$(gzip -V)
  if [[ -z ${gzip_ver} ]]; then
    if [[ ${release} == "centos" ]]; then
      yum update
      yum install -y gzip wget
    else
      apt-get update
      apt-get install -y gzip wget
    fi
  fi
}

function check_root() {
  [[ $EUID != 0 ]] && echo -e "${Error} This script must be run as ROOT. Please use ${Green_background_prefix}sudo su${Font_color_suffix} or switch to a ROOT account." && exit 1
}

function check_new_ver() {
  # deprecated
  ct_new_ver=$(wget --no-check-certificate -qO- -t2 -T3 https://api.github.com/repos/ginuerzh/gost/releases/latest | grep "tag_name" | head -n 1 | awk -F ":" '{print $2}' | sed 's/\"//g;s/,//g;s/ //g;s/v//g')
  if [[ -z ${ct_new_ver} ]]; then
    ct_new_ver="2.11.2"
    echo -e "${Error} Failed to fetch the latest version of gost. Downloading version v${ct_new_ver}"
  else
    echo -e "${Info} The latest version of gost is ${ct_new_ver}"
  fi
}

function check_file() {
  if test ! -d "/usr/lib/systemd/system/"; then
    mkdir /usr/lib/systemd/system
    chmod -R 777 /usr/lib/systemd/system
  fi
}

function check_nor_file() {
  rm -rf "$(pwd)"/gost
  rm -rf "$(pwd)"/gost.service
  rm -rf "$(pwd)"/config.json
  rm -rf /etc/gost
  rm -rf /usr/lib/systemd/system/gost.service
  rm -rf /usr/bin/gost
}

function Install_ct() {
  check_root
  check_nor_file
  Installation_dependency
  check_file
  check_sys
  # check_new_ver
  echo -e "If you are in China, it is recommended to use a mirror for faster downloads."
  read -e -p "Do you want to use a mirror? [y/n]: " addyn
  [[ -z ${addyn} ]] && addyn="n"
  if [[ ${addyn} == [Yy] ]]; then
    rm -rf gost-linux-"$bit"-"$ct_new_ver".gz
    wget --no-check-certificate https://files.cdndouyin.com/gost-linux-amd64-2.11.2.gz
    gunzip gost-linux-"$bit"-"$ct_new_ver".gz
    mv gost-linux-"$bit"-"$ct_new_ver" gost
    mv gost /usr/bin/gost
    chmod -R 777 /usr/bin/gost
    wget --no-check-certificate https://files.cdndouyin.com/gost.service && chmod -R 777 gost.service && mv gost.service /usr/lib/systemd/system
    mkdir /etc/gost && wget --no-check-certificate https://files.cdndouyin.com/config.json && mv config.json /etc/gost && chmod -R 777 /etc/gost
  else
    rm -rf gost-linux-"$bit"-"$ct_new_ver".gz
    wget --no-check-certificate https://ghproxy.com/https://github.com/ginuerzh/gost/releases/download/v"$ct_new_ver"/gost-linux-"$bit"-"$ct_new_ver".gz
    gunzip gost-linux-"$bit"-"$ct_new_ver".gz
    mv gost-linux-"$bit"-"$ct_new_ver" gost
    mv gost /usr/bin/gost
    chmod -R 777 /usr/bin/gost
    wget --no-check-certificate https://files.cdndouyin.com/gost.service && chmod -R 777 gost.service && mv gost.service /usr/lib/systemd/system
    mkdir /etc/gost && wget --no-check-certificate https://files.cdndouyin.com/config.json && mv config.json /etc/gost && chmod -R 777 /etc/gost
  fi

  systemctl enable gost && systemctl restart gost
  echo "------------------------------"
  if test -a /usr/bin/gost -a /usr/lib/systemctl/gost.service -a /etc/gost/config.json; then
  echo "gost installation successful"
  rm -rf "$(pwd)"/gost
  rm -rf "$(pwd)"/gost.service
  rm -rf "$(pwd)"/config.json
else
  echo "gost installation failed"
  rm -rf "$(pwd)"/gost
  rm -rf "$(pwd)"/gost.service
  rm -rf "$(pwd)"/config.json
  rm -rf "$(pwd)"/gost.sh
fi
}

function Uninstall_ct() {
  rm -rf /usr/bin/gost
  rm -rf /usr/lib/systemd/system/gost.service
  rm -rf /etc/gost
  rm -rf "$(pwd)"/gost.sh
  echo "gost has been successfully removed"
}

function Start_ct() {
  systemctl start gost
  echo "Started"
}

function Stop_ct() {
  systemctl stop gost
  echo "Stopped"
}

function Restart_ct() {
  rm -rf /etc/gost/config.json
  confstart
  writeconf
  conflast
  systemctl restart gost
  echo "Configuration re-read and gost restarted"
}

function read_protocol() {
  echo -e "Please choose the desired functionality: "
  echo -e "-----------------------------------"
  echo -e "[1] tcp+udp traffic forwarding, non-encrypted"
  echo -e "Description: Typically set on a domestic relay machine"
  echo -e "-----------------------------------"
  echo -e "[2] Encrypted tunnel traffic forwarding"
  echo -e "Description: Used to forward originally lower-grade encrypted traffic, usually set on a domestic relay machine"
  echo -e "     Choosing this protocol means you have another machine to receive this encrypted traffic, then you need to configure protocol [3] on that machine for connection"
  echo -e "-----------------------------------"
  echo -e "[3] Decrypt and forward traffic transmitted by gost"
  echo -e "Description: For traffic encrypted and relayed by gost, use this option to decrypt and forward it to the local proxy service port or forward it to another remote machine"
  echo -e "      Typically set on a foreign machine used to receive relayed traffic"
  echo -e "-----------------------------------"
  echo -e "[4] One-click installation of ss/socks5/http proxy"
  echo -e "Description: Use the built-in proxy protocol of gost, lightweight and easy to manage"
  echo -e "-----------------------------------"
  echo -e "[5] Advanced: Multi-destination load balancing"
  echo -e "Description: Supports simple load balancing for various encryption methods"
  echo -e "-----------------------------------"
  echo -e "[6] Advanced: Forward CDN selected nodes"
  echo -e "Description: Only need to be set on the relay machine"
  echo -e "-----------------------------------"
  read -p "Please choose: " numprotocol

  if [ "$numprotocol" == "1" ]; then
    flag_a="nonencrypt"
  elif [ "$numprotocol" == "2" ]; then
    encrypt
  elif [ "$numprotocol" == "3" ]; then
    decrypt
  elif [ "$numprotocol" == "4" ]; then
    proxy
  elif [ "$numprotocol" == "5" ]; then
    enpeer
  elif [ "$numprotocol" == "6" ]; then
    cdn
  else
    echo "type error, please try again"
    exit
  fi
}

function read_s_port() {
  if [ "$flag_a" == "ss" ]; then
    echo -e "-----------------------------------"
    read -p "Please enter ss password: " flag_b
  elif [ "$flag_a" == "socks" ]; then
    echo -e "-----------------------------------"
    read -p "Please enter socks password: " flag_b
  elif [ "$flag_a" == "http" ]; then
    echo -e "-----------------------------------"
    read -p "Please enter http password: " flag_b
  else
    echo -e "------------------------------------------------------------------"
    echo -e "Which port on this machine do you want to forward traffic to?"
    read -p "Please enter: " flag_b
  fi
}

function read_d_ip() {
  if [ "$flag_a" == "ss" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "Please enter the ss encryption you want to set (only provide commonly used ones): "
    echo -e "-----------------------------------"
    echo -e "[1] aes-256-gcm"
    echo -e "[2] aes-256-cfb"
    echo -e "[3] chacha20-ietf-poly1305"
    # ... (continue with other options if needed)
    echo -e "[4] chacha20"
    echo -e "[5] rc4-md5"
    echo -e "[6] AEAD_CHACHA20_POLY1305"
    echo -e "-----------------------------------"
   
    fi
}
function writerawconf() {
  echo $flag_a"/""$flag_b""#""$flag_c""#""$flag_d" >>$raw_conf_path
}
function rawconf() {
  read_protocol
  read_s_port
  read_d_ip
  read_d_port
  writerawconf
}
function eachconf_retrieve() {
  d_server=${trans_conf#*#}
  d_port=${d_server#*#}
  d_ip=${d_server%#*}
  flag_s_port=${trans_conf%%#*}
  s_port=${flag_s_port#*/}
  is_encrypt=${flag_s_port%/*}
}
function confstart() {
  echo "{
    \"Debug\": true,
    \"Retries\": 0,
    \"ServeNodes\": [" >>$gost_conf_path
}
function multiconfstart() {
  echo "        {
            \"Retries\": 0,
            \"ServeNodes\": [" >>$gost_conf_path
}
function conflast() {
  echo "    ]
}" >>$gost_conf_path
}
function multiconflast() {
  if [ $i -eq $count_line ]; then
    echo "            ]
        }" >>$gost_conf_path
  else
    echo "            ]
        }," >>$gost_conf_path
  fi
}
function encrypt() {
  echo -e "Please specify the forwarding transmission type: "
  echo -e "-----------------------------------"
  echo -e "[1] TLS tunnel"
  echo -e "[2] WebSocket (WS) tunnel"
  echo -e "[3] WebSocket Secure (WSS) tunnel"
  echo -e "Note: For each forwarding rule, the transmission type of relay and destination must match. This script defaults to enabling TCP+UDP."
  echo -e "-----------------------------------"
  read -p "Select the forwarding transmission type: " numencrypt

  if [ "$numencrypt" == "1" ]; then
    flag_a="encrypttls"
    echo -e "Note: If 'Yes' is selected, certificate verification will be enabled for the custom TLS certificate on the destination. Make sure to enter the ${Red_font_prefix}domain${Font_color_suffix} later."
    read -e -p "Has the destination enabled a custom TLS certificate? [y/n]:" is_cert
  elif [ "$numencrypt" == "2" ]; then
    flag_a="encryptws"
  elif [ "$numencrypt" == "3" ]; then
    flag_a="encryptwss"
    echo -e "Note: If 'Yes' is selected, certificate verification will be enabled for the custom TLS certificate on the destination. Make sure to enter the ${Red_font_prefix}domain${Font_color_suffix} later."
    read -e -p "Has the destination enabled a custom TLS certificate? [y/n]:" is_cert
  else
    echo "Type error, please try again."
    exit
  fi
}
function enpeer() {
 echo -e "Please select the transmission type for load balancing: "
echo -e "-----------------------------------"
echo -e "[1] Unencrypted forwarding"
echo -e "[2] TLS tunnel"
echo -e "[3] WS tunnel"
echo -e "[4] WSS tunnel"
echo -e "Note: For the same forwarding, the transmission type for relay and destination must match! This script defaults to the same transmission type for the same configuration."
echo -e "This script supports simple load balancing, for more details, refer to the official documentation."
echo -e "Gost Load Balancing Official Documentation: https://docs.ginuerzh.xyz/gost/load-balancing"
echo -e "-----------------------------------"
read -p "Please choose the transmission type for forwarding: " numpeer

if [ "$numpeer" == "1" ]; then
  flag_a="peerno"
elif [ "$numpeer" == "2" ]; then
  flag_a="peertls"
elif [ "$numpeer" == "3" ]; then
  flag_a="peerws"
elif [ "$numpeer" == "4" ]; then
  flag_a="peerwss"
else
  echo "Type error, please try again"
  exit
fi

function cdn() {
  echo -e "Please select the CDN transmission type: "
  echo -e "-----------------------------------"
  echo -e "[1] Unencrypted forwarding"
  echo -e "[2] WS tunnel"
  echo -e "[3] WSS tunnel"
  echo -e "Note: For the same forwarding, the transmission type for relay and destination must match! This feature only needs to be set on the relay machine."
  echo -e "-----------------------------------"
  read -p "Please choose CDN forwarding transmission type: " numcdn

  if [ "$numcdn" == "1" ]; then
    flag_a="cdnno"
  elif [ "$numcdn" == "2" ]; then
    flag_a="cdnws"
  elif [ "$numcdn" == "3" ]; then
    flag_a="cdnwss"
  else
    echo "Type error, please try again"
    exit
  fi
}

function cert() {
  echo -e "-----------------------------------"
  echo -e "[1] ACME one-click certificate application"
  echo -e "[2] Manual certificate upload"
  echo -e "-----------------------------------"
  echo -e "Explanation: Only for destination machine configuration. Using the built-in certificate of gost may pose security risks. Using a custom certificate enhances security."
  echo -e "Once configured, it takes effect for all TLS/WSS decryption on this machine, and no need to set again."
  read -p "Please choose the certificate generation method: " numcert


  if [ "$numcert" == "1" ]; then
    check_sys
    if [[ ${release} == "centos" ]]; then
      yum install -y socat
    else
      apt-get install -y socat
    fi
    read -p "Please enter your ZeroSSL account email (register at zerossl.com): " zeromail
    read -p "Please enter the domain pointing to this machine: " domain
    curl https://get.acme.sh | sh
    "$HOME"/.acme.sh/acme.sh --set-default-ca --server zerossl
    "$HOME"/.acme.sh/acme.sh --register-account -m "${zeromail}" --server zerossl
    echo -e "ACME certificate application program installed successfully"
    echo -e "-----------------------------------"
    echo -e "[1] HTTP application (requires port 80 unoccupied)"
    echo -e "[2] Cloudflare DNS API application (requires APIKEY)"
    echo -e "-----------------------------------"
    read -p "Please select the certificate application method: " certmethod
    if [ "$certmethod" == "1" ]; then
      echo -e "Please confirm that ${Red_font_prefix}port 80${Font_color_suffix} is not occupied on this machine, otherwise, the application will fail"
      if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force; then
        echo -e "SSL certificate generated successfully, default to apply for a high-security ECC certificate"
        if [ ! -d "$HOME/gost_cert" ]; then
          mkdir $HOME/gost_cert
        fi
        if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath $HOME/gost_cert/cert.pem --keypath $HOME/gost_cert/key.pem --ecc --force; then
          echo -e "SSL certificate configuration successful, and it will automatically renew. The certificate and key are located in the user directory under ${Red_font_prefix}gost_cert${Font_color_suffix} directory"
          echo -e "Please do not change the directory name and certificate file name; delete the gost_cert directory and restart the script to automatically enable the built-in gost certificate"
          echo -e "-----------------------------------"
        fi
      else
        echo -e "SSL certificate generation failed"
        exit 1
      fi
    else
      read -p "Please enter your Cloudflare account email: " cfmail
      read -p "Please enter your Cloudflare Global API Key: " cfkey
      export CF_Key="${cfkey}"
      export CF_Email="${cfmail}"
      if "$HOME"/.acme.sh/acme.sh --issue --dns dns_cf -d "${domain}" --standalone -k ec-256 --force; then
        echo -e "SSL certificate generated successfully, default to apply for a high-security ECC certificate"
        if [ ! -d "$HOME/gost_cert" ]; then
          mkdir $HOME/gost_cert
        fi
        if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath $HOME/gost_cert/cert.pem --keypath $HOME/gost_cert/key.pem --ecc --force; then
          echo -e "SSL certificate configuration successful, and it will automatically renew. The certificate and key are located in the user directory under ${Red_font_prefix}gost_cert${Font_color_suffix} directory"
          echo -e "Please do not change the directory name and certificate file name; delete the gost_cert directory and restart the script to automatically enable the built-in gost certificate"
          echo -e "-----------------------------------"
        fi
      else
        echo -e "SSL certificate generation failed"
        exit 1
      fi
    fi

  elif [ "$numcert" == "2" ]; then
    if [ ! -d "$HOME/gost_cert" ]; then
      mkdir $HOME/gost_cert
    fi
    echo -e "-----------------------------------"
    echo -e "A directory ${Red_font_prefix}gost_cert${Font_color_suffix} has been created in the user directory. Please upload the certificate file cert.pem and the key file key.pem to this directory"
    echo -e "The certificate and key file names must be consistent with the above, and the directory name should not be changed"
    echo -e "After a successful upload, restarting gost with the script will automatically enable it, and there is no need to set it again; delete the gost_cert directory and restart it with the script to re-enable the built-in gost certificate"
    echo -e "-----------------------------------"
  else
    echo "Type error, please try again"
    exit
  fi

}
function decrypt() {
  echo -e "Please select the decryption transport type: "
  echo -e "-----------------------------------"
  echo -e "[1] tls"
  echo -e "[2] ws"
  echo -e "[3] wss"
  echo -e "Note: For the same forwarding, the transport types on relay and destination must match. This script defaults to enabling tcp+udp."
  echo -e "-----------------------------------"
  read -p "Please choose the decryption transport type: " numdecrypt

  if [ "$numdecrypt" == "1" ]; then
    flag_a="decrypttls"
  elif [ "$numdecrypt" == "2" ]; then
    flag_a="decryptws"
  elif [ "$numdecrypt" == "3" ]; then
    flag_a="decryptwss"
  else
    echo "Type error, please try again."
    exit
  fi
}

function proxy() {
  echo -e "------------------------------------------------------------------"
  echo -e "Please select the proxy type: "
  echo -e "-----------------------------------"
  echo -e "[1] Shadowsocks"
  echo -e "[2] SOCKS5 (Highly recommended to use with a tunnel for Telegram proxy)"
  echo -e "[3] HTTP"
  echo -e "-----------------------------------"
  read -p "Please choose the proxy type: " numproxy
  if [ "$numproxy" == "1" ]; then
    flag_a="ss"
  elif [ "$numproxy" == "2" ]; then
    flag_a="socks"
  elif [ "$numproxy" == "3" ]; then
    flag_a="http"
  else
    echo "Type error, please try again."
    exit
  fi
}

}
function method() {
  if [ $i -eq 1 ]; then
    if [ "$is_encrypt" == "nonencrypt" ]; then
      echo "        \"tcp://:$s_port/$d_ip:$d_port\",
        \"udp://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnno" ]; then
      echo "        \"tcp://:$s_port/$d_ip?host=$d_port\",
        \"udp://:$s_port/$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerno" ]; then
      echo "        \"tcp://:$s_port?ip=/root/$d_ip.txt&strategy=$d_port\",
        \"udp://:$s_port?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encrypttls" ]; then
      echo "        \"tcp://:$s_port\",
        \"udp://:$s_port\"
    ],
    \"ChainNodes\": [
        \"relay+tls://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encryptws" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+ws://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encryptwss" ]; then
      echo "        \"tcp://:$s_port\",
		  \"udp://:$s_port\"
	],
	\"ChainNodes\": [
		\"relay+wss://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peertls" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+tls://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerws" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+ws://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerwss" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+wss://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnws" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+ws://$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnwss" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+wss://$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "decrypttls" ]; then
      if [ -d "$HOME/gost_cert" ]; then
        echo "        \"relay+tls://:$s_port/$d_ip:$d_port?cert=/root/gost_cert/cert.pem&key=/root/gost_cert/key.pem\"" >>$gost_conf_path
      else
        echo "        \"relay+tls://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
      fi
    elif [ "$is_encrypt" == "decryptws" ]; then
      echo "        \"relay+ws://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "decryptwss" ]; then
      if [ -d "$HOME/gost_cert" ]; then
        echo "        \"relay+wss://:$s_port/$d_ip:$d_port?cert=/root/gost_cert/cert.pem&key=/root/gost_cert/key.pem\"" >>$gost_conf_path
      else
        echo "        \"relay+wss://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
      fi
    elif [ "$is_encrypt" == "ss" ]; then
      echo "        \"ss://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "socks" ]; then
      echo "        \"socks5://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "http" ]; then
      echo "        \"http://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    else
      echo "config error"
    fi
  elif [ $i -gt 1 ]; then
    if [ "$is_encrypt" == "nonencrypt" ]; then
      echo "                \"tcp://:$s_port/$d_ip:$d_port\",
                \"udp://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerno" ]; then
      echo "                \"tcp://:$s_port?ip=/root/$d_ip.txt&strategy=$d_port\",
                \"udp://:$s_port?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnno" ]; then
      echo "                \"tcp://:$s_port/$d_ip?host=$d_port\",
                \"udp://:$s_port/$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encrypttls" ]; then
      echo "                \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+tls://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encryptws" ]; then
      echo "                \"tcp://:$s_port\",
	            \"udp://:$s_port\"
	        ],
	        \"ChainNodes\": [
	            \"relay+ws://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encryptwss" ]; then
      echo "                \"tcp://:$s_port\",
		        \"udp://:$s_port\"
		    ],
		    \"ChainNodes\": [
		        \"relay+wss://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peertls" ]; then
      echo "                \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+tls://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerws" ]; then
      echo "                \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+ws://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerwss" ]; then
      echo "                \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+wss://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnws" ]; then
      echo "                \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+ws://$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnwss" ]; then
      echo "                 \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+wss://$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "decrypttls" ]; then
      if [ -d "$HOME/gost_cert" ]; then
        echo "        		  \"relay+tls://:$s_port/$d_ip:$d_port?cert=/root/gost_cert/cert.pem&key=/root/gost_cert/key.pem\"" >>$gost_conf_path
      else
        echo "        		  \"relay+tls://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
      fi
    elif [ "$is_encrypt" == "decryptws" ]; then
      echo "        		  \"relay+ws://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "decryptwss" ]; then
      if [ -d "$HOME/gost_cert" ]; then
        echo "        		  \"relay+wss://:$s_port/$d_ip:$d_port?cert=/root/gost_cert/cert.pem&key=/root/gost_cert/key.pem\"" >>$gost_conf_path
      else
        echo "        		  \"relay+wss://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
      fi
    elif [ "$is_encrypt" == "ss" ]; then
      echo "        \"ss://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "socks" ]; then
      echo "        \"socks5://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "http" ]; then
      echo "        \"http://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    else
      echo "config error"
    fi
  else
    echo "config error"
    exit
  fi
}

function writeconf() {
  count_line=$(awk 'END{print NR}' $raw_conf_path)
  for ((i = 1; i <= $count_line; i++)); do
    if [ $i -eq 1 ]; then
      trans_conf=$(sed -n "${i}p" $raw_conf_path)
      eachconf_retrieve
      method
    elif [ $i -gt 1 ]; then
      if [ $i -eq 2 ]; then
        echo "    ],
    \"Routes\": [" >>$gost_conf_path
        trans_conf=$(sed -n "${i}p" $raw_conf_path)
        eachconf_retrieve
        multiconfstart
        method
        multiconflast
      else
        trans_conf=$(sed -n "${i}p" $raw_conf_path)
        eachconf_retrieve
        multiconfstart
        method
        multiconflast
      fi
    fi
  done
}
function show_all_conf() {
  echo -e "                      GOST Configuration                        "
  echo -e "-------------------------------------------------------------"
  echo -e "No. | Method    | Local Port | Destination Address:Port"
  echo -e "-------------------------------------------------------------"

  count_line=$(awk 'END{print NR}' $raw_conf_path)
  for ((i = 1; i <= $count_line; i++)); do
    trans_conf=$(sed -n "${i}p" $raw_conf_path)
    eachconf_retrieve

    if [ "$is_encrypt" == "nonencrypt" ]; then
      str="Non-encrypted Transit"
    elif [ "$is_encrypt" == "encrypttls" ]; then
      str=" TLS Tunnel "
    elif [ "$is_encrypt" == "encryptws" ]; then
      str="  WS Tunnel "
    elif [ "$is_encrypt" == "encryptwss" ]; then
      str=" WSS Tunnel "
    elif [ "$is_encrypt" == "peerno" ]; then
      str=" Non-encrypted Load Balancing "
    elif [ "$is_encrypt" == "peertls" ]; then
      str=" TLS Tunnel Load Balancing "
    elif [ "$is_encrypt" == "peerws" ]; then
      str="  WS Tunnel Load Balancing "
    elif [ "$is_encrypt" == "peerwss" ]; then
      str=" WSS Tunnel Load Balancing "
    elif [ "$is_encrypt" == "decrypttls" ]; then
      str=" TLS Decryption "
    elif [ "$is_encrypt" == "decryptws" ]; then
      str="  WS Decryption "
    elif [ "$is_encrypt" == "decryptwss" ]; then
      str=" WSS Decryption "
    elif [ "$is_encrypt" == "ss" ]; then
      str="   SS   "
    elif [ "$is_encrypt" == "socks" ]; then
      str=" SOCKS5 "
    elif [ "$is_encrypt" == "http" ]; then
      str=" HTTP "
    elif [ "$is_encrypt" == "cdnno" ]; then
      str="Non-encrypted CDN Transit"
    elif [ "$is_encrypt" == "cdnws" ]; then
      str="WS Tunnel CDN Transit"
    elif [ "$is_encrypt" == "cdnwss" ]; then
      str="WSS Tunnel CDN Transit"
    else
      str=""
    fi

    echo -e " $i  |$str  |$s_port\t|$d_ip:$d_port"
    echo -e "-------------------------------------------------------------"
  done
}

cron_restart() {
  echo -e "------------------------------------------------------------------"
  echo -e "GOST Scheduled Restart Task: "
  echo -e "-----------------------------------"
  echo -e "[1] Configure GOST Scheduled Restart Task"
  echo -e "[2] Delete GOST Scheduled Restart Task"
  echo -e "-----------------------------------"
  read -p "Select: " numcron
  if [ "$numcron" == "1" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "GOST Scheduled Restart Task Type: "
    echo -e "-----------------------------------"
    echo -e "[1] Restart every ? hours"
    echo -e "[2] Restart at ? o'clock daily"
    echo -e "-----------------------------------"
    read -p "Select: " numcrontype
    if [ "$numcrontype" == "1" ]; then
      echo -e "-----------------------------------"
      read -p "Restart every ? hours: " cronhr
      echo "0 0 */$cronhr * * ? * systemctl restart gost" >>/etc/crontab
      echo -e "Scheduled restart set successfully!"
    elif [ "$numcrontype" == "2" ]; then
      echo -e "-----------------------------------"
      read -p "Restart at ? o'clock daily: " cronhr
      echo "0 0 $cronhr * * ? systemctl restart gost" >>/etc/crontab
      echo -e "Scheduled restart set successfully!"
    else
      echo "type error, please try again"
      exit
    fi
  elif [ "$numcron" == "2" ]; then
    sed -i "/gost/d" /etc/crontab
    echo -e "Scheduled restart task deletion completed!"
  else
    echo "type error, please try again"
    exit
  fi
}

update_sh() {
  ol_version=$(curl -L -s --connect-timeout 5 https://raw.githubusercontent.com/KANIKIG/Multi-EasyGost/master/gost.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
  if [ -n "$ol_version" ]; then
    if [[ "$shell_version" != "$ol_version" ]]; then
      echo -e "A new version is available. Do you want to update? [Y/N]"
      read -r update_confirm
      case $update_confirm in
      [yY][eE][sS] | [yY])
        wget -N --no-check-certificate https://raw.githubusercontent.com/KANIKIG/Multi-EasyGost/master/gost.sh
        echo -e "Update completed."
        exit 0
        ;;
      *) ;;

      esac
    else
      echo -e "                 ${Green_font_prefix}The current version is the latest!${Font_color_suffix}"
    fi
  else
    echo -e "                 ${Red_font_prefix}Failed to fetch the latest script version. Please check your connection to GitHub!${Font_color_suffix}"
  fi
}

update_sh
echo && echo -e "                 GOST One-Click Install and Configuration Script"${Red_font_prefix}[${shell_version}]${Font_color_suffix}"
  ----------- KANIKIG -----------
  Features: (1) This script uses systemd and GOST configuration files to manage GOST.
        (2) It can simultaneously apply multiple forwarding rules without relying on other tools (such as screen).
        (3) Forwarding remains effective after a machine reboot.
  Functions: (1) Non-encrypted forwarding of TCP + UDP, (2) Encrypted forwarding on the relay machine, (3) Decryption and forwarding on the landing machine.
  Documentation: https://github.com/KANIKIG/Multi-EasyGost

 ${Green_font_prefix}1.${Font_color_suffix} Install GOST
 ${Green_font_prefix}2.${Font_color_suffix} Update GOST
 ${Green_font_prefix}3.${Font_color_suffix} Uninstall GOST
————————————
 ${Green_font_prefix}4.${Font_color_suffix} Start GOST
 ${Green_font_prefix}5.${Font_color_suffix} Stop GOST
 ${Green_font_prefix}6.${Font_color_suffix} Restart GOST
————————————
 ${Green_font_prefix}7.${Font_color_suffix} Add GOST forwarding configuration
 ${Green_font_prefix}8.${Font_color_suffix} View existing GOST configurations
 ${Green_font_prefix}9.${Font_color_suffix} Delete a GOST configuration
————————————
 ${Green_font_prefix}10.${Font_color_suffix} Configure scheduled restart for GOST
 ${Green_font_prefix}11.${Font_color_suffix} Customize TLS certificate configuration
————————————" && echo
read -e -p " Please enter a number [1-9]:" num

case "$num" in
1)
  Install_ct
  ;;
2)
  checknew
  ;;
3)
  Uninstall_ct
  ;;
4)
  Start_ct
  ;;
5)
  Stop_ct
  ;;
6)
  Restart_ct
  ;;
7)
  rawconf
  rm -rf /etc/gost/config.json
  confstart
  writeconf
  conflast
  systemctl restart gost
  echo -e "Configuration has been applied, current configuration is as follows"
  echo -e "--------------------------------------------------------"
  show_all_conf
  ;;
8)
  show_all_conf
  ;;
9)
  show_all_conf
  read -p "Please enter the configuration number you want to delete: " numdelete
  if echo $numdelete | grep -q '[0-9]'; then
    sed -i "${numdelete}d" $raw_conf_path
    rm -rf /etc/gost/config.json
    confstart
    writeconf
    conflast
    systemctl restart gost
    echo -e "Configuration has been deleted, service has been restarted"
  else
    echo "Please enter a valid number"
  fi
  ;;
10)
  cron_restart
  ;;
11)
  cert
  ;;
*)
  echo "Please enter a valid number [1-9]"
  ;;
esac

