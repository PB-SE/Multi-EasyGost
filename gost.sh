#! /bin/bash
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[Information]${Font_color_suffix}"
Error="${Red_font_prefix}[mistake]${Font_color_suffix}"
shell_version="1.1.1"
ct_new_ver="2.11.2" # 2.x No longer follow official updates
gost_conf_path="/etc/gost/config.json"
raw_conf_path="/etc/gost/rawconf"
function checknew() {
  checknew=$(gost -V 2>&1 | awk '{print $2}')
  # check_new_ver
  echo "Your gost version is:""$checknew"""
  echo -n do you want to update?\(y/n\)\:
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
    echo "Please enter your chip architecture，/386/armv5/armv6/armv7/armv8"
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
  [[ $EUID != 0 ]] && echo -e "${Error} The current non-ROOT account (or no ROOT permission) cannot continue the operation. Please change the ROOT account or use ${Green_background_prefix}sudo su${Font_color_suffix} Command to obtain temporary ROOT permissions (you may be prompted to enter the password of the current account after execution）。" && exit 1
}
function check_new_ver() {
  # deprecated
  ct_new_ver=$(wget --no-check-certificate -qO- -t2 -T3 https://api.github.com/repos/ginuerzh/gost/releases/latest | grep "tag_name" | head -n 1 | awk -F ":" '{print $2}' | sed 's/\"//g;s/,//g;s/ //g;s/v//g')
  if [[ -z ${ct_new_ver} ]]; then
    ct_new_ver="2.11.2"
    echo -e "${Error} gost Failed to obtain the latest version, downloading is in progressv${ct_new_ver}Version"
  else
    echo -e "${Info} gost The latest version is currenlty ${ct_new_ver}"
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
  echo -e "If it is a domestic machine, it is recommended to use a mainland image to speed up the download."
  read -e -p "Do you want to use?？[y/n]:" addyn
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
    wget --no-check-certificate https://mirror.ghproxy.com/https://github.com/ginuerzh/gost/releases/download/v"$ct_new_ver"/gost-linux-"$bit"-"$ct_new_ver".gz
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
    echo "gost Successful installation"
    rm -rf "$(pwd)"/gost
    rm -rf "$(pwd)"/gost.service
    rm -rf "$(pwd)"/config.json
  else
    echo "gost Installation not successful"
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
  echo "gost has been successfully deleted"
}
function Start_ct() {
  systemctl start gost
  echo "Started"
}
function Stop_ct() {
  systemctl stop gost
  echo "已停止"
}
function Restart_ct() {
  rm -rf /etc/gost/config.json
  confstart
  writeconf
  conflast
  systemctl restart gost
  echo "Configuration has been reread and restarted"
}
function read_protocol() {
  echo -e "What kind of function do you want to set?: "
  echo -e "-----------------------------------"
  echo -e "[1] tcp+udp traffic forwarding, no encryption"
  echo -e "Note: Generally set on domestic transit flights"
  echo -e "-----------------------------------"
  echo -e "[2] Encrypted tunnel traffic forwarding"
  echo -e "Description: Used to forward traffic with originally low encryption level, usually set on domestic transit planes"
  echo -e "    Selecting this protocol means that you still have a machine to receive this encrypted traffic, and then you must configure the protocol [3] on that machine for connection."
  echo -e "-----------------------------------"
  echo -e "[3] Decrypt the traffic transmitted by gost and forward it"
  echo -e "Description: For traffic transferred via gost encryption, use this option to decrypt and forward it to the proxy service port of the local machine or forward it to other remote machines."
  echo -e "      Generally set on foreign machines used to receive transit traffic"
  echo -e "-----------------------------------"
  echo -e "[4] Install ss/socks5/http proxy with one click"
  echo -e "Description: Use gost's built-in proxy protocol, which is lightweight and easy to manage."
  echo -e "-----------------------------------"
  echo -e "[5] Advanced: Multi-landing load balancing"
  echo -e "Description: Supports simple load balancing of various encryption methods"
  echo -e "-----------------------------------"
  echo -e "[6] 进阶：Advanced: forwarding CDN to selected nodes"
  echo -e "Note: Just set it on the transfer machine"
  echo -e "-----------------------------------"
  read -p "please choose: " numprotocol

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
    echo -e "Which port on this machine do you want to forward the traffic received?"
    read -p "please enter: " flag_b
  fi
}
function read_d_ip() {
  if [ "$flag_a" == "ss" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "Please tell me the ss encryption you want to set up (only the commonly used ones are provided): "
    echo -e "-----------------------------------"
    echo -e "[1] aes-256-gcm"
    echo -e "[2] aes-256-cfb"
    echo -e "[3] chacha20-ietf-poly1305"
    echo -e "[4] chacha20"
    echo -e "[5] rc4-md5"
    echo -e "[6] AEAD_CHACHA20_POLY1305"
    echo -e "-----------------------------------"
    read -p "Please select ss encryption method: " ssencrypt

    if [ "$ssencrypt" == "1" ]; then
      flag_c="aes-256-gcm"
    elif [ "$ssencrypt" == "2" ]; then
      flag_c="aes-256-cfb"
    elif [ "$ssencrypt" == "3" ]; then
      flag_c="chacha20-ietf-poly1305"
    elif [ "$ssencrypt" == "4" ]; then
      flag_c="chacha20"
    elif [ "$ssencrypt" == "5" ]; then
      flag_c="rc4-md5"
    elif [ "$ssencrypt" == "6" ]; then
      flag_c="AEAD_CHACHA20_POLY1305"
    else
      echo "type error, please try again"
      exit
    fi
  elif [ "$flag_a" == "socks" ]; then
    echo -e "-----------------------------------"
    read -p "Please enter socks user name: " flag_c
  elif [ "$flag_a" == "http" ]; then
    echo -e "-----------------------------------"
    read -p "Please enter http username: " flag_c
  elif [[ "$flag_a" == "peer"* ]]; then
    echo -e "------------------------------------------------------------------"
    echo -e "Please enter the landing list file name"
    read -e -p "Customized but different configurations should not be repeated, and there is no need to enter a suffix, such as ips1, iplist2:" flag_c
    touch $flag_c.txt
    echo -e "------------------------------------------------------------------"
    echo -e "Please enter the landing IP and port you want to load balance in sequence."
    while true; do
      echo -e "Would you like to change this machine from${flag_b}Which IP or domain name is the received traffic forwarded to?"
      read -p "please enter: " peer_ip
      echo -e "Would you like to change this machine from${flag_b}Received traffic is forwarded to${peer_ip}Which port?"
      read -p "please enter: " peer_port
      echo -e "$peer_ip:$peer_port" >>$flag_c.txt
      read -e -p "Do you want to continue adding landings?[Y/n]:" addyn
      [[ -z ${addyn} ]] && addyn="y"
      if [[ ${addyn} == [Nn] ]]; then
        echo -e "------------------------------------------------------------------"
        echo -e "Created in root directory$flag_c.txt，You can edit this file to modify the landing information at any time, and it will take effect after restarting gost."
        echo -e "------------------------------------------------------------------"
        break
      else
        echo -e "------------------------------------------------------------------"
        echo -e "Continue to add balanced load landing configuration"
      fi
    done
  elif [[ "$flag_a" == "cdn"* ]]; then
    echo -e "------------------------------------------------------------------"
    echo -e "Change this machine from${flag_b}Optional direction for forwarding received traffic ip:"
    read -p "please enter: " flag_c
    echo -e "Would you like to change this machine from${flag_b}Received traffic is forwarded to${flag_c}Which port?"
    echo -e "[1] 80"
    echo -e "[2] 443"
    echo -e "[3] Custom port (such as 8080, etc.)"
    read -p "Please select a port: " cdnport
    if [ "$cdnport" == "1" ]; then
      flag_c="$flag_c:80"
    elif [ "$cdnport" == "2" ]; then
      flag_c="$flag_c:443"
    elif [ "$cdnport" == "3" ]; then
      read -p "Please enter custom port: " customport
      flag_c="$flag_c:$customport"
    else
      echo "type error, please try again"
      exit
    fi
  else
    echo -e "------------------------------------------------------------------"
    echo -e "Would you like to change this machine from${flag_b}To which IP or domain name is the received traffic forwarded?"
    echo -e "Note: The IP can be either the public IP of [remote machine/current machine], or the local loopback IP of this machine (i.e. 127.0.0.1)"
    echo -e "Filling in the specific IP address depends on the IP that the service receiving the traffic is monitoring (for details, see): https://github.com/KANIKIG/Multi-EasyGost)"
    if [[ ${is_cert} == [Yy] ]]; then
      echo -e "Note: When turning on the custom tls certificate on the floor machine, be sure to fill it in${Red_font_prefix}domain name${Font_color_suffix}"
    fi
    read -p "please enter: " flag_c
  fi
}
function read_d_port() {
  if [ "$flag_a" == "ss" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "Do you want to set the port of the ss proxy service?"
    read -p "please enter: " flag_d
  elif [ "$flag_a" == "socks" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "Do you want to set the port of the socks proxy service?"
    read -p "please enter: " flag_d
  elif [ "$flag_a" == "http" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "Do you want to set the port of the http proxy service?"
    read -p "please enter: " flag_d
  elif [[ "$flag_a" == "peer"* ]]; then
    echo -e "------------------------------------------------------------------"
    echo -e "The load balancing policy you want to set: "
    echo -e "-----------------------------------"
    echo -e "[1] round - polling"
    echo -e "[2] random - random"
    echo -e "[3] fifo - top down"
    echo -e "-----------------------------------"
    read -p "Please select a balancing load type: " numstra

    if [ "$numstra" == "1" ]; then
      flag_d="round"
    elif [ "$numstra" == "2" ]; then
      flag_d="random"
    elif [ "$numstra" == "3" ]; then
      flag_d="fifo"
    else
      echo "type error, please try again"
      exit
    fi
  elif [[ "$flag_a" == "cdn"* ]]; then
    echo -e "------------------------------------------------------------------"
    read -p "Please enter host:" flag_d
  else
    echo -e "------------------------------------------------------------------"
    echo -e "Would you like to change this machine from${flag_b}Received traffic is forwarded to${flag_c}Which port?"
    read -p "please enter: " flag_d
    if [[ ${is_cert} == [Yy] ]]; then
      flag_d="$flag_d?secure=true"
    fi
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
  echo -e "What type of forwarding transmission do you want to set: "
  echo -e "-----------------------------------"
  echo -e "[1] tls tunnel"
  echo -e "[2] ws tunnel"
  echo -e "[3] wss tunnel"
  echo -e "Note: For the same forwarding, the transfer and landing transmission types must correspond! This script enables tcp+udp by default"
  echo -e "-----------------------------------"
  read -p "Please select a forwarding transfer type: " numencrypt

  if [ "$numencrypt" == "1" ]; then
    flag_a="encrypttls"
    echo -e "Note: Select Yes to enable certificate verification for the custom certificate for landing to ensure security. Be sure to fill in the landing machine later.${Red_font_prefix}domain name${Font_color_suffix}"
    read -e -p "Is the custom tls certificate enabled on the floor machine?[y/n]:" is_cert
  elif [ "$numencrypt" == "2" ]; then
    flag_a="encryptws"
  elif [ "$numencrypt" == "3" ]; then
    flag_a="encryptwss"
    echo -e "Note: Select Yes to enable certificate verification for the custom certificate for landing to ensure security. Be sure to fill in the landing machine later.${Red_font_prefix}domain name${Font_color_suffix}"
    read -e -p "Is the custom tls certificate enabled on the floor machine?[y/n]:" is_cert
  else
    echo "type error, please try again"
    exit
  fi
}
function enpeer() {
  echo -e "What type of load balancing transmission do you want to set: "
  echo -e "-----------------------------------"
  echo -e "[1] Forwarding without encryption"
  echo -e "[2] tls tunnel"
  echo -e "[3] ws tunnel"
  echo -e "[4] wss tunnel"
  echo -e "Note: For the same forwarding, the transfer and landing transmission types must correspond! This script defaults to the same transmission type for the same configuration"
  echo -e "This script only supports simple load balancing. Please refer to the official documentation for details."
  echo -e "gost balanced load official document：https://docs.ginuerzh.xyz/gost/load-balancing"
  echo -e "-----------------------------------"
  read -p "Please select a forwarding transfer type: " numpeer

  if [ "$numpeer" == "1" ]; then
    flag_a="peerno"
  elif [ "$numpeer" == "2" ]; then
    flag_a="peertls"
  elif [ "$numpeer" == "3" ]; then
    flag_a="peerws"
  elif [ "$numpeer" == "4" ]; then
    flag_a="peerwss"

  else
    echo "type error, please try again"
    exit
  fi
}
function cdn() {
  echo -e "Please tell me the CDN transmission type you want to set: "
  echo -e "-----------------------------------"
  echo -e "[1] Forwarding without encryption"
  echo -e "[2] ws tunnel"
  echo -e "[3] wss tunnel"
  echo -e "Note: For the same forwarding, the transfer and landing transmission types must correspond！"
  echo -e "This function only needs to be set on the transit machine"
  echo -e "-----------------------------------"
  read -p "Select CDN forwarding transfer type: " numcdn

  if [ "$numcdn" == "1" ]; then
    flag_a="cdnno"
  elif [ "$numcdn" == "2" ]; then
    flag_a="cdnws"
  elif [ "$numcdn" == "3" ]; then
    flag_a="cdnwss"
  else
    echo "type error, please try again"
    exit
  fi
}
function cert() {
  echo -e "-----------------------------------"
  echo -e "[1] ACME Apply for a certificate with one click"
  echo -e "[2] Manually upload certificate"
  echo -e "-----------------------------------"
  echo -e "Note: It is only used for floor-standing machine configuration. The built-in certificate of gost used by default may cause security problems. Use a custom certificate to improve security."
  echo -e "    After configuration, all tls/wss decryption will take effect on this machine, no need to set it again."
  read -p "Please select the certificate generation method: " numcert

  if [ "$numcert" == "1" ]; then
    check_sys
    if [[ ${release} == "centos" ]]; then
      yum install -y socat
    else
      apt-get install -y socat
    fi
    read -p "Please enter your ZeroSSL account email address (go to zerossl.com to register)：" zeromail
    read -p "Please enter the domain name resolved to this machine：" domain
    curl https://get.acme.sh | sh
    "$HOME"/.acme.sh/acme.sh --set-default-ca --server zerossl
    "$HOME"/.acme.sh/acme.sh --register-account -m "${zeromail}" --server zerossl
    echo -e "ACME certificate application program installed successfully"
    echo -e "-----------------------------------"
    echo -e "[1] HTTP application (requires port 80 to be unoccupied)"
    echo -e "[2] Cloudflare DNS API application (requires entering APIKEY)"
    echo -e "-----------------------------------"
    read -p "Please select the certificate application method: " certmethod
    if [ "certmethod" == "1" ]; then
      echo -e "Please confirm this machine${Red_font_prefix}80${Font_color_suffix}The port is not occupied, otherwise the application will fail"
      if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force; then
        echo -e "The SSL certificate is generated successfully and a high-security ECC certificate is applied by default."
        if [ ! -d "$HOME/gost_cert" ]; then
          mkdir $HOME/gost_cert
        fi
        if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath $HOME/gost_cert/cert.pem --keypath $HOME/gost_cert/key.pem --ecc --force; then
          echo -e "The The SSL certificate is configured successfully and will be automatically renewed. The certificate and key are located in the user directory. ${Red_font_prefix}gost_cert${Font_color_suffix} Table of contents"
          echo -e "Do not change the certificate directory name and certificate file name; delete the gost_cert directory and restart with the script, which will automatically enable the gost built-in certificate."
          echo -e "-----------------------------------"
        fi
      else
        echo -e "SSL certificate generation failed"
        exit 1
      fi
    else
      read -p "Please enter your Cloudflare account email address：" cfmail
      read -p "please enter Cloudflare Global API Key：" cfkey
      export CF_Key="${cfkey}"
      export CF_Email="${cfmail}"
      if "$HOME"/.acme.sh/acme.sh --issue --dns dns_cf -d "${domain}" --standalone -k ec-256 --force; then
        echo -e "The SSL certificate is generated successfully and a high-security ECC certificate is applied by default."
        if [ ! -d "$HOME/gost_cert" ]; then
          mkdir $HOME/gost_cert
        fi
        if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath $HOME/gost_cert/cert.pem --keypath $HOME/gost_cert/key.pem --ecc --force; then
          echo -e "The SSL certificate is configured successfully and will be automatically renewed. The certificate and key are located in the user directory ${Red_font_prefix}gost_cert${Font_color_suffix} Table of contents"
          echo -e "Do not change the certificate directory name and certificate file name; delete the gost_cert directory and use the script to restart, that is, re-enable the gost built-in certificate"
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
    echo -e "Created in user directory ${Red_font_prefix}gost_cert${Font_color_suffix} Directory, please upload the certificate file cert.pem and the secret key file key.pem to this directory."
    echo -e "The certificate and secret key file names must be consistent with the above, and the directory name must not be changed."
    echo -e "After the upload is successful, restart gost with a script and it will be automatically enabled, no need to set it up again; delete the gost_cert directory and restart with a script, that is, re-enable gost's built-in certificate"
    echo -e "-----------------------------------"
  else
    echo "type error, please try again"
    exit
  fi
}
function decrypt() {
  echo -e "Please tell me the decryption transmission type you want to set: "
  echo -e "-----------------------------------"
  echo -e "[1] tls"
  echo -e "[2] ws"
  echo -e "[3] wss"
  echo -e "Note: For the same forwarding, the transfer and landing transmission types must correspond! This script enables tcp+udp by default"
  echo -e "-----------------------------------"
  read -p "Please select a decryption transfer type: " numdecrypt

  if [ "$numdecrypt" == "1" ]; then
    flag_a="decrypttls"
  elif [ "$numdecrypt" == "2" ]; then
    flag_a="decryptws"
  elif [ "$numdecrypt" == "3" ]; then
    flag_a="decryptwss"
  else
    echo "type error, please try again"
    exit
  fi
}
function proxy() {
  echo -e "------------------------------------------------------------------"
  echo -e "What type of proxy do you want to set up: "
  echo -e "-----------------------------------"
  echo -e "[1] shadowsocks"
  echo -e "[2] socks5 (It is strongly recommended to add a tunnel for Telegram proxy)"
  echo -e "[3] http"
  echo -e "-----------------------------------"
  read -p "Please select agent type: " numproxy
  if [ "$numproxy" == "1" ]; then
    flag_a="ss"
  elif [ "$numproxy" == "2" ]; then
    flag_a="socks"
  elif [ "$numproxy" == "3" ]; then
    flag_a="http"
  else
    echo "type error, please try again"
    exit
  fi
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
  echo -e "                      GOST configuration                        "
  echo -e "--------------------------------------------------------"
  echo -e "Serial number|Method\t|Local port\t|Destination address:destination port"
  echo -e "--------------------------------------------------------"

  count_line=$(awk 'END{print NR}' $raw_conf_path)
  for ((i = 1; i <= $count_line; i++)); do
    trans_conf=$(sed -n "${i}p" $raw_conf_path)
    eachconf_retrieve

    if [ "$is_encrypt" == "nonencrypt" ]; then
      str="Transfer without encryption"
    elif [ "$is_encrypt" == "encrypttls" ]; then
      str=" tls tunnel "
    elif [ "$is_encrypt" == "encryptws" ]; then
      str="  ws tunnel "
    elif [ "$is_encrypt" == "encryptwss" ]; then
      str=" wss tunnel "
    elif [ "$is_encrypt" == "peerno" ]; then
      str=" Load balancing without encryption "
    elif [ "$is_encrypt" == "peertls" ]; then
      str=" tls tunnel load balancing "
    elif [ "$is_encrypt" == "peerws" ]; then
      str="  ws tunnel load balancing"
    elif [ "$is_encrypt" == "peerwss" ]; then
      str=" wss tunnel load balancing "
    elif [ "$is_encrypt" == "decrypttls" ]; then
      str=" tls decryption "
    elif [ "$is_encrypt" == "decryptws" ]; then
      str="  ws decryption "
    elif [ "$is_encrypt" == "decryptwss" ]; then
      str=" wss decryption"
    elif [ "$is_encrypt" == "ss" ]; then
      str="   ss   "
    elif [ "$is_encrypt" == "socks" ]; then
      str=" socks5 "
    elif [ "$is_encrypt" == "http" ]; then
      str=" http "
    elif [ "$is_encrypt" == "cdnno" ]; then
      str="Forwarding CDN without encryption"
    elif [ "$is_encrypt" == "cdnws" ]; then
      str="ws tunnel forwarding CDN"
    elif [ "$is_encrypt" == "cdnwss" ]; then
      str="wss tunnel forwarding CDN"
    else
      str=""
    fi

    echo -e " $i  |$str  |$s_port\t|$d_ip:$d_port"
    echo -e "--------------------------------------------------------"
  done
}

cron_restart() {
  echo -e "------------------------------------------------------------------"
  echo -e "gost schedules restart tasks: "
  echo -e "-----------------------------------"
  echo -e "[1] Configure gost scheduled restart tasks"
  echo -e "[2] Delete gost scheduled restart task"
  echo -e "-----------------------------------"
  read -p "please choose: " numcron
  if [ "$numcron" == "1" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "gost scheduled restart task type: "
    echo -e "-----------------------------------"
    echo -e "[1] Every? (hour restart)"
    echo -e "[2] daily? (Click restart)"
    echo -e "-----------------------------------"
    read -p "please choose:" numcrontype
    if [ "$numcrontype" == "1" ]; then
      echo -e "-----------------------------------"
      read -p "Every? (hourly restart): " cronhr
      echo "0 0 */$cronhr * * ? * systemctl restart gost" >>/etc/crontab
      echo -e "The scheduled restart setting is successful!"
    elif [ "$numcrontype" == "2" ]; then
      echo -e "-----------------------------------"
      read -p "daily? Click restart: " cronhr
      echo "0 0 $cronhr * * ? systemctl restart gost" >>/etc/crontab
      echo -e "The scheduled restart setting is successful!"
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
      echo -e "There is a new version, do you want to update? [Y/N]?"
      read -r update_confirm
      case $update_confirm in
      [yY][eE][sS] | [yY])
        wget -N --no-check-certificate https://raw.githubusercontent.com/KANIKIG/Multi-EasyGost/master/gost.sh
        echo -e "update completed"
        exit 0
        ;;
      *) ;;

      esac
    else
      echo -e "                 ${Green_font_prefix}The current version is the latest version！${Font_color_suffix}"
    fi
  else
    echo -e "                 ${Red_font_prefix}Failed to obtain the latest version of the script, please check the connection to github！${Font_color_suffix}"
  fi
}

update_sh
echo && echo -e "                 gost One-click installation configuration script"${Red_font_prefix}[${shell_version}]${Font_color_suffix}"
  ----------- KANIKIG -----------
  Features: (1) This script uses systemd and gost configuration files to manage gost
        (2) Able to realize multiple forwarding rules taking effect at the same time without using other tools (such as screen)
        (3) Forwarding does not fail after the machine reboots
  Functions: (1) tcp+udp unencrypted forwarding, (2) transit machine encrypted forwarding, (3) landing machine decryption and docking forwarding
  Help documentation：https://github.com/KANIKIG/Multi-EasyGost

 ${Green_font_prefix}1.${Font_color_suffix} install gost
 ${Green_font_prefix}2.${Font_color_suffix} renew gost
 ${Green_font_prefix}3.${Font_color_suffix} uninstall gost
————————————
 ${Green_font_prefix}4.${Font_color_suffix} start up gost
 ${Green_font_prefix}5.${Font_color_suffix} stop gost
 ${Green_font_prefix}6.${Font_color_suffix} Restart gost
————————————
 ${Green_font_prefix}7.${Font_color_suffix} Added gost forwarding configuration
 ${Green_font_prefix}8.${Font_color_suffix} View existing gost configuration
 ${Green_font_prefix}9.${Font_color_suffix} Delete a gost configuration
————————————
 ${Green_font_prefix}10.${Font_color_suffix} gost scheduled restart configuration
 ${Green_font_prefix}11.${Font_color_suffix} Custom TLS certificate configuration
————————————" && echo
read -e -p " Please enter the number [1-9]:" num
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
  echo -e "The configuration has taken effect. The current configuration is as follows"
  echo -e "--------------------------------------------------------"
  show_all_conf
  ;;
8)
  show_all_conf
  ;;
9)
  show_all_conf
  read -p "Please enter the configuration number you want to delete：" numdelete
  if echo $numdelete | grep -q '[0-9]'; then
    sed -i "${numdelete}d" $raw_conf_path
    rm -rf /etc/gost/config.json
    confstart
    writeconf
    conflast
    systemctl restart gost
    echo -e "The configuration has been deleted and the service has been restarted"
  else
    echo "Please enter the correct number"
  fi
  ;;
10)
  cron_restart
  ;;
11)
  cert
  ;;
*)
  echo "please enter the correct number [1-9]"
  ;;
esac
