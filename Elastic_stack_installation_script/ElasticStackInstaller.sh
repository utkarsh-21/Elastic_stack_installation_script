#!/bin/bash
# Installation Script (Elasticsearch, Logstash, Kibana & Nginx)
# 

# Description: This script installs every single component of the ELK Stack plus Nginx


LOGFILE="/var/log/Elastic-install.log"


echoerror() {
    printf "${RC} * ERROR${EC}: $@\n" 1>&2;
}


# installing updates

apt-get update >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install updates (Error Code: $ERROR)."
    fi



echo "Starting Elastic Stack installation...."
echo "Enter credentials for accessing the web Elastic Stack console"

read -p 'Username: ' nginxUsername

while true; do
    read -p 'Password: ' passvar1
    echo
    read -p 'Verify Password: ' passvar2
    echo
    [ "$passvar1" == "$passvar2" ] && break
    echo "Passwords do not match..."
done

# echo "[ELK INFO] Commenting out CDROM in /etc/apt/sources.list.."
# sed -i '5s/^/#/' /etc/apt/sources.list >> $LOGFILE 2>&1

echo "[ELK INFO] Installing updates.."
apt-get update >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install updates (Error Code: $ERROR)."
        exit
    fi


echo "[ELK INFO] Installing JDK"

apt-get install -y openjdk-8-jre >> $LOGFILE 2>&1

# source /etc/environment 2>&1

# echo "JAVA_HOME=/usr/bin/java" >> /etc/environment 2>&1
# source /etc/environment 2>&1

# ERROR=$?
#     if [ $ERROR -ne 0 ]; then
#         echoerror "Could not install JDK (Error Code: $ERROR)."
#         echo $ERROR
#     fi



# Elastic signs all of their packages with their own Elastic PGP signing key.
echo "[ELK INFO] Downloading and installing (writing to a file) the public signing key to the host.."
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add - >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not write the public signing key to the host (Error Code: $ERROR)."
    fi

# Before installing elasticsearch, we have to set the elastic packages definitions to our source list.
# For this step, elastic recommends to have "apt-transport-https" installed already or install it before adding the elasticsearch apt repository source list definition to your /etc/apt/sources.list
echo "Installing apt-transport-https.."
apt-get install apt-transport-https >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install apt-transport-https (Error Code: $ERROR)."
    fi

echo "[ELK INFO] Adding elastic packages source list definitions to your sources list.."
echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not add elastic packages source list definitions to your source list (Error Code: $ERROR)."
    fi

echo "[ELK INFO] Installing updates.."
apt-get update >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install updates (Error Code: $ERROR)."
    fi

 

# *********** Installing Elasticsearch ***************
echo "[ELK INFO] Installing Elasticsearch.."
apt-get install elasticsearch >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install elasticsearch (Error Code: $ERROR)."
    fi
    
echo "[ELK INFO] Creating a backup of Elasticsearch's original yml file.."
cp /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/backup_elasticsearch.yml >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not create a backup of the elasticsearch.yml config (Error Code: $ERROR)."
    fi
    
echo "[ELK INFO] editing /etc/elasticsearch/elasticsearch.yml.."
sed -i 's/#network.host.*/network.host: 0.0.0.0 /g' /etc/elasticsearch/elasticsearch.yml >> $LOGFILE 2>&1
sed -i 's/#http.port.*/http.port: 9200/g' /etc/elasticsearch/elasticsearch.yml >> $LOGFILE 2>&1

ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not edit elasticsearch config (Error Code: $ERROR)."
    fi
    
echo "[ELK INFO] Starting elasticsearch and setting elasticsearch to start automatically when the system boots.."
systemctl daemon-reload >> $LOGFILE 2>&1
systemctl enable elasticsearch.service >> $LOGFILE 2>&1
systemctl start elasticsearch.service >> $LOGFILE 2>&1
service elasticsearch restart
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not start elasticsearch and set elasticsearch to start automatically when the system boots (Error Code: $ERROR)."
    fi






# *********** Installing Kibana ***************
echo "[ELK INFO] Installing Kibana.."
apt-get install -y kibana >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install kibana (Error Code: $ERROR)."
    fi
    
echo "[ELK INFO] Creating a backup of Kibana's original yml file.."
cp /etc/kibana/kibana.yml /etc/kibana/backup_kibana.yml >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not create a backup of Kibana's original yml file (Error Code: $ERROR)."
    fi
    
echo "[ELK INFO] editing /etc/kibana/kibana.yml.."
sed -i 's/#server.port:.*/server.port: 5601/g' /etc/kibana/kibana.yml >> $LOGFILE 2>&1
sed -i 's/#elasticsearch.hosts:.*/elasticsearch.url: \"http:\/\/localhost:9200\"/g' /etc/kibana/kibana.yml >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not edit kibana.yml file (Error Code: $ERROR)."
    fi
    
echo "[ELK INFO] Starting kibana and setting kibana to start automatically when the system boots.."
systemctl daemon-reload >> $LOGFILE 2>&1
systemctl enable kibana.service >> $LOGFILE 2>&1
systemctl start kibana.service >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not start kibana and set kibana to start automatically when the system boots (Error Code: $ERROR)."
    fi



# *********** Installing Nginx ***************
echo "[ELK INFO] Installing Nginx.."
apt-get install -y nginx >> $LOGFILE 2>&1
apt-get install -y nginx apache2-utils >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install nginx (Error Code: $ERROR)."
    fi
    
echo "[ELK INFO] Adding a user ' $nginxUsername '::' $passvar1 'htpasswd.users file to nginx.."
htpasswd -b -c /etc/nginx/htpasswd.users $nginxUsername $passvar1 >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not add user Hunter to htpasswd.users file (Error Code: $ERROR)."
    fi
    
echo "[ELK INFO] Backing up Nginx's config file.."
cp /etc/nginx/sites-available/default /etc/nginx/sites-available/backup_default >> $LOGFILE 2>&1
sudo truncate -s 0 /etc/nginx/sites-available/default >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not create a backup of nginx config file (Error Code: $ERROR)."
    fi
    
echo "[ELK INFO] Creating custom nginx config file to /etc/nginx/sites-available/default.."

echo "
server {
    listen 80;

    server_name example.com;

    auth_basic \"Restricted Access\";
    auth_basic_user_file /etc/nginx/htpasswd.users;

    location / {
        proxy_pass http://localhost:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
" >> /etc/nginx/sites-available/default

ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not create custom nginx file (Error Code: $ERROR)."
    fi
    
echo "[ELK INFO] testing nginx configuration.."
nginx -t >> $LOGFILE 2>&1

echo "[ELK INFO] Restarting nginx service.."
systemctl restart nginx >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not restart nginx (Error Code: $ERROR)."
    fi

sudo systemctl restart nginx



# *********** Installing Logstash ***************  checked 
echo "[ELK INFO] Installing Logstash.."
apt-get install logstash >> $LOGFILE 2>&1
ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install logstash (Error Code: $ERROR)."
    fi
 
echo "[ELK INFO] Creating logstash's .conf files.."



ELASTICSEARCHOUTPUT="
input {
udp {
port => 10514
codec => cef
host => \"10.2.0.41\"
}
}

filter {
geoip {
source => \"sourceAddress\"
target => \"src_geoip\"
}
geoip{
source => \"destinationAddress\"
target => \"dst_geoip\"
} 
mutate {
convert => { \"GigamonMdata_krb5_ticket_name_type\" => \"integer\" }
convert => { \"GigamonMdata_krb5_pa_data_type\" => \"integer\" }
convert => { \"GigamonMdata_krb5_err_cname_type\" => \"integer\" }
convert => { \"GigamonMdata_krb5_enc_data_type\" => \"integer\" }
convert => { \"GigamonMdata_krb5_err_sname_type\" => \"integer\" }
convert => { \"GigamonMdata_krb5_cname_type\" => \"integer\" }
convert => { \"GigamonMdata_http_code\" => \"integer\" }
convert => { \"GigamonMdata_http_video_height\" => \"integer\" }
convert => { \"GigamonMdata_http_user_agent_start_offset\" => \"integer\" }
convert => { \"GigamonMdata_http_start_time\" => \"integer\" }
convert => { \"GigamonMdata_http_uri_start_offset\" => \"integer\" }
convert => { \"GigamonMdata_http_video_duration\" => \"integer\" }
convert => { \"GigamonMdata_http_index\" => \"integer\" }
convert => { \"GigamonMdata_http_video_avgdatarate\" => \"integer\" }
convert => { \"GigamonMdata_http_total_datarate\" => \"integer\" }
convert => { \"GigamonMdata_http_video_lasttimestamp\" => \"integer\" }
convert => { \"GigamonMdata_http_ntlm_message_type\" => \"integer\" }
convert => { \"GigamonMdata_http_video_firsttimestamp\" => \"integer\" }
convert => { \"GigamonMdata_http_video_width\" => \"integer\" }
convert => { \"GigamonMdata_http_decompress_size\" => \"integer\" }
convert => { \"GigamonMdata_http_image_width\" => \"integer\" }
convert => { \"GigamonMdata_http_audio_datarate\" => \"integer\" }
convert => { \"GigamonMdata_http_header_end_offset\" => \"integer\" }
convert => { \"GigamonMdata_http_video_totalduration\" => \"integer\" }
convert => { \"GigamonMdata_http_dechunk_size\" => \"integer\" }
convert => { \"GigamonMdata_http_video_datarate\" => \"integer\" }
convert => { \"GigamonMdata_http_chunk_size\" => \"integer\" }
convert => { \"GigamonMdata_http_host_start_offset\" => \"integer\" }
convert => { \"GigamonMdata_http_video_framerate\" => \"integer\" }
convert => { \"GigamonMdata_http_image_height\" => \"integer\" }
convert => { \"GigamonMdata_rdp_encrypted\" => \"integer\" }
convert => { \"GigamonMdata_rdp_desktop_height\" => \"integer\" }
convert => { \"GigamonMdata_rdp_keyboard_subtype\" => \"integer\" }
convert => { \"GigamonMdata_rdp_serial_number\" => \"integer\" }
convert => { \"GigamonMdata_rdp_desktop_width\" => \"integer\" }
convert => { \"GigamonMdata_rdp_keyboard_type\" => \"integer\" }
convert => { \"GigamonMdata_rdp_io_channel_id\" => \"integer\" }
convert => { \"GigamonMdata_rdp_keyboard_function_key\" => \"integer\" }
convert => { \"GigamonMdata_rdp_channel_disabled\" => \"integer\" }
convert => { \"GigamonMdata_rdp_channel_id\" => \"integer\" }
convert => { \"GigamonMdata_rdp_client_build\" => \"integer\" }
convert => { \"GigamonMdata_smtp_attach_size_decoded\" => \"integer\" }
convert => { \"GigamonMdata_smtp_attach_size\" => \"integer\" }
convert => { \"GigamonMdata_smtp_response_code\" => \"integer\" }
convert => { \"GigamonMdata_ssl_index\" => \"integer\" }
convert => { \"GigamonMdata_radius_nas_port_type\" => \"integer\" }
convert => { \"GigamonMdata_radius_acct_output_octets\" => \"integer\" }
convert => { \"GigamonMdata_radius_acct_input_octets\" => \"integer\" }
convert => { \"GigamonMdata_radius_avp_vendor_id\" => \"integer\" }
convert => { \"GigamonMdata_radius_avp_int\" => \"integer\" }
convert => { \"GigamonMdata_radius_idle_timeout\" => \"integer\" }
convert => { \"GigamonMdata_radius_nas_port\" => \"integer\" }
convert => { \"GigamonMdata_radius_3gpp_sgsn_mcc_mnc\" => \"integer\" }
convert => { \"GigamonMdata_radius_terminate_cause\" => \"integer\" }
convert => { \"GigamonMdata_radius_session_timeout\" => \"integer\" }
convert => { \"GigamonMdata_dns_krb5_message_type\" => \"integer\" }
convert => { \"GigamonMdata_dns_ttl\" => \"integer\" }
convert => { \"GigamonMdata_dns_krb5_ticket_name_type\" => \"integer\" }
convert => { \"GigamonMdata_dns_nscount\" => \"integer\" }
convert => { \"GigamonMdata_dns_arcount\" => \"integer\" }
convert => { \"GigamonMdata_dns_opcode\" => \"integer\" }
convert => { \"GigamonMdata_dns_krb5_pa_data_type\" => \"integer\" }
convert => { \"GigamonMdata_dns_qdcount\" => \"integer\" }
convert => { \"GigamonMdata_dns_krb5_err_sname_type\" => \"integer\" }
convert => { \"GigamonMdata_dns_krb5_enc_data_type\" => \"integer\" }
convert => { \"GigamonMdata_dns_krb5_err_cname_type\" => \"integer\" }
convert => { \"GigamonMdata_dns_transaction_id\" => \"integer\" }
convert => { \"GigamonMdata_dns_ancount\" => \"integer\" }
convert => { \"GigamonMdata_dhcp_xid\" => \"integer\" }
convert => { \"GigamonMdata_dhcp_ip_lease_time\" => \"integer\" }
convert => { \"GigamonMdata_dhcp_end_status\" => \"integer\" }
convert => { \"GigamonMdata_smb_krb5_message_type\" => \"integer\" }
convert => { \"GigamonMdata_smb_search_attributes\" => \"integer\" }
convert => { \"GigamonMdata_smb_krb5_ticket_name_type\" => \"integer\" }
convert => { \"GigamonMdata_smb_create_options\" => \"integer\" }
convert => { \"GigamonMdata_smb_ext_attributes\" => \"integer\" }
convert => { \"GigamonMdata_smb_session_key\" => \"integer\" }
convert => { \"GigamonMdata_smb_user_id\" => \"integer\" }
convert => { \"GigamonMdata_smb_security_blob_len\" => \"integer\" }
convert => { \"GigamonMdata_smb_dcerpc_call_id\" => \"integer\" }
convert => { \"GigamonMdata_smb_search_storage_type\" => \"integer\" }
convert => { \"GigamonMdata_smb_version\" => \"integer\" }
convert => { \"GigamonMdata_smb_file_chunk_len\" => \"integer\" }
convert => { \"GigamonMdata_smb_krb5_pa_data_type\" => \"integer\" }
convert => { \"GigamonMdata_smb_nt_status\" => \"integer\" }
convert => { \"GigamonMdata_smb_create_action\" => \"integer\" }
convert => { \"GigamonMdata_smb_file_attributes\" => \"integer\" }
convert => { \"GigamonMdata_smb_process_id\" => \"integer\" }
convert => { \"GigamonMdata_smb_attributes\" => \"integer\" }
convert => { \"GigamonMdata_smb_ntlm_message_type\" => \"integer\" }
convert => { \"GigamonMdata_smb_krb5_err_sname_type\" => \"integer\" }
convert => { \"GigamonMdata_smb_share_access\" => \"integer\" }
convert => { \"GigamonMdata_smb_krb5_enc_data_type\" => \"integer\" }
convert => { \"GigamonMdata_smb_krb5_err_cname_type\" => \"integer\" }
convert => { \"GigamonMdata_smb_tree_id\" => \"integer\" }
convert => { \"GigamonApplicationID\" => \"integer\" }
convert => { \"GigamonMdataIngressVlanId\" => \"integer\" }
convert => { \"GigamonMdataIpVer\" => \"integer\" }
convert => { \"proto\" => \"integer\" }
convert => { \"spt\" => \"integer\" }
convert => { \"dpt\" => \"integer\" }
convert => { \"GigamonMdataTcpFlags\" => \"integer\" }
convert => { \"deviceInboundInterface\" => \"integer\" }
convert => { \"GigamonTotalPackets\" => \"integer\" }
convert => { \"GigamonTotalPacketsReverse\" => \"integer\" }
convert => { \"GigamonMdataFlowEndReason\" => \"integer\" }
convert => { \"GigamonTotalBytes\" => \"integer\" }
convert => { \"GigamonTotalBytesReverse\" => \"integer\" }
convert => { \"GigamonFlowID\" => \"integer\" }

}
}

output {
elasticsearch { hosts => [\"localhost:9200\"] }
}
"
touch /etc/logstash/conf.d/cef_events.conf
echo "$ELASTICSEARCHOUTPUT" >> /etc/logstash/conf.d/cef_events.conf

ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not create custom logstash file /etc/logstash/conf.d/cef_events.conf (Error Code: $ERROR)."
    fi
    
echo "[ELK INFO] Starting logstash and setting Logstash to start automatically when the system boots.."

systemctl daemon-reload >> $LOGFILE 2>&1
systemctl enable logstash >> $LOGFILE 2>&1
systemctl start logstash >> $LOGFILE 2>&1
systemctl restart logstash >> $LOGFILE 2>&1
service logstash restart


ERROR=$?
      if [ $ERROR -ne 0 ]; then
        echoerror "Could not start logstash and set it to start automatically when the system boots (Error Code: $ERROR)"
      fi
echo "**********************************************************************************************************"
echo " "
echo "[ELK INFO] Your ELK has been installed"
echo "[ELK INFO] Browse to your Ubuntu Server and sign-in:"
echo " "
echo " "
echo " "
echo "If you experience problem starting logstash like:"
echo " "
echo "Unrecognized VM option 'UseParNewGC'"
echo "Error: Could not create the Java Virtual Machine"
echo "you have to install Java 8 instead and update alternatives as follow:"
echo " "
echo "apt-get install openjdk-8-jre"
echo "update-alternatives --config java"
echo "Select number which corespond with Java 8 - logstash will work"
echo "- this is necesary until bug with Elastic/Java10 is fixed"

echo "Username: " $nginxUsername
echo "Password: " $passvar1
echo "**********************************************************************************************************"
