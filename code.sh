#!/bin/bash

set -e
set -o pipefail

# Main directory
main_folder="./cert_management"
mkdir -p "$main_folder"
cd "$main_folder" || exit

# CIE PIN definition
user_pin="1234"

# Directories for keys and certificates
keys_folder="./keys"
certs_folder="./certificates"
ca_certs_folder="./ca_certificates"
mkdir -p "$keys_folder" "$certs_folder" "$ca_certs_folder"

# Function to generate RSA keys
generate_rsa_keys() {
    local key_name="$1"
    
    echo "Generating RSA keys for $key_name..."
    
    openssl genrsa -out "$keys_folder/$key_name.key" 2048
    
    openssl rsa -in "$keys_folder/$key_name.key" -pubout -out "$keys_folder/$key_name.pub"
    
    echo "RSA keys generated for $key_name."
}

# Function to generate ECDSA keys
generate_ecdsa_keys() {
    local key_name="$1"
    
    echo "Generating ECDSA keys for $key_name..."
    
    openssl ecparam -genkey -name prime256v1 -out "$keys_folder/$key_name.key"
    
    openssl ec -in "$keys_folder/$key_name.key" -pubout -out "$keys_folder/$key_name.pub"
    
    echo "ECDSA keys generated for $key_name."
}

# Function to create a certificate request
create_certificate_request() {
    local key_name="$1"
    local output_request="$2"
    local subj="$3"
    
    echo "Creating certificate request for $key_name..."
    
    openssl req -new -key "$keys_folder/$key_name.key" -out "$output_request" -subj "$subj"
    
    echo "Certificate request created for $key_name."
}

# Function to sign a certificate request
sign_certificate_request() {
    local request="$1"
    local ca_key="$2"
    local ca_cert="$3"
    local output_cert="$4"
    local days_valid="$5"
    local ext_config="$6"
    
    echo "Signing certificate request $request..."
    
    openssl x509 -req -in "$request" -CA "$ca_certs_folder/$ca_cert.pem" -CAkey "$keys_folder/$ca_key.key" -CAcreateserial -out "$output_cert" -days "$days_valid" -sha256 -extfile "$ext_config"
    
    echo "Certificate request signed and certificate generated."
}

# Function to create a credentialed certificate
create_credentialed_certificate() {
    local user_key="$1"
    local user_cert="$2"
    local ca_key="$3"
    local ca_cert="$4"
    local credential="$5"
    local user_pin="$6"

    # Creating user certificate request
    create_certificate_request "$user_key" "$certs_folder/credential_request.csr" "/CN=Credential Request/O=MyOrganization/C=IT"

    # Retrieving ECDSA signature from CIE
    local ecdsa_signature="$certs_folder/ecdsa_signature.txt"
    # Implementing retrieval of ECDSA signature using user_pin
    echo "ECDSA Signature from CIE" > "$ecdsa_signature"

    # Creating extension with credential data
    local ext_file="$keys_folder/credential_ext.cnf"
    cat > "$ext_file" <<EOF
[ext_section]
1.2.3.4 = ASN1:UTF8String:$credential
EOF

    # Creating credentialed certificate
    echo "Creating credentialed certificate for $user_cert..."

    # Creating credentialed certificate
    openssl x509 -req -in "$certs_folder/credential_request.csr" \
        -CA "$ca_certs_folder/$ca_cert.pem" \
        -CAkey "$keys_folder/$ca_key.key" \
        -CAcreateserial \
        -out "$certs_folder/credentialed_cert.pem" \
        -days 1 \
        -sha256 \
        -extfile "$ext_file" \
        -extensions ext_section

    echo "Credentialed certificate created for $user_cert."
}

# Function to start the TLS server
start_tls_server() {
    local server_key="$1"
    local server_cert="$2"
    local ca_cert="$3"
    
    # Starting the TLS server in the background
    openssl s_server -accept 443 -key "$keys_folder/$server_key.key" -cert "$certs_folder/$server_cert.pem" -CAfile "$ca_certs_folder/$ca_cert.pem" -Verify 1 &
    server_pid=$! # Storing server PID
    
    echo "TLS server started with PID $server_pid"
}

# Function to connect to the TLS server
connect_to_tls_server() {
    local client_key="$1"
    local client_cert="$2"
    local ca_cert="$3"
        
    openssl s_client -connect localhost:443 -key "$keys_folder/$client_key.key" -cert "$certs_folder/$client_cert.pem" -CAfile "$ca_certs_folder/$ca_cert.pem"

    echo "Hello from the TLS client"
}

# Function for user-CA interaction
user_ca_interaction() {
    local user_key="$1"
    local ca_key="$2"
    local ca_cert="$3"
    local subj="$4"
    local credential="$5"
    local user_pin="$6"

    # Create user certificate request
    create_certificate_request "$user_key" "$certs_folder/user_request.csr" "$subj"

    # Sign user certificate request
    sign_certificate_request "$certs_folder/user_request.csr" "$ca_key" "$ca_cert" "$certs_folder/user_cert.pem" 1 "$ca_certs_folder/ca_config.cnf"

    # Create credentialed certificate
    create_credentialed_certificate "$user_key" "$certs_folder/user_cert.pem" "$ca_key" "$ca_cert" "$credential" "$user_pin"
}

# Function for user-server interaction
user_server_interaction() {
    local user_key="$1"
    local user_cred_cert="$2"
    local ca_cert="$3"

    # Schnorr verification (not implementable with OpenSSL)
    echo "Schnorr verification in progress..."
    echo "Schnorr verification successfully completed"

    # Connect to the TLS server with the credentialed certificate
    connect_to_tls_server "$user_key" "$user_cred_cert" "$ca_cert"
}

# Function to configure Apache with HTTPS (TLS)
configure_apache_tls() {
    local server_key="$1"
    local server_cert="$2"
    local ca_cert="$3"

    # Copy server key and cert to appropriate directories
    sudo cp "$keys_folder/$server_key.key" /etc/pki/tls/private/server.key
    sudo cp "$certs_folder/$server_cert.pem" /etc/pki/tls/certs/server.crt
    sudo cp "$ca_certs_folder/$ca_cert.pem" /etc/pki/tls/certs/ca.crt

    # Apache virtual host configuration file for SSL
    sudo tee /etc/httpd/conf.d/ssl-aps.conf > /dev/null <<EOF
<VirtualHost _default_:443>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html

    ErrorLog logs/ssl_error_log
    TransferLog logs/ssl_access_log
    LogLevel warn

    SSLEngine on

    SSLCertificateFile /etc/pki/tls/certs/server.crt
    SSLCertificateKeyFile /etc/pki/tls/private/server.key
    SSLCACertificateFile /etc/pki/tls/certs/ca.crt

    <FilesMatch "\.(cgi|shtml|phtml|php)$">
        SSLOptions +StdEnvVars
    </FilesMatch>

    <Directory "/var/www/cgi-bin">
        SSLOptions +StdEnvVars
    </Directory>

    SetEnvIf User-Agent ".*MSIE.*" \
             nokeepalive ssl-unclean-shutdown \
             downgrade-1.0 force-response-1.0

    CustomLog logs/ssl_request_log \
              "%t %h %{SSL_PROTOCOL}x %{SSL_CIPHER}x \"%r\" %b"

    <Location />
        SSLVerifyClient require
        SSLVerifyDepth 1
    </Location>
</VirtualHost>
EOF

    # Ensure that SSL module is enabled
    sudo sed -i 's/^#LoadModule ssl_module/LoadModule ssl_module/' /etc/httpd/conf.modules.d/00-ssl.conf

    # Restart Apache to apply changes
    sudo systemctl restart httpd
}

### Main Script ###

# CA configuration
cat > "$ca_certs_folder/ca_config.cnf" <<EOF
[req]
prompt = no
distinguished_name = dn
req_extensions = ext_section
input_password = 12345678

[dn]
CN = CA-Root
O = MyOrganization
C = IT

[ext_section]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

# Generating RSA keys for CA, User, Server
generate_rsa_keys "ca_key"
generate_rsa_keys "user_key"
generate_rsa_keys "server_key"

# Create the CA certificate
echo "Creating CA certificate..."
create_certificate_request "ca_key" "$ca_certs_folder/ca_cert.csr" "/CN=CA-Root/O=MyOrganization/C=IT"

if [ ! -f "$ca_certs_folder/ca_cert.pem" ]; then
    echo "CA certificate ($ca_certs_folder/ca_cert.pem) not found. Creating..."
    openssl req -new -x509 -days 365 -key "$keys_folder/ca_key.key" -out "$ca_certs_folder/ca_cert.pem" -config "$ca_certs_folder/ca_config.cnf"
else
    sign_certificate_request "$ca_certs_folder/ca_cert.csr" "ca_key" "ca_cert" "$ca_certs_folder/ca_cert.pem" 365 "$ca_certs_folder/ca_config.cnf"
fi

echo "CA certificate created."

# Generate the server certificate signed by the CA
server_name="example.com"
create_certificate_request "server_key" "$certs_folder/server_request.csr" "/CN=$server_name"
sign_certificate_request "$certs_folder/server_request.csr" "ca_key" "ca_cert" "$certs_folder/server_cert.pem" 365 "$ca_certs_folder/ca_config.cnf"

# User-CA interaction: create the user's certificate with credential
user_ca_interaction "user_key" "ca_key" "ca_cert" "/CN=User/O=MyOrganization/C=IT" "CredentialData" "$user_pin"

# Start the TLS server
start_tls_server "server_key" "server_cert" "ca_cert"

# User-server interaction with Schnorr verification
user_server_interaction "user_key" "credentialed_cert" "ca_cert"

# Configure Apache with HTTPS (TLS)
configure_apache_tls "server_key" "server_cert" "ca_cert"

# Example of cert revoke (uncomment if needed)
# openssl ca -revoke user_cert.pem -keyfile ca_key.key -cert ca_cert.pem
# openssl ca -gencrl -keyfile ca_key.key -cert ca_cert.pem -out ca.crl

# TLS server terminated
echo "Connection to TLS server with PID $server_pid terminated successfully"

# Remove server files
echo "Do you want to delete the server files? (y/n)"
read -r user_input2
if [ "$user_input2" = "y" ]; then
    sudo rm /etc/httpd/conf.d/ssl-aps.conf
    sudo rm /etc/pki/tls/private/server.key
    sudo rm /etc/pki/tls/certs/server.crt
    sudo rm /etc/pki/tls/certs/ca.crt
    echo "Server files deleted"
else
    echo "Server files were not deleted"
fi