#!/bin/bash

# Function to generate Snort rule
generate_snort_rule() {
    local action="$1"
    local protocol="$2"
    local src_ip="$3"
    local src_port="$4"
    local dst_ip="$5"
    local dst_port="$6"
    local msg="$7"
    local sid="$8"
    local rev="$9"
    local class_type="${10}"
    local priority="${11}"
    local gid="${12}"

    rule="$action $protocol $src_ip $src_port -> $dst_ip $dst_port (msg:\"$msg\"; sid:$sid; rev:$rev;"
    
    [[ -n "$class_type" ]] && rule+=" class_type:$class_type;"
    [[ -n "$priority" ]] && rule+=" priority:$priority;"
    [[ -n "$gid" ]] && rule+=" gid:$gid;"
    
    rule+=")"
    echo "$rule"
}

# Main script logic
echo -e "\n======Snortify======"
echo "Snort Rule Generator"
echo "===================="
echo -e "\n"

# Get user input for action
echo -e "Action:\n 1. alert\n 2. log\n 3. pass\n 4. activate\n 5. dynamic\n 6. drop\n 7. reject\n 8. sdrop"
read -p "Choose an action (1-8): " action_choice
case "$action_choice" in
    1) action="alert" ;;
    2) action="log" ;;
    3) action="pass" ;;
    4) action="activate" ;;
    5) action="dynamic" ;;
    6) action="drop" ;;
    7) action="reject" ;;
    8) action="sdrop" ;;
    *) echo "Invalid choice"; exit 1 ;;
esac

# Get user input for protocol
echo -e "Protocol:\n 1. icmp\n 2. tcp\n 3. udp\n 4. ip"
read -p "Choose a protocol (1-4): " protocol_choice
case "$protocol_choice" in
    1) protocol="icmp" ;;
    2) protocol="tcp" ;;
    3) protocol="udp" ;;
    4) protocol="ip" ;;
    *) echo "Invalid choice"; exit 1 ;;
esac

# Get user input for source and destination details
echo -e "Source IP:\n - any\n - x.x.x.x\n - x.x.x.x/x"
read -p "src ip: " src_ip

# Default ports based on protocol
if [[ "$protocol" == "ip" ]]; then
    src_port="any"
    dst_port="any"
else
    echo -e "Source Port:\n - any\n - <port>"
    read -p "src port: " src_port
    echo -e "Destination Port\n - any\n - <port>"
    read -p "dst port: " dst_port
fi

echo -e "Destination IP:\n - any\n - x.x.x.x\n - x.x.x.x/x"
read -p "dst ip: " dst_ip
read -p "Message: " msg
read -p "SID (unique integer): " sid
read -p "Rev number: " rev

# Optional fields
read -p "Class Type (optional, press Enter to skip): " class_type
read -p "Priority (optional, press Enter to skip): " priority
read -p "GID (optional, press Enter to skip): " gid

# Generate the rule
rule=$(generate_snort_rule "$action" "$protocol" "$src_ip" "$src_port" "$dst_ip" "$dst_port" "$msg" "$sid" "$rev" "$class_type" "$priority" "$gid")

# Output the generated rule
echo "Generated Snort Rule:"
echo "$rule"

# Optional: Save the rule to a file
# read -p "Save rule to file? (y/n): " save
# if [[ "$save" == "y" ]]; then
#    read -p "Enter filename: " filename
#    echo "$rule" >> "$filename"
#    echo "Rule saved to $filename"
# fi

