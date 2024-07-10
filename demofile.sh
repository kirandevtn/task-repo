#!/bin/bash

apk add --update --no-cache openssh sshpass                                                                                                                # Replace with your subnet ID
apk update && apk add bind-tools

TEAM="qa"
ENVIRONMENT="test"
PROVISIONED_BY="script"
AUTOSHUTDOWN="true"

export AWS_ACCESS_KEY_ID=$ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY=$SECRET_KEY_ID
aws configure set aws_access_key_id "$AWS_ACCESS_KEY_ID"
aws configure set aws_secret_access_key "$AWS_SECRET_ACCESS_KEY"
aws configure set region "$REGION"

CONFIG=m5a.large #cpu 2, memory 8    "default config"
if [[ "$VM_CPU" == "4" ]]; then
    CONFIG="m6a.xlarge"             #cpu 4, memory 16
elif [[ "$size" == "8" ]]; then
    CONFIG="m6a.2xlarge"            #cpu 8, memory 16
fi

echo "========== TYPE OF INSTANCE  ============="
echo "                        "
echo "Instance to be launched: $CONFIG..."

# Function to list all EC2 instances
list_ec2_instances() {
    aws ec2 describe-instances --region ${REGION} --query 'Reservations[*].Instances[*].[InstanceId,InstanceType,State.Name,Tags[?Key==`Name`].Value|[0]]' --output table
}

# Creating a random pasword for devtron user.
PASSWORD=$(openssl rand -base64 15 | tr -dc 'a-zA-Z0-9' | head -c15 ; echo -n '!@#$%&' )
echo "Password of the instance is: $PASSWORD"

# Function to launch a new EC2 instance
launch_ec2_instance() {

    # Variables (Replace with your actual values)
    INSTANCE_TYPE=$CONFIG

    OWNER=$EMAIL_ID
    echo "================LAUNCHING AN EC2 INSTANCE ==============="
    echo "                        "

    echo "Launching EC2 instance with name: $INSTANCE_NAME..."


    # User data script to enable password authentication, install the microk8s and other required setup
    USER_DATA=$(cat <<EOF
#!/bin/bash
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/Include/#Include/' /etc/ssh/sshd_config
adduser --disabled-password --gecos "" devtron
echo "export PASSWORD='$PASSWORD'" >> ~/.bashrc
source ~/.bashrc
echo "devtron:$PASSWORD" | chpasswd
echo "devtron ALL=(ALL) NOPASSWD: ALL" | sudo EDITOR='tee -a' visudo
sudo -u devtron -i <<'EOF'
EOF
)

    # Launch EC2 spot node instance
    INSTANCE_ID=$(aws ec2 run-instances \
        --image-id $AMI_ID \
        --instance-type $INSTANCE_TYPE \
        --key-name $KEY_NAME \
        --region ${REGION} \
        --subnet-id $SUBNET_ID \
        --security-group-ids $SECURITY_GROUP_ID \
        --user-data "$USER_DATA" \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$INSTANCE_NAME},{Key=team,Value=$TEAM},{Key=environment,Value=$ENVIRONMENT},{Key=owner,Value=$OWNER},{Key=autoShutdown,Value=$AUTOSHUTDOWN},{Key=provisioned-by,Value=$PROVISIONED_BY}]" \
        --instance-market-options "MarketType=spot,SpotOptions={SpotInstanceType=persistent,InstanceInterruptionBehavior=stop}" \
        --query 'Instances[0].InstanceId' \
        --output text)

    if [ $? -ne 0 ]; then
        echo "Failed to launch EC2 instance."
        exit 1
    fi

    echo "EC2 instance launched successfully with Instance ID: $INSTANCE_ID"
    echo "                        "
}

echo "========== Listing all VM already Present ============="
echo "                        "
list_ec2_instances
echo "                        "

echo "================YOUR EMAIL ADDRESS ==============="
echo "                        "
echo "$EMAIL_ID"
 
# Check the email valid or not.
if [[ $EMAIL_ID == *@devtron.ai ]]; then
  echo "Valid email address"
else
  echo "Invalid email address"
  exit
fi
echo "                        "

# Generate the instance name from the email id
INSTANCE_NAME=$(echo "$EMAIL_ID" | tr "@" "-")

# Call function to launch an spot instance
launch_ec2_instance

# Allocation an elastic ip
echo "================LAUNCING AN ELASTIC IP==============="
echo "                        "
EIP_INFO=$(aws ec2 allocate-address --region ${REGION} --domain vpc)
if [ $? -ne 0 ]; then
  echo "Failed to create an Elastic IP."
  exit 1
fi
echo "Elastic IP is created successfully..."
ALLOCATION_ID=$(echo $EIP_INFO | jq -r '.AllocationId')
echo "Elastic-ip id:" $ALLOCATION_ID
PUBLIC_IP=$(echo $EIP_INFO | jq -r '.PublicIp')
echo "Public-ip allocated by the elastic-ip:" $PUBLIC_IP

# Time taking to come up the instance in running state.
sleep 30

# Associating an Elastic ip to the spot node vm...
response=$(aws ec2 associate-address --region ${REGION} --instance-id $INSTANCE_ID --allocation-id $ALLOCATION_ID)
if [ $? -ne 0 ]; then
  echo "Failed to associate an Elastic IP to the spot node..."
  exit 1
fi
echo "Elastic IP is associated successfully with the vm..."
echo "                        "

cat << 'EOF' > ./helper.sh
#!/bin/bash
sudo snap install microk8s --classic --channel=1.28
echo "alias kubectl='microk8s kubectl '" >> ~/.bashrc
echo "alias helm='microk8s helm3 '" >> ~/.bashrc
source ~/.bashrc
sudo usermod -a -G microk8s devtron
sudo chown -f -R devtron ~/.kube
  newgrp microk8s << END
    echo "                        "
    echo "============== ENABLE DNS, STORAGE, HELM3 =========================================="
    echo "                        "
    sleep 20
    microk8s enable dns 
    microk8s enable storage
    microk8s enable helm
    echo "                        "
    echo "============== CREATING A NAMESPACE devtron-ci, devtron-cd, devtron-demo =========================================="
    echo "                        "
    microk8s kubectl create namespace devtron-ci
    microk8s kubectl create namespace devtron-cd
    microk8s kubectl create namespace devtron-demo
curl -O https://raw.githubusercontent.com/devtron-labs/utilities/main/kubeconfig-exporter/kubernetes_export_sa.sh && sed -i 's/kubectl/microk8s kubectl/g' kubernetes_export_sa.sh && bash kubernetes_export_sa.sh cd-user devtroncd > /home/devtron/bearerToken.txt
exit 0
EOF

echo "============== SETUP AN MICROK8S WITH USER DEVTRON =========================================="
echo "                        "

sshpass -p "$PASSWORD" scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no helper.sh devtron@$PUBLIC_IP:/home/devtron/
sshpass -p "$PASSWORD" ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no devtron@$PUBLIC_IP 'bash /home/devtron/helper.sh'

echo "Installation Completed successfully ..."
echo "                        "

# Print devtron user credential 
echo "========= SSH TO THE VM =========="
echo "ssh devtron@$PUBLIC_IP" 
echo "Password: $PASSWORD"
echo "                        "


# Send an alert on the discord channel
echo "=========SENDING MESSAGE ON DISCORD CHANNEL=========="
echo "                        "
JSON='{
  "content": "``` A virtual machine has been provisioned by the QA team under the username '"$EMAIL_ID"' and its associated with the following security group id: '"$SECURITY_GROUP_ID"' and ElasticIP-ID: '"$ALLOCATION_ID"' ``` "
}'
curl -H "Content-Type: application/json" -X POST -d "$JSON" $DISCORD_URL

if [ $? -ne 0 ]; then
  echo "Failed to send message on discord."
  exit 1
fi
echo "Message sent on discord channel successfully..."
echo "                        "


echo "=========GETTING THE BEARER TOKEN=========="
echo "                        "
sshpass -p $PASSWORD scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no devtron@$PUBLIC_IP:/home/devtron/bearerToken.txt .
bearerToken=$(cat ./bearerToken.txt | grep "TOKEN" | awk -F ' := ' '{print $2}')
echo "Bearer Token: $bearerToken"

dashboardUrl=$dashboardUrl
devtronApiToken=$devtronApiToken
clusterData=$(curl -s "${dashboardUrl}/orchestrator/cluster" -H "token: $devtronApiToken")
clusterDataStatusCode=$(echo "$clusterData" | jq ".code")
if [ ! "$clusterData" ] || [ "$clusterDataStatusCode" -ne 200 ]; then
  echo "Please check the dashboardUrl or devtronApiToken provided!"
  exit 1
fi

clusterList=$(echo "$clusterData" | jq ".result")

echo "$clusterList" | jq -c '.[]' | while read -r cluster; do
  regex="^qa-devtroncd-[0-9]+$"
  clusterName=$(echo "$cluster" | jq -r ".cluster_name")
  serverUrl=$(echo "$cluster" | jq -r ".server_url")

  if [[ $clusterName =~ $regex ]]; then
    hostname=$(echo "$serverUrl" | awk -F[/:] '{print $4}')
    echo "Hostname is $hostname"
    ipAddress=$(dig -4 +short "$hostname" | grep -oE "([0-9]{1,3}\\.){3}[0-9]{1,3}")
    echo "IPAddress is $ipAddress"

    instances=$(aws ec2 describe-instances)
    instanceState=$(echo "$instances" | jq -r --arg ipAddress "$ipAddress" '.Reservations[].Instances[] | select(.PublicIpAddress == $ipAddress) | .State.Name')
    echo "$instanceState"

    curl_response=$(curl -k -s --max-time 5 "$serverUrl")
    statusCode=$(echo "$curl_response" | jq ".code")
    if [ "$statusCode" ]; then
      echo "Cluster is running"
      echo "Cluster info:"
      echo "Skipping $clusterName, status: Active"
    elif [ "$instanceState" == "terminated" ] || [ ! "$instanceState" ]; then
      echo ""
      echo "$cluster" | jq "."
      id=$(echo "$cluster" | jq ".id")

      echo "Mapping the ip with the domain name......."
      export disallowed_domains=("staging.devtron.info" "test.devtron.info" "preview.devtron.info" "automation.devtron.info")
      export HOSTED_ZONE_ID=$HOSTED_ZONE_ID_AWS
      export AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID_R53
      export AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY_R53

      # Authenticate to AWS using secrets
      aws configure set aws_access_key_id $AWS_ACCESS_KEY_ID
      aws configure set aws_secret_access_key $AWS_SECRET_ACCESS_KEY
      aws configure set region ap-south-1

      DOMAIN_NAME=$hostname
      IP_ADDRESS=$PUBLIC_IP
      echo "Patchin $DOMAIN_NAME and $IP_ADDRESS"

      # if [[ " ${disallowed_domains[*]} " =~ " ${DOMAIN_NAME} " ]]; then
      #     echo "Sorry, the domain '$DOMAIN_NAME' is not allowed for mapping. Please choose a different one."
      #     exit
      # fi

      if [[ $(echo "$DOMAIN_NAME" | cut -d'.' -f 2-3) == "devtron.info" ]]; then
        echo "Domain name '$DOMAIN_NAME' is allowed for mapping."
      else
        echo "Error: Only domains under '*.devtron.info' are allowed for mapping. Please provide a valid domain."
        exit
      fi

      cat >data.json <<EOF
{
    "Comment": "Modifying the existing record $DOMAIN_NAME .",
    "Changes": [{
        "Action": "UPSERT",
        "ResourceRecordSet": {
            "Name": "${DOMAIN_NAME}",
            "Type": "A",
            "TTL": 300,
            "ResourceRecords": [{
                "Value": "${IP_ADDRESS}"
            }]
        }
    }]
}
EOF


      ID=$(aws route53 change-resource-record-sets --hosted-zone-id $HOSTED_ZONE_ID --change-batch file://data.json | jq -r '.ChangeInfo.Id')

      while true; do

        status=$(aws route53 get-change --id "$ID" --query 'ChangeInfo.Status' --output text)

        if [[ "$status" == "PENDING" ]]; then
          echo "Waiting for DNS mapping to complete. Current status: $status"
          sleep 10
        else

          if [[ "$status" == "INSYNC" ]]; then
            echo "DNS mapping is successfully completed. The changes are now live."
            echo "Adding the cluster to staging"
            sleep 60

            json_data=$(jq -n --argjson id "$id" \
              --arg clusterName "$clusterName" \
              --arg bearerToken "$bearerToken" \
              --arg serverUrl "$serverUrl" \
              '{id: $id, insecureSkipTlsVerify: true, cluster_name: $clusterName, config: {bearer_token: $bearerToken}, active: true,"remoteConnectionConfig":{"connectionMethod":"DIRECT","proxyConfig":null,"sshConfig":null},"prometheus_url":"","prometheusAuth":{"userName":"","password":"","tlsClientKey":"","tlsClientCert":"","isAnonymous":true},server_url: $serverUrl}')

            res=$(curl "${dashboardUrl}/orchestrator/cluster" \
              -X "PUT" \
              -H "Content-Type: application/json" \
              -H "token: $devtronApiToken" \
              --data-raw "$json_data")


            echo "resvalue: $res"
          else
            echo "Unexpected status: $status. Please check the AWS Route 53 console for more details/Connect with Devops team ."
          fi
          break
        fi
      done
      echo "$json_data" | jq "."
      break
    else
      echo "VM is not terminated yet skipping $clusterName"
    fi
  fi

done
