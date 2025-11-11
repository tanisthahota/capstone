#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

show_help() {
    echo -e "${BLUE}📊 PayPal Clone - Kubernetes Log Monitor${NC}"
    echo "======================================"
    echo "Usage: ./k8s-logs.sh [option]"
    echo ""
    echo "Options:"
    echo "  -a, --all       Show logs from all pods"
    echo "  -p, --pods      Show pod status"
    echo "  -e, --events    Show Kubernetes events"
    echo "  -d, --describe  Describe all resources"
    echo "  -s, --service   Show logs for a specific service"
    echo "                  (auth|payment|notification|api-gateway)"
    echo "  -u, --audit     Show Kubernetes audit logs"
    echo "  --audit-policy  Configure the audit policy for Minikube"
    echo "  -h, --help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  ./k8s-logs.sh --all"
    echo "  ./k8s-logs.sh --service auth"
    echo ""
}

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}❌ kubectl is not installed or not in PATH${NC}"
    exit 1
fi

# Check if namespace exists
if ! kubectl get namespace paypal-clone &> /dev/null; then
    echo -e "${RED}❌ Namespace 'paypal-clone' not found${NC}"
    exit 1
fi

# Function to get logs from all pods in a deployment
get_deployment_logs() {
    local deployment=$1
    echo -e "${YELLOW}📋 Logs for $deployment:${NC}"
    kubectl -n paypal-clone logs -l app=$deployment --tail=50 -f
}

# Function to show pod status
show_pod_status() {
    echo -e "${GREEN}📊 Pod Status:${NC}"
    kubectl -n paypal-clone get pods
    echo ""
    echo -e "${GREEN}📊 Deployments Status:${NC}"
    kubectl -n paypal-clone get deployments
    echo ""
    echo -e "${GREEN}📊 Services Status:${NC}"
    kubectl -n paypal-clone get services
}

# Function to show Kubernetes events
show_events() {
    echo -e "${CYAN}🔍 Kubernetes Events:${NC}"
    kubectl -n paypal-clone get events --sort-by=.metadata.creationTimestamp
}

# Function to describe all resources
describe_resources() {
    echo -e "${MAGENTA}📝 Describing All Resources:${NC}"
    echo -e "\n${YELLOW}Deployments:${NC}"
    kubectl -n paypal-clone describe deployments
    echo -e "\n${YELLOW}Services:${NC}"
    kubectl -n paypal-clone describe services
    echo -e "\n${YELLOW}Pods:${NC}"
    kubectl -n paypal-clone describe pods
}

# Function to show audit logs
show_audit_logs() {
    echo -e "${CYAN}🔍 Kubernetes Audit Logs:${NC}"

    # Check if using minikube
    if command -v minikube &> /dev/null && minikube status &> /dev/null; then
        echo -e "${YELLOW}Using Minikube audit logs...${NC}"

        # Check if audit log exists
        if ! minikube ssh "sudo test -f /var/log/kubernetes/audit/audit.log"; then
            echo -e "${RED}Audit log file not found. Run the script with '--audit-policy' to set it up.${NC}"
            exit 1
        fi

        # Display the logs with proper formatting
        echo -e "${GREEN}Recent audit log entries:${NC}"
        minikube ssh "sudo cat /var/log/kubernetes/audit/audit.log" | jq -r '. | "\nTimestamp: \(.timestamp)\nUser: \(.user.username)\nOperation: \(.verb) \(.objectRef.resource)\nStatus: \(.responseStatus.code)\n"' 2>/dev/null || minikube ssh "sudo cat /var/log/kubernetes/audit/audit.log"
    # Check if using kind
    elif command -v kind &> /dev/null && kind get clusters | grep -q "kind"; then
        echo -e "${YELLOW}Using Kind audit logs...${NC}"
        docker exec -it kind-control-plane cat /var/log/kubernetes/audit.log
    # Check if using Docker Desktop
    elif docker info 2>/dev/null | grep -q "Docker Desktop"; then
        echo -e "${YELLOW}Using Docker Desktop audit logs...${NC}"
        echo "Note: Make sure audit logging is enabled in Docker Desktop Kubernetes"
        echo "You can find audit logs in your Docker Desktop VM at /var/log/kubernetes/audit.log"
    else
        echo -e "${RED}Could not determine Kubernetes setup. Please check your audit log location manually.${NC}"
    fi
}

# Function to wait until minikube ssh is ready
wait_for_ssh() {
    echo -e "${CYAN}Waiting for SSH connection to be ready...${NC}"
    for i in {1..15}; do
        # Use a simple 'echo' command to test the connection
        if minikube ssh 'echo "SSH is ready"' &> /dev/null; then
            echo -e "${GREEN}✅ SSH connection is active.${NC}"
            return 0
        fi
        echo -n "."
        sleep 2
    done
    echo -e "\n${RED}❌ Timed out waiting for Minikube SSH. Please run 'minikube stop && minikube start' and try again.${NC}"
    exit 1
}


# Function to generate audit policy
setup_audit_policy() {
    echo -e "${GREEN}Setting up Kubernetes audit policy...${NC}"

    # Check if audit policy file exists
    if [ ! -f "k8s/audit-policy.yaml" ]; then
        echo -e "${RED}Audit policy file not found at k8s/audit-policy.yaml${NC}"
        exit 1
    fi

    # Apply the audit policy based on the Kubernetes setup
    if command -v minikube &> /dev/null && minikube status &> /dev/null; then
        echo "Configuring Minikube audit policy..."

        # Check minikube status and ensure it's running
        echo "🔍 Checking minikube status..."
        if ! minikube status | grep -q "host: Running"; then
            echo -e "${YELLOW}⚠️  Minikube is not running. Starting it...${NC}"
            if ! minikube start; then
                echo -e "${RED}❌ Failed to start minikube${NC}"
                exit 1
            fi
        fi

        # Wait for SSH to be responsive
        wait_for_ssh

        echo "🔧 Setting up audit directories..."
        minikube ssh 'sudo mkdir -p /etc/kubernetes/audit /var/log/kubernetes/audit'
        if [ $? -ne 0 ]; then
            echo -e "${RED}❌ Failed to create audit directories via SSH.${NC}"
            exit 1
        fi

        # (inside the setup_audit_policy function)

        echo "📝 Copying audit policy file using 'minikube cp'..."
        if ! minikube cp k8s/audit-policy.yaml /tmp/policy.yaml; then
            echo -e "${RED}❌ Failed to copy audit policy file to Minikube.${NC}"
            exit 1
        fi
        if ! minikube ssh 'sudo mv /tmp/policy.yaml /etc/kubernetes/audit/policy.yaml'; then
            echo -e "${RED}❌ Failed to move audit policy to the correct location.${NC}"
            exit 1
        fi

        echo "🔐 Setting permissions..."
        minikube ssh 'sudo touch /var/log/kubernetes/audit/audit.log'
        minikube ssh 'sudo chmod 644 /var/log/kubernetes/audit/audit.log'

        echo -e "${YELLOW}⚠️  Minikube will restart to apply the audit configuration. This may take a few minutes...${NC}"
        echo -e "${YELLOW}Press Ctrl+C within 5 seconds to cancel...${NC}"
        sleep 5

        echo "🛑 Stopping Minikube..."
        minikube stop

        echo "🚀 Starting Minikube with audit logging enabled..."
        if ! minikube start \
            --extra-config=apiserver.audit-policy-file=/etc/kubernetes/audit/policy.yaml \
            --extra-config=apiserver.audit-log-path=/var/log/kubernetes/audit/audit.log \
            --extra-config=apiserver.audit-log-maxage=30 \
            --extra-config=apiserver.audit-log-maxbackup=10 \
            --extra-config=apiserver.audit-log-maxsize=100; then
            echo -e "${RED}❌ Failed to start minikube with audit configuration${NC}"
            exit 1
        fi

        # Verify audit logging is working
        echo "✅ Verifying audit logging setup..."
        wait_for_ssh # Wait for SSH again after restart
        
        # Generate some audit events
        kubectl get pods -n kube-system &>/dev/null
        sleep 2 # Give a moment for the log to be written

        if minikube ssh "sudo test -s /var/log/kubernetes/audit/audit.log"; then
            echo -e "${GREEN}✅ Audit logging is successfully configured and the log file is not empty.${NC}"
        else
            echo -e "${RED}❌ Audit log file was not created or is empty. Please check minikube logs for errors.${NC}"
            exit 1
        fi

    elif command -v kind &> /dev/null; then
        echo "Configuring Kind audit policy..."
        echo "Note: Kind requires cluster recreation with audit policy. Please recreate your cluster with the appropriate audit configuration."
    elif docker info 2>/dev/null | grep -q "Docker Desktop"; then
        echo "Configuring Docker Desktop audit policy..."
        echo "Note: Docker Desktop Kubernetes audit logging needs to be configured in the Docker Desktop settings."
    fi
}

# Parse command line arguments
case "${1:-}" in
    -a|--all)
        show_pod_status
        echo "Press Ctrl+C to stop watching logs"
        kubectl -n paypal-clone logs -f --all-containers=true --tail=50
        ;;
    -p|--pods)
        show_pod_status
        ;;
    -e|--events)
        show_events
        ;;
    -d|--describe)
        describe_resources
        ;;
    -s|--service)
        case "${2:-}" in
            auth)
                get_deployment_logs "auth-service"
                ;;
            payment)
                get_deployment_logs "payment-service"
                ;;
            notification)
                get_deployment_logs "notification-service"
                ;;
            api-gateway)
                get_deployment_logs "api-gateway"
                ;;
            *)
                echo -e "${RED}❌ Invalid service. Use: auth, payment, notification, or api-gateway${NC}"
                show_help
                exit 1
                ;;
        esac
        ;;
    -u|--audit)
        show_audit_logs
        ;;
    --audit-policy)
        setup_audit_policy
        ;;
    -h|--help|*)
        show_help
        exit 0
        ;;
esac