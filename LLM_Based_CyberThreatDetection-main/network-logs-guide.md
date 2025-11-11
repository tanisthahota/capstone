# Guide to Network Traffic Monitoring (`network-logs.sh`)

## 1. Introduction

This document provides a comprehensive guide to using the `network-logs.sh` script. Its purpose is to capture and analyze network traffic within the PayPal Clone microservices ecosystem, providing critical data for security analysis and threat detection. The script acts as a wrapper around powerful Linux networking tools like `tcpdump` and `netstat`.

## 2. Prerequisites

- **Operating System**: A Linux-based environment.
- **Permissions**: You must have `sudo` or root access to run the network capture commands. The script will exit if run without sufficient privileges.
- **`tcpdump`**: This is the core tool used for packet sniffing. The script includes a function (`check_tcpdump`) that will automatically attempt to install it using `apt-get` if it is not found.

## 3. Script Usage and Commands

The script is located at `/home/uday/Desktop/PayPal/network-logs.sh`.

### 3.1. Displaying Help

To see a list of all available commands and examples, use the `--help` flag.

**Command:**
```bash
./network-logs.sh --help
```

### 3.2. Monitoring the API Gateway

This is the most common use case. It captures all traffic entering the ecosystem through the Nginx reverse proxy.

**Command:**
```bash
sudo ./network-logs.sh --api
```
- **Action**: Listens on port `8080`.
- **Output**: Shows the full content (`-A`) of packets for all incoming and outgoing requests and responses at the gateway. This is useful for seeing exactly what clients are sending and what the gateway is forwarding.

### 3.3. Monitoring Service-to-Service Communication

To isolate and inspect the traffic between internal services, use the `--service` flag.

**Command:**
```bash
sudo ./network-logs.sh --service <service-name>
```
- **`<service-name>`**: Can be one of the following:
    - `auth-service` (monitors port `3001`)
    - `payment-service` (monitors port `3002`)
    - `notification-service` (monitors port `3003`)

- **Example**: To see requests flowing from the `payment-service` to the `auth-service` for token verification:
  ```bash
  sudo ./network-logs.sh --service auth-service
  ```

### 3.4. Viewing Active TCP Connections

To get a snapshot of the current network state without capturing live traffic, use the `--tcp` flag.

**Command:**
```bash
sudo ./network-logs.sh --tcp
```
- **Action**: This command provides three pieces of information:
    1.  **Docker Network Statistics**: Shows the total network I/O for each running container.
    2.  **Active TCP Connections**: Uses `netstat` to show established connections on the service ports (`3001`, `3002`, `3003`) and the gateway port (`8080`).
    3.  **Docker Network Details**: Inspects the `paypal-network` to show which containers are connected and their IP addresses.

## 4. How to Save Network Logs

For analysis, it's essential to save the captured traffic to a file. This can be done using standard shell redirection.

### Example Workflow: Capturing an Attack

1.  **Start the capture** in one terminal, redirecting the output to a log file.
    ```bash
    sudo ./network-logs.sh --api > api_gateway_capture.log
    ```

2.  **Execute an action** in a second terminal (e.g., run a normal test script or an attack simulation script).
    ```bash
    ./generate-logs.sh
    # or ./attack-simulation.sh
    ```

3.  **Stop the capture** in the first terminal by pressing `Ctrl+C`.

4.  **Analyze the file**. The `api_gateway_capture.log` file now contains a complete record of the network traffic during the simulation.

## 5. Conclusion

The `network-logs.sh` script is a versatile tool for gathering network-level data from your application. By capturing traffic at both the edge (API Gateway) and between services, you can build a comprehensive dataset that complements your application-level logs, providing a multi-layered view for your threat detection model.
