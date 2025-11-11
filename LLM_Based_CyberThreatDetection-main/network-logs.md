# Network Traffic Monitoring - PayPal Clone

This document explains how to use the `network-logs.sh` script to capture and analyze network traffic in your microservices ecosystem. The script leverages `tcpdump` and other tools to provide visibility into API gateway and service-to-service communications.

---

## Script Location
- Path: `/home/uday/Desktop/PayPal/network-logs.sh`

## Prerequisites
- **Root/Sudo Access:** Network monitoring requires elevated privileges.
- **tcpdump:** The script will auto-install `tcpdump` if not present.

---

## Usage

### Show Help
```bash
./network-logs.sh --help
```
Displays usage instructions and available options.

### Monitor API Gateway Traffic
```bash
sudo ./network-logs.sh --api
```
- Captures all HTTP traffic on port 8080 (Nginx gateway).
- Shows raw request/response data.
- Press `Ctrl+C` to stop monitoring.

### Monitor Service-to-Service Communication
```bash
sudo ./network-logs.sh --service <service-name>
```
- `<service-name>` can be `auth-service`, `payment-service`, or `notification-service`.
- Captures traffic on the corresponding service port (3001, 3002, 3003).
- Example:
  ```bash
  sudo ./network-logs.sh --service payment-service
  ```

### Show TCP Connections
```bash
sudo ./network-logs.sh --tcp
```
- Displays active TCP connections and Docker network stats.
- Useful for debugging connectivity issues.

---

## Saving Network Logs to a File

To save captured network traffic for later analysis:

```bash
sudo ./network-logs.sh --api > network-traffic.log
```
- This will write all output to `network-traffic.log`.
- You can do the same for service traffic:
  ```bash
  sudo ./network-logs.sh --service auth-service > auth-service-traffic.log
  ```

---

## Example Workflow
1. Start network monitoring in one terminal:
    ```bash
    sudo ./network-logs.sh --api > network-attack.log
    ```
2. In another terminal, run your attack simulation or generate logs:
    ```bash
    ./attack-simulation.sh
    ```
3. Stop monitoring with `Ctrl+C` when done.
4. Analyze `network-attack.log` for suspicious traffic patterns.

---

## Troubleshooting
- If you see a message about missing `tcpdump`, the script will attempt to install it automatically.
- Always run the script with `sudo` for full network capture capabilities.
- If you get permission errors, check your user privileges.

---

## Script Reference
- **API Gateway Port:** 8080
- **Service Ports:**
  - auth-service: 3001
  - payment-service: 3002
  - notification-service: 3003
- **Docker Network:** `paypal-network`

---

For further details, see the comments in `network-logs.sh` or run with `--help`.
