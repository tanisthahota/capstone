// Chart instance will be managed by Chart.js
// Using a scoped variable instead of window.threatChart
let threatChartInstance = null;

// Format date to readable format
function formatDate(timestamp) {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp);
    return date.toLocaleString();
}

// Update threat list
function updateThreats(threats) {
    const tbody = document.getElementById('threats-list');
    if (!tbody) {
        console.error('threats-list element not found');
        return;
    }
    
    tbody.innerHTML = '';
    
    if (!threats || threats.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="px-6 py-4 text-center text-gray-500">No threats found</td></tr>';
        return;
    }
    
    threats.forEach(threat => {
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-gray-50';
        tr.innerHTML = `
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${threat.timestamp || 'N/A'}</td>
            <td class="px-6 py-4 whitespace-nowrap">
                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                    ${threat.threat_name === 'SQLi' ? 'bg-red-100 text-red-800' : 
                      threat.threat_name === 'XSS' ? 'bg-yellow-100 text-yellow-800' : 
                      'bg-blue-100 text-blue-800'}">
                    ${threat.threat_name || 'Unknown'}
                </span>
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${threat.source_ip || 'N/A'}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${threat.target_container || threat.target || 'N/A'}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                ${threat.confidence ? (threat.confidence * 100).toFixed(2) + '%' : 'N/A'}
            </td>
        `;
        tbody.appendChild(tr);
    });
}

// Update blocked IPs list
function updateBlockedIPs(ips) {
    const container = document.getElementById('blocked-ips');
    if (!container) {
        console.error('blocked-ips element not found');
        return;
    }
    
    container.innerHTML = '';
    
    if (!ips || ips.length === 0) {
        container.innerHTML = '<p class="text-gray-500 text-center py-4">No blocked IPs</p>';
        return;
    }
    
    ips.forEach(ip => {
        const div = document.createElement('div');
        div.className = 'py-1 px-2 hover:bg-gray-50 rounded';
        div.textContent = ip;
        container.appendChild(div);
    });
}

// Update chart data
function updateChart(threatsByType) {
    const labels = Object.keys(threatsByType);
    const data = Object.values(threatsByType);
    
    threatChart.data.labels = labels;
    threatChart.data.datasets[0].data = data;
    threatChart.update();
}

// Unblock IP (placeholder function)
window.unblockIP = function(ip) {
    if (confirm(`Are you sure you want to unblock ${ip}?`)) {
        fetch(`/api/unblock-ip?ip=${encodeURIComponent(ip)}`, {
            method: 'POST',
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                fetchThreats(); // Refresh the data
            }
        });
    }
};

// Fetch latest threats from the server
async function fetchThreats() {
    try {
        console.log('Fetching threats from /api/threats...');
        const response = await fetch('/api/threats');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        
        console.log('Received data from API:', data); // Debug log
        
        // Update recent threats list
        if (data.recent) {
            updateThreats(data.recent);
        }

        // Update threat stats
        if (data.stats) {
            const totalEl = document.getElementById('total-threats');
            if (totalEl) totalEl.textContent = data.stats.total || 0;
            
            // Update blocked IPs
            // Update blocked IPs using the dedicated function
            if (data.stats.blocked_ips) {
                updateBlockedIPs(data.stats.blocked_ips);
                // Update the count in the header
                const blockedIpsCountEl = document.getElementById('blocked-ips-count');
                if (blockedIpsCountEl) {
                    blockedIpsCountEl.textContent = data.stats.blocked_ips.length;
                }
            }

            // Update threat distribution chart if we have data
            if (data.stats.by_type) {
                updateThreatChart(data.stats.by_type);
            }
        }

    } catch (error) {
        console.error('Error fetching threats:', error);
        // Show error in the UI
        const threatsList = document.getElementById('threats-list');
        if (threatsList) {
            threatsList.innerHTML = `
                <div class="bg-red-50 border-l-4 border-red-400 p-4">
                    <div class="flex">
                        <div class="flex-shrink-0">
                            <svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                            </svg>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm text-red-700">
                                Error loading threats. Please refresh the page or try again later.
                            </p>
                        </div>
                    </div>
                </div>`;
        }
    }
}

// Update the threat chart
function updateThreatChart(threatData) {
    const chartCanvas = document.getElementById('threatChart');
    
    if (!chartCanvas) {
        console.error('Chart canvas element not found');
        return;
    }

    // Destroy existing chart if it exists
    if (threatChartInstance) {
        threatChartInstance.destroy();
        threatChartInstance = null;
    }

    const ctx = chartCanvas.getContext('2d');
    const labels = Object.keys(threatData);
    const data = Object.values(threatData);
    
    if (labels.length === 0) {
        // Show a message when no data is available
        chartCanvas.style.display = 'none';
        const container = chartCanvas.parentElement;
        if (!container.querySelector('.no-data-message')) {
            const message = document.createElement('p');
            message.className = 'no-data-message text-gray-500 text-center py-8';
            message.textContent = 'No threat data available';
            container.appendChild(message);
        }
        return;
    } else {
        // Remove any existing no-data message
        const message = chartCanvas.parentElement.querySelector('.no-data-message');
        if (message) {
            message.remove();
        }
        chartCanvas.style.display = 'block';
    }

    const colors = [
        'rgba(239, 68, 68, 0.8)',    // red-500
        'rgba(59, 130, 246, 0.8)',   // blue-500
        'rgba(245, 158, 11, 0.8)',   // yellow-500
        'rgba(16, 185, 129, 0.8)',   // emerald-500
        'rgba(139, 92, 246, 0.8)',   // violet-500
        'rgba(20, 184, 166, 0.8)',   // teal-500
        'rgba(249, 115, 22, 0.8)',   // orange-500
    ];

    threatChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderWidth: 0,
                hoverOffset: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        padding: 15,
                        usePointStyle: true,
                        pointStyle: 'circle',
                        font: {
                            family: 'Inter, system-ui, -apple-system, sans-serif'
                        }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    titleFont: {
                        weight: '500',
                        size: 14
                    },
                    bodyFont: {
                        size: 13
                    },
                    padding: 12,
                    cornerRadius: 6,
                    displayColors: false
                }
            },
            animation: {
                animateScale: true,
                animateRotate: true
            },
            layout: {
                padding: 10
            }
        }
    });
}

// Poll for updates
function pollThreats() {
    fetchThreats().finally(() => {
        // Poll every 2 seconds after the current request completes
        setTimeout(pollThreats, 2000);
    });
}

// Start polling when the page loads
document.addEventListener('DOMContentLoaded', () => {
    // Check if we're on the dashboard page
    if (document.getElementById('threatChart')) {
        console.log('Initializing dashboard...');
        // Initial load
        fetchThreats();
        // Start polling (no need for separate interval as pollThreats handles it)
        pollThreats();
    }
});
