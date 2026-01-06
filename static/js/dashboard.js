// Global chart instances to destroy before re-rendering
let protocolChartInstance = null;
let topTalkersChartInstance = null;

function loadDashboardData(id) {
    fetch(`/api/data/${id}`)
        .then(res => res.json())
        .then(data => {
            if (data.error) {
                alert("Error loading data: " + data.error);
                return;
            }
            
            // Update Text Stats
            document.getElementById('file-info').textContent = data.filename;
            document.getElementById('total-packets').textContent = data.stats.total_packets.toLocaleString();
            document.getElementById('total-sessions').textContent = data.sessions.length.toLocaleString();
            document.getElementById('threat-count').textContent = data.threats.length;
            
            const duration = (data.stats.end_time - data.stats.start_time).toFixed(2);
            document.getElementById('duration').textContent = duration + "s";

            // Render Charts
            renderProtocolChart(data.stats.protocols);
            renderTopTalkers(data.sessions);
            
            // Render Table (limit to 50)
            renderSessionTable(data.sessions.slice(0, 50));
        })
        .catch(err => console.error(err));
}

function renderProtocolChart(protocols) {
    const ctx = document.getElementById('protocolChart').getContext('2d');
    
    if (protocolChartInstance) protocolChartInstance.destroy();

    const labels = Object.keys(protocols);
    const values = Object.values(protocols);
    
    protocolChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: [
                    '#ffffff', '#d4d4d8', '#a1a1aa', '#71717a', '#52525b', '#3f3f46'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right', labels: { color: '#a1a1aa' } }
            }
        }
    });
}

function renderTopTalkers(sessions) {
    // Aggregate by Src IP
    const ipCounts = {};
    sessions.forEach(s => {
        const ip = s.src_ip;
        ipCounts[ip] = (ipCounts[ip] || 0) + s.bytes_sent;
    });
    
    // Sort and top 10
    const sortedIPs = Object.entries(ipCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);
        
    const ctx = document.getElementById('topTalkersChart').getContext('2d');
    
    if (topTalkersChartInstance) topTalkersChartInstance.destroy();

    topTalkersChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sortedIPs.map(i => i[0]),
            datasets: [{
                label: 'Bytes Sent',
                data: sortedIPs.map(i => i[1]),
                backgroundColor: '#d4d4d8',
                borderRadius: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#a1a1aa' } },
                x: { grid: { display: false }, ticks: { color: '#a1a1aa' } }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

function renderSessionTable(sessions) {
    const tbody = document.querySelector('#sessions-table tbody');
    tbody.innerHTML = '';
    
    sessions.forEach(s => {
        const row = document.createElement('tr');
        row.className = "hover:bg-white/5 transition-colors";
        
        const date = new Date(s.start_time * 1000).toISOString().split('T')[1].split('.')[0];
        
        // Protocol Badge Color - Monochrome
        let badgeClass = "bg-zinc-800 text-zinc-300 border border-zinc-700";
        if (s.protocol === 'TCP') badgeClass = "bg-zinc-800 text-white border border-zinc-600";
        if (s.protocol === 'UDP') badgeClass = "bg-zinc-800 text-zinc-400 border border-zinc-700";
        if (s.protocol === 'HTTP') badgeClass = "bg-white/10 text-white border border-white/20";
        if (s.protocol === 'DNS') badgeClass = "bg-zinc-900 text-zinc-500 border border-zinc-800";
        
        row.innerHTML = `
            <td class="px-6 py-3 text-zinc-500 font-mono text-xs">${date}</td>
            <td class="px-6 py-3 font-mono text-xs text-zinc-300">${s.src_ip}:${s.src_port}</td>
            <td class="px-6 py-3 font-mono text-xs text-zinc-400">${s.dst_ip}:${s.dst_port}</td>
            <td class="px-6 py-3"><span class="px-2 py-0.5 rounded text-xs font-medium ${badgeClass}">${s.protocol}</span></td>
            <td class="px-6 py-3 text-zinc-400">${s.packet_count}</td>
            <td class="px-6 py-3 text-zinc-400">${(s.bytes_sent / 1024).toFixed(1)} KB</td>
        `;
        tbody.appendChild(row);
    });
}
