function loadGeoData(id) {
    // Initialize Leaflet Map with Dark Theme
    const map = L.map('map').setView([20, 0], 2);
    
    // Dark matter tiles (CartoDB)
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(map);

    fetch(`/api/data/${id}`)
        .then(res => res.json())
        .then(data => {
            if (data.error) {
                console.error(data.error);
                return;
            }

            if (data.geo && data.geo.length > 0) {
                data.geo.forEach(loc => {
                    // Create pulsing blimp effect using CircleMarker
                    const marker = L.circleMarker([loc.lat, loc.lon], {
                        color: '#2e2e2eff',
                        fillColor: '#d4d4d8',
                        fillOpacity: 0.5,
                        radius: 8,
                        weight: 2
                    }).addTo(map);

                    // Floating info card
                    const popupContent = `
                        <div class="font-sans min-w-[200px]">
                            <h4 class="mb-2 font-bold text-white border-b border-white/10 pb-1">${loc.ip}</h4>
                            <div class="text-sm space-y-1 text-zinc-300">
                                <div class="flex justify-between"><span class="text-zinc-500">Country:</span> <span>${loc.country}</span></div>
                                <div class="flex justify-between"><span class="text-zinc-500">City:</span> <span>${loc.city}</span></div>
                                <div class="flex justify-between"><span class="text-zinc-500">Region:</span> <span>${loc.region || 'Unknown'}</span></div>
                                <div class="flex justify-between"><span class="text-zinc-500">Org:</span> <span class="truncate max-w-[120px]" title="${loc.org}">${loc.org || 'Unknown'}</span></div>
                            </div>
                        </div>
                    `;

                    marker.bindPopup(popupContent);
                });
                
                // Fit bounds if we have points
                if (data.geo.length > 1) {
                    const group = new L.featureGroup(data.geo.map(l => L.marker([l.lat, l.lon])));
                    map.fitBounds(group.getBounds().pad(0.1));
                }
            } else {
                console.log("No Geo data found or resolved.");
            }
        })
        .catch(err => console.error("Geo load error:", err));
}
