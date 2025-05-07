// Dashboard JavaScript functions

// Helper function to get authentication token from URL
function getAuthToken() {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get('token');
}

// Helper function to add token to API endpoint URLs
function getApiUrl(endpoint) {
    const token = getAuthToken();
    if (token) {
        return `${endpoint}${endpoint.includes('?') ? '&' : '?'}token=${token}`;
    }
    return endpoint;
}

// DOM elements will be loaded once the document is ready
document.addEventListener('DOMContentLoaded', function() {
    // Initialize recurring log updates
    initializeLogUpdates();
    
    // Add event listeners for ANPR toggle button
    initializeAnprToggle();
    
    // Initialize charts if Chart.js is available and chart containers exist
    if (typeof Chart !== 'undefined') {
        initializeCharts();
    }
    
    // Initialize vehicle edit modal functionality
    initializeEditVehicleModal();
    
    // Initialize vehicle delete modal functionality
    initializeDeleteVehicleModal();
});

/**
 * Initialize automatic log updates
 */
function initializeLogUpdates() {
    // Check if we're on a page that needs recurring log updates
    const recentLogsContainer = document.getElementById('recent-logs-container');
    if (recentLogsContainer) {
        // Set up recurring fetch of log data
        function refreshLogs() {
            fetch(getApiUrl('/api/logs/recent?limit=10'))
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        recentLogsContainer.innerHTML = data.html;
                    }
                })
                .catch(error => {
                    console.error('Error fetching logs:', error);
                });
        }
        
        // Refresh logs every 10 seconds
        setInterval(refreshLogs, 10000);
    }
}

/**
 * Initialize ANPR toggle button functionality
 */
function initializeAnprToggle() {
    const anprToggleBtn = document.getElementById('anprToggleBtn');
    
    if (anprToggleBtn) {
        anprToggleBtn.addEventListener('click', function() {
            const isRunning = anprToggleBtn.classList.contains('btn-danger');
            const url = isRunning ? '/api/anpr/stop' : '/api/anpr/start';
            
            fetch(getApiUrl(url), {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert(data.message, 'success');
                    
                    // Update button state
                    updateAnprStatus(!isRunning);
                    
                    // Refresh page after short delay
                    setTimeout(() => {
                        window.location.reload();
                    }, 2000);
                } else {
                    showAlert(data.message, 'danger');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert('Error communicating with server', 'danger');
            });
        });
    }
}

/**
 * Update ANPR status button appearance
 * @param {boolean} isRunning - Whether ANPR is running
 */
function updateAnprStatus(isRunning) {
    const anprToggleBtn = document.getElementById('anprToggleBtn');
    if (!anprToggleBtn) return;
    
    if (isRunning) {
        anprToggleBtn.classList.remove('btn-success');
        anprToggleBtn.classList.add('btn-danger');
        anprToggleBtn.innerHTML = '<i class="fas fa-stop me-1"></i> Stop ANPR';
    } else {
        anprToggleBtn.classList.remove('btn-danger');
        anprToggleBtn.classList.add('btn-success');
        anprToggleBtn.innerHTML = '<i class="fas fa-play me-1"></i> Start ANPR';
    }
}

/**
 * Display an alert message that fades after a few seconds
 * @param {string} message - Alert message
 * @param {string} type - Alert type (success, danger, warning, info)
 */
function showAlert(message, type) {
    const alertContainer = document.createElement('div');
    alertContainer.className = `alert alert-${type} alert-dismissible fade show position-fixed top-0 end-0 m-3`;
    alertContainer.style.zIndex = '9999';
    alertContainer.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    document.body.appendChild(alertContainer);
    
    // Auto dismiss after 5 seconds
    setTimeout(() => {
        alertContainer.remove();
    }, 5000);
}

/**
 * Initialize dashboard charts
 */
function initializeCharts() {
    // Only initialize if Chart.js is available and containers exist
    if (typeof Chart === 'undefined') return;
    
    // Traffic chart initialization
    const trafficChartContainer = document.getElementById('traffic-chart');
    if (trafficChartContainer) {
        initializeTrafficChart();
    }
    
    // Accuracy chart initialization
    const accuracyChartContainer = document.getElementById('accuracy-chart');
    if (accuracyChartContainer) {
        initializeAccuracyChart();
    }
}

/**
 * Initialize traffic chart with entry/exit data
 */
function initializeTrafficChart() {
    // Fetch traffic data from API
    fetch(getApiUrl('/api/stats/daily_traffic'))
        .then(response => response.json())
        .then(data => {
            if (!data.success) return;
            
            const ctx = document.getElementById('traffic-chart').getContext('2d');
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: data.labels,
                    datasets: [
                        {
                            label: 'Entries',
                            data: data.entries,
                            backgroundColor: 'rgba(40, 167, 69, 0.7)',
                            borderColor: 'rgba(40, 167, 69, 1)',
                            borderWidth: 1
                        },
                        {
                            label: 'Exits',
                            data: data.exits,
                            backgroundColor: 'rgba(255, 193, 7, 0.7)',
                            borderColor: 'rgba(255, 193, 7, 1)',
                            borderWidth: 1
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                precision: 0
                            }
                        }
                    }
                }
            });
        })
        .catch(error => {
            console.error('Error loading traffic chart:', error);
        });
}

/**
 * Initialize recognition accuracy chart
 */
function initializeAccuracyChart() {
    // Fetch accuracy data from API
    fetch(getApiUrl('/api/stats/recognition_accuracy'))
        .then(response => response.json())
        .then(data => {
            if (!data.success) return;
            
            const ctx = document.getElementById('accuracy-chart').getContext('2d');
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['High (>90%)', 'Medium (70-90%)', 'Low (<70%)'],
                    datasets: [
                        {
                            data: [data.high, data.medium, data.low],
                            backgroundColor: [
                                'rgba(40, 167, 69, 0.7)',
                                'rgba(23, 162, 184, 0.7)',
                                'rgba(220, 53, 69, 0.7)'
                            ],
                            borderColor: [
                                'rgba(40, 167, 69, 1)',
                                'rgba(23, 162, 184, 1)',
                                'rgba(220, 53, 69, 1)'
                            ],
                            borderWidth: 1
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });
        })
        .catch(error => {
            console.error('Error loading accuracy chart:', error);
        });
}

/**
 * Initialize edit vehicle modal to populate form fields
 */
function initializeEditVehicleModal() {
    const editModal = document.getElementById('editVehicleModal');
    if (!editModal) return;
    
    editModal.addEventListener('show.bs.modal', function (event) {
        // Button that triggered the modal
        const button = event.relatedTarget;
        
        // Extract info from data attributes
        const vehicleId = button.getAttribute('data-bs-vehicle-id');
        const licensePlate = button.getAttribute('data-bs-license-plate');
        const ownerName = button.getAttribute('data-bs-owner-name');
        const ownerPhone = button.getAttribute('data-bs-owner-phone');
        const flatUnitNumber = button.getAttribute('data-bs-flat-unit-number');
        const vehicleType = button.getAttribute('data-bs-vehicle-type');
        const status = button.getAttribute('data-bs-status');
        const isResident = button.getAttribute('data-bs-is-resident') === 'true';
        const notes = button.getAttribute('data-bs-notes');
        
        // Update the modal's content
        const modalVehicleId = editModal.querySelector('#edit_vehicle_id');
        const modalLicensePlate = editModal.querySelector('#edit_license_plate');
        const modalOwnerName = editModal.querySelector('#edit_owner_name');
        const modalOwnerPhone = editModal.querySelector('#edit_owner_phone');
        const modalFlatUnitNumber = editModal.querySelector('#edit_flat_unit_number');
        const modalVehicleType = editModal.querySelector('#edit_vehicle_type');
        const modalStatus = editModal.querySelector('#edit_status');
        const modalIsResident = editModal.querySelector('#edit_is_resident');
        const modalNotes = editModal.querySelector('#edit_notes');
        
        // Set values in form fields
        modalVehicleId.value = vehicleId;
        modalLicensePlate.value = licensePlate;
        modalOwnerName.value = ownerName;
        modalOwnerPhone.value = ownerPhone;
        modalFlatUnitNumber.value = flatUnitNumber;
        
        // Set select options
        if (vehicleType) {
            modalVehicleType.value = vehicleType;
        }
        
        if (status) {
            modalStatus.value = status;
        }
        
        // Set checkbox
        modalIsResident.checked = isResident;
        
        // Set textarea
        modalNotes.value = notes;
        
        // Update form action to include token
        const form = editModal.querySelector('form');
        form.action = getApiUrl('/edit_vehicle');
    });
}

/**
 * Initialize delete vehicle modal
 */
function initializeDeleteVehicleModal() {
    const deleteModal = document.getElementById('deleteVehicleModal');
    if (!deleteModal) return;
    
    deleteModal.addEventListener('show.bs.modal', function (event) {
        // Button that triggered the modal
        const button = event.relatedTarget;
        
        // Extract info from data attributes
        const vehicleId = button.getAttribute('data-bs-vehicle-id');
        const licensePlate = button.getAttribute('data-bs-license-plate');
        
        // Update the modal's content
        const modalVehicleId = deleteModal.querySelector('#delete_vehicle_id');
        const modalLicensePlateText = deleteModal.querySelector('#delete_license_plate_text');
        
        modalVehicleId.value = vehicleId;
        if (modalLicensePlateText) {
            modalLicensePlateText.textContent = licensePlate;
        }
        
        // Update form action to include token
        const form = deleteModal.querySelector('form');
        form.action = getApiUrl('/delete_vehicle');
    });
}