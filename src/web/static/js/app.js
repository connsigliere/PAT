// Phishing Automation Tool - Main JavaScript

// API Base URL
const API_BASE = '';

// Axios configuration
axios.defaults.headers.common['Content-Type'] = 'application/json';

// Global error handler
axios.interceptors.response.use(
    response => response,
    error => {
        console.error('API Error:', error);
        return Promise.reject(error);
    }
);

// Utility Functions
const utils = {
    // Format date
    formatDate: (dateString) => {
        if (!dateString) return 'N/A';
        return new Date(dateString).toLocaleString();
    },

    // Format number
    formatNumber: (num) => {
        return num.toLocaleString();
    },

    // Calculate percentage
    calculatePercentage: (part, total) => {
        if (total === 0) return '0.0';
        return ((part / total) * 100).toFixed(1);
    },

    // Show toast notification
    showToast: (message, type = 'info') => {
        const toast = document.createElement('div');
        toast.className = `alert alert-${type} alert-dismissible fade show position-fixed top-0 start-50 translate-middle-x mt-3`;
        toast.style.zIndex = '9999';
        toast.style.minWidth = '300px';
        toast.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        document.body.appendChild(toast);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            toast.remove();
        }, 5000);
    },

    // Show loading state
    showLoading: (elementId) => {
        const element = document.getElementById(elementId);
        if (element) {
            element.innerHTML = `
                <div class="text-center py-4">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                </div>
            `;
        }
    },

    // Copy to clipboard
    copyToClipboard: (text) => {
        navigator.clipboard.writeText(text).then(() => {
            utils.showToast('Copied to clipboard!', 'success');
        }).catch(err => {
            console.error('Failed to copy:', err);
        });
    },

    // Download as file
    downloadAsFile: (content, filename, mimeType = 'text/plain') => {
        const blob = new Blob([content], { type: mimeType });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    }
};

// API Helper Functions
const api = {
    // Dashboard
    getDashboardStats: () => axios.get(`${API_BASE}/api/dashboard/stats`),

    // Campaigns
    getCampaigns: (status = null) => {
        const url = status
            ? `${API_BASE}/api/campaigns?status=${status}`
            : `${API_BASE}/api/campaigns`;
        return axios.get(url);
    },

    createCampaign: (data) => axios.post(`${API_BASE}/api/campaigns`, data),

    getCampaign: (id) => axios.get(`${API_BASE}/api/campaigns/${id}`),

    startCampaign: (id) => axios.post(`${API_BASE}/api/campaigns/${id}/start`),

    pauseCampaign: (id) => axios.post(`${API_BASE}/api/campaigns/${id}/pause`),

    completeCampaign: (id) => axios.post(`${API_BASE}/api/campaigns/${id}/complete`),

    getCampaignTargets: (id) => axios.get(`${API_BASE}/api/campaigns/${id}/targets`),

    addCampaignTargets: (id, targets) => axios.post(`${API_BASE}/api/campaigns/${id}/targets`, { targets }),

    getCampaignResults: (id) => axios.get(`${API_BASE}/api/campaigns/${id}/results`),

    // Domain
    checkDomain: (domain) => axios.post(`${API_BASE}/api/domain/check`, { domain }),

    // Email
    generateEmail: (data) => axios.post(`${API_BASE}/api/email/generate`, data),

    getEmailTemplates: () => axios.get(`${API_BASE}/api/email/templates`),

    // Page Cloner
    clonePage: (data) => axios.post(`${API_BASE}/api/clone/page`, data),

    // SSL
    getSSLCertificates: () => axios.get(`${API_BASE}/api/ssl/certificates`),

    obtainSSLCertificate: (data) => axios.post(`${API_BASE}/api/ssl/obtain`, data)
};

// Form validation
function validateForm(formId) {
    const form = document.getElementById(formId);
    if (!form) return false;

    if (!form.checkValidity()) {
        form.reportValidity();
        return false;
    }

    return true;
}

// Get form data as object
function getFormData(formId) {
    const form = document.getElementById(formId);
    const formData = new FormData(form);
    const data = {};

    for (let [key, value] of formData.entries()) {
        data[key] = value;
    }

    return data;
}

// Initialize tooltips
function initTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', function() {
    initTooltips();

    // Add fade-in animation to main content
    document.querySelector('main').classList.add('fade-in');
});

// Export for use in other scripts
window.utils = utils;
window.api = api;
