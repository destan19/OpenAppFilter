function showCommonModal(message, duration = 2000, type = 'info') {
    const existingModal = document.querySelector('.common-modal-mask');
    if (existingModal) {
        existingModal.remove();
    }

    const modalMask = document.createElement('div');
    modalMask.className = 'common-modal-mask';
    
    const modalContent = document.createElement('div');
    modalContent.className = 'common-modal-content';
    
    modalContent.style.backgroundColor = 'rgba(0, 0, 0, 0.5)';
    modalContent.style.color = 'white';
    
    modalContent.textContent = message;
    
    modalMask.appendChild(modalContent);
    document.body.appendChild(modalMask);
    
    setTimeout(() => {
        modalMask.classList.add('show');
    }, 10);
    
    setTimeout(() => {
        modalMask.classList.remove('show');
        setTimeout(() => {
            if (modalMask.parentNode) {
                modalMask.remove();
            }
        }, 300);
    }, duration);
}

function showSuccess(message, duration = 2000) {
    showCommonModal(message, duration);
}

function showWarning(message, duration = 2000) {
    showCommonModal(message, duration);
}

function showError(message, duration = 3000) {
    showCommonModal(message, duration);
}

function showInfo(message, duration = 2000) {
    showCommonModal(message, duration);
}

function showConfirmModal(message, onConfirm, onCancel, confirmText = '确定', cancelText = '取消') {
    const existingModal = document.querySelector('.common-modal-mask');
    if (existingModal) {
        existingModal.remove();
    }

    const modalMask = document.createElement('div');
    modalMask.className = 'common-modal-mask';
    
    const modalContent = document.createElement('div');
    modalContent.className = 'common-modal-content';
    modalContent.style.width = '300px';
    modalContent.style.height = 'auto';
    modalContent.style.minHeight = '120px';
    modalContent.style.padding = '20px';
    modalContent.style.flexDirection = 'column';
    modalContent.style.justifyContent = 'space-between';
    modalContent.style.backgroundColor = 'rgba(0, 0, 0, 0.5)';
    modalContent.style.color = 'white';
    
    const messageDiv = document.createElement('div');
    messageDiv.textContent = message;
    messageDiv.style.marginBottom = '20px';
    messageDiv.style.textAlign = 'center';
    
    const buttonContainer = document.createElement('div');
    buttonContainer.style.display = 'flex';
    buttonContainer.style.justifyContent = 'center';
    buttonContainer.style.gap = '10px';
    
    const confirmBtn = document.createElement('button');
    confirmBtn.textContent = confirmText;
    confirmBtn.style.padding = '8px 16px';
    confirmBtn.style.backgroundColor = '#2885e8';
    confirmBtn.style.color = 'white';
    confirmBtn.style.border = 'none';
    confirmBtn.style.borderRadius = '4px';
    confirmBtn.style.cursor = 'pointer';
    confirmBtn.onclick = () => {
        modalMask.remove();
        if (onConfirm) onConfirm();
    };
    
    const cancelBtn = document.createElement('button');
    cancelBtn.textContent = cancelText;
    cancelBtn.style.padding = '8px 16px';
    cancelBtn.style.backgroundColor = '#666';
    cancelBtn.style.color = 'white';
    cancelBtn.style.border = 'none';
    cancelBtn.style.borderRadius = '4px';
    cancelBtn.style.cursor = 'pointer';
    cancelBtn.onclick = () => {
        modalMask.remove();
        if (onCancel) onCancel();
    };
    
    buttonContainer.appendChild(confirmBtn);
    buttonContainer.appendChild(cancelBtn);
    
    modalContent.appendChild(messageDiv);
    modalContent.appendChild(buttonContainer);
    modalMask.appendChild(modalContent);
    document.body.appendChild(modalMask);
    
    setTimeout(() => {
        modalMask.classList.add('show');
    }, 10);
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function throttle(func, limit) {
    let inThrottle;
    return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

function getUrlParameter(name) {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(name);
}

function setUrlParameter(name, value) {
    const url = new URL(window.location);
    url.searchParams.set(name, value);
    window.history.replaceState({}, '', url);
}

function deepClone(obj) {
    if (obj === null || typeof obj !== 'object') return obj;
    if (obj instanceof Date) return new Date(obj.getTime());
    if (obj instanceof Array) return obj.map(item => deepClone(item));
    if (typeof obj === 'object') {
        const clonedObj = {};
        for (const key in obj) {
            if (obj.hasOwnProperty(key)) {
                clonedObj[key] = deepClone(obj[key]);
            }
        }
        return clonedObj;
    }
}

function validateIP(ip) {
    if (!ip || ip.trim() === '') return true; 
    const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(ip.trim());
}

function validateNetmask(mask) {
    if (!mask || mask.trim() === '') return true; 
    const maskRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!maskRegex.test(mask.trim())) return false;
    const parts = mask.split('.');
    const binary = parts.map(p => parseInt(p).toString(2).padStart(8, '0')).join('');
    return /^1+0*$/.test(binary);
}

window.showCommonModal = showCommonModal;
window.showSuccess = showSuccess;
window.showWarning = showWarning;
window.showError = showError;
window.showInfo = showInfo;
window.showConfirmModal = showConfirmModal;
window.formatFileSize = formatFileSize;
window.debounce = debounce;
window.throttle = throttle;
window.getUrlParameter = getUrlParameter;
window.setUrlParameter = setUrlParameter;
window.deepClone = deepClone;
window.validateIP = validateIP;
window.validateNetmask = validateNetmask; 
