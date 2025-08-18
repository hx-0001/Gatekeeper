// Common JavaScript utilities for Gatekeeper
function showError(message, duration = 5000) {
    // Create error modal
    const modal = document.createElement('dialog');
    modal.style.cssText = `
        padding: 20px;
        border: none;
        border-radius: 8px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        background: white;
        max-width: 400px;
        width: 90%;
    `;
    
    modal.innerHTML = `
        <article style="margin: 0;">
            <header style="color: #dc3545; margin-bottom: 16px;">
                <h4 style="margin: 0; display: flex; align-items: center;">
                    <span style="margin-right: 8px;">⚠️</span>
                    错误
                </h4>
            </header>
            <p style="margin: 16px 0;">${message}</p>
            <footer style="text-align: right; margin-top: 20px;">
                <button type="button" class="contrast" onclick="this.closest('dialog').close()">
                    确定
                </button>
            </footer>
        </article>
    `;
    
    document.body.appendChild(modal);
    modal.showModal();
    
    // Auto close after duration
    if (duration > 0) {
        setTimeout(() => {
            if (modal.open) {
                modal.close();
            }
        }, duration);
    }
    
    // Remove modal when closed
    modal.addEventListener('close', () => {
        document.body.removeChild(modal);
    });
}

function showSuccess(message, duration = 3000) {
    // Create success modal
    const modal = document.createElement('dialog');
    modal.style.cssText = `
        padding: 20px;
        border: none;
        border-radius: 8px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        background: white;
        max-width: 400px;
        width: 90%;
    `;
    
    modal.innerHTML = `
        <article style="margin: 0;">
            <header style="color: #28a745; margin-bottom: 16px;">
                <h4 style="margin: 0; display: flex; align-items: center;">
                    <span style="margin-right: 8px;">✅</span>
                    成功
                </h4>
            </header>
            <p style="margin: 16px 0;">${message}</p>
            <footer style="text-align: right; margin-top: 20px;">
                <button type="button" class="secondary" onclick="this.closest('dialog').close()">
                    确定
                </button>
            </footer>
        </article>
    `;
    
    document.body.appendChild(modal);
    modal.showModal();
    
    // Auto close after duration
    if (duration > 0) {
        setTimeout(() => {
            if (modal.open) {
                modal.close();
            }
        }, duration);
    }
    
    // Remove modal when closed
    modal.addEventListener('close', () => {
        document.body.removeChild(modal);
    });
}

// Handle form submissions with AJAX to show popup errors
function setupFormErrorHandling() {
    document.addEventListener('submit', function(e) {
        const form = e.target;
        
        // Ensure we're dealing with a form element
        if (form.tagName !== 'FORM') {
            console.log('Submit event not from a form element:', form.tagName);
            return;
        }
        
        console.log('Form submission intercepted:', form.action, form.method);
        
        // Skip forms that explicitly want default behavior
        if (form.dataset.skipAjax === 'true') {
            console.log('Skipping AJAX for form with data-skip-ajax=true');
            return;
        }
        
        console.log('Preventing default form submission, using AJAX instead');
        e.preventDefault();
        
        const formData = new FormData(form);
        const submitButton = form.querySelector('button[type="submit"]');
        const originalText = submitButton?.textContent;
        
        // Show loading state
        if (submitButton) {
            submitButton.disabled = true;
            submitButton.textContent = '提交中...';
        }
        
        // Use getAttribute to get the actual action attribute, not the property
        const actionUrl = form.getAttribute('action') || window.location.pathname;
        console.log('Sending AJAX request to:', actionUrl);
        fetch(actionUrl, {
            method: form.method || 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => {
            if (response.ok) {
                // Check if it's a JSON response with success message
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    return response.json().then(data => {
                        if (data.success) {
                            showSuccess(data.message || '操作成功');
                            if (data.redirect) {
                                setTimeout(() => {
                                    window.location.href = data.redirect;
                                }, 1000);
                            }
                        }
                    });
                } else {
                    // Redirect for successful non-JSON responses
                    if (response.redirected) {
                        window.location.href = response.url;
                    } else {
                        // Reload the page for successful form submissions
                        window.location.reload();
                    }
                }
            } else {
                // Handle error response
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    return response.json().then(data => {
                        showError(data.error || '操作失败');
                    });
                } else {
                    return response.text().then(text => {
                        // Try to extract error message from plain text response
                        showError(text || `请求失败 (${response.status})`);
                    });
                }
            }
        })
        .catch(error => {
            console.error('Request failed:', error);
            showError('网络错误，请稍后重试');
        })
        .finally(() => {
            // Restore button state
            if (submitButton) {
                submitButton.disabled = false;
                submitButton.textContent = originalText;
            }
        });
    });
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded, setting up form error handling');
    setupFormErrorHandling();
});