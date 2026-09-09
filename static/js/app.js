// AI Chat Bot (Prompt Injection Demo)
document.addEventListener('DOMContentLoaded', function() {
    const aiChatForm = document.getElementById('aiChatForm');
    if (aiChatForm) {
        aiChatForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const prompt = document.getElementById('aiPrompt').value;
            const token = localStorage.getItem('jwt_token');
            
            const response = await fetch('/api/ai/chatbot', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': token ? `Bearer ${token}` : ''
                },
                body: JSON.stringify({
                    model: 'AIChatBot',
                    year: 2025,
                    price: 0,
                    user_instructions: prompt
                })
            });
            const data = await response.json();
            const resultDiv = document.getElementById('aiChatResult');
            if (data.description) {
                resultDiv.innerHTML = `<div class="alert alert-success"><strong>AI Bot:</strong><br>${data.description}</div>`;
            } else {
                resultDiv.innerHTML = `<div class="alert alert-danger">Error: ${data.error || 'Unknown error'}</div>`;
            }
        });
    }
});
// Mobile sidebar toggle
document.addEventListener('DOMContentLoaded', function() {
    const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
    const sidebar = document.querySelector('.sidebar');
    
    if (mobileMenuBtn && sidebar) {
        mobileMenuBtn.addEventListener('click', function() {
            sidebar.classList.toggle('active');
        });
    }
    
    // Handle file upload preview
    const fileInput = document.getElementById('fileInput');
    const imagePreview = document.getElementById('imagePreview');
    
    if (fileInput && imagePreview) {
        fileInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = function(e) {
                    imagePreview.innerHTML = `<img src="${e.target.result}" alt="Preview" style="max-width: 100%; max-height: 200px;">`;
                };
                reader.readAsDataURL(file);
            }
        });
    }
    
    // Handle payment form
    const paymentForm = document.getElementById('paymentForm');
    if (paymentForm) {
        paymentForm.addEventListener('submit', function(e) {
            e.preventDefault();
            processPayment();
        });
    }
    
    // Handle search functionality
    const searchForm = document.getElementById('searchForm');
    if (searchForm) {
        searchForm.addEventListener('submit', function(e) {
            e.preventDefault();
            performSearch();
        });
    }

    const garageControlForm = document.getElementById('garageControlForm');
    if (garageControlForm) {
        garageControlForm.addEventListener('submit', handleGarageControlSubmit);
    }

    document.querySelectorAll('.purchase-product-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const productId = this.getAttribute('data-product-id');
            if (productId) {
                purchaseProduct(parseInt(productId, 10));
            }
        });
    });
});

function processPayment() {
    const formData = new FormData(document.getElementById('paymentForm'));
    const amount = formData.get('amount');
    const productId = formData.get('product_id');
    
    fetch('/api/payments/create', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            amount: parseFloat(amount),
            product_id: parseInt(productId)
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showAlert('Payment processed successfully!', 'success');
            setTimeout(() => {
                window.location.href = '/orders';
            }, 2000);
        } else {
            showAlert('Payment failed: ' + data.error, 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showAlert('An error occurred during payment processing', 'danger');
    });
}

function performSearch() {
    const formData = new FormData(document.getElementById('searchForm'));
    const params = new URLSearchParams();
    
    for (let [key, value] of formData) {
        if (value) params.append(key, value);
    }
    
    window.location.href = `/products?${params.toString()}`;
}

function showAlert(message, type) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type}`;
    alertDiv.textContent = message;
    
    const container = document.querySelector('.main-content');
    container.insertBefore(alertDiv, container.firstChild);
    
    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}

// Handle product purchase
function purchaseProduct(productId) {
    if (!confirm('Are you sure you want to purchase this product?')) {
        return;
    }
    
    // Prepare purchase data with potential vulnerability parameters
    const purchaseData = {
        product_id: productId,
        payment_method: 'web_purchase'
    };
    
    // Check for price override (VULNERABILITY: Client-side can modify price)
    const priceOverrideElement = document.getElementById('priceOverride');
    if (priceOverrideElement && priceOverrideElement.value) {
        purchaseData.price_override = parseFloat(priceOverrideElement.value);
    }
    
    // Check for discount code (VULNERABILITY: Client can send hidden codes)
    const discountCodeElement = document.getElementById('discountCode');
    if (discountCodeElement && discountCodeElement.value) {
        purchaseData.discount_code = discountCodeElement.value;
    }
    
    // Check for special offer (VULNERABILITY: Client can enable special offers)
    const specialOfferElement = document.getElementById('specialOffer');
    if (specialOfferElement && specialOfferElement.checked) {
        purchaseData.special_offer = true;
    }
    
    console.log('Sending purchase request with potential vulnerabilities:', purchaseData);
    
    fetch(`/api/products/${productId}/purchase`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(purchaseData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            const vulnInfo = data.vulnerability_exploited ? 
                `\n\n⚠️ VULNERABILITY EXPLOITED!\nActual Price: $${data.actual_price.toFixed(2)}\nYou Paid: $${data.paid_amount.toFixed(2)}\nSavings: $${data.discount_applied.toFixed(2)}` : '';
            showAlert('Product purchased successfully!' + vulnInfo, 'success');
            setTimeout(() => {
                window.location.href = '/orders';
            }, 2000);
        } else {
            showAlert('Purchase failed: ' + data.error, 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showAlert('An error occurred during purchase', 'danger');
    });
}

// Handle file upload
function uploadProductImage(productId) {
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    
    if (!file) {
        showAlert('Please select a file to upload', 'warning');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    
    fetch(`/api/products/${productId}/upload`, {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            showAlert('File uploaded successfully!', 'success');
            setTimeout(() => {
                window.location.reload();
            }, 2000);
        } else {
            showAlert('Upload failed: ' + data.error, 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showAlert('An error occurred during upload', 'danger');
    });
}

function handleGarageControlSubmit(event) {
    event.preventDefault();
    const payload = {};

    const valueOrNull = (id) => {
        const el = document.getElementById(id);
        return el ? el.value.trim() : '';
    };

    const orderId = valueOrNull('gcOrderId');
    const orderStatus = valueOrNull('gcOrderStatus');
    const userId = valueOrNull('gcUserId');
    const userBalance = valueOrNull('gcUserBalance');
    const grantAdminEl = document.getElementById('gcGrantAdmin');
    const productId = valueOrNull('gcProductId');
    const productAvailableEl = document.getElementById('gcProductAvailable');
    const transferProductTo = valueOrNull('gcTransferProductTo');

    if (orderId) payload.order_id = parseInt(orderId, 10);
    if (orderStatus) payload.order_status = orderStatus;
    if (userId) payload.user_id = parseInt(userId, 10);
    if (userBalance) payload.user_balance = parseFloat(userBalance);
    if (grantAdminEl && grantAdminEl.value !== '') payload.grant_admin = grantAdminEl.value === 'true';
    if (productId) payload.product_id = parseInt(productId, 10);
    if (productAvailableEl && productAvailableEl.value !== '') payload.product_available = productAvailableEl.value === 'true';
    if (transferProductTo) payload.transfer_product_to = parseInt(transferProductTo, 10);

    fetch('/api/garage/control-center', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
    .then(res => res.json().then(body => ({ status: res.status, body })))
    .then(({ status, body }) => {
        const resultDiv = document.getElementById('garageControlResult');
        if (!resultDiv) return;

        if (status === 200) {
            resultDiv.className = 'alert alert-success mt-3';
            resultDiv.innerHTML = `<strong>Garage controls applied.</strong><pre>${JSON.stringify(body.actions || [], null, 2)}</pre>`;
        } else {
            resultDiv.className = 'alert alert-danger mt-3';
            resultDiv.innerHTML = `<strong>Garage control failed:</strong> ${body.detail || body.error || 'Unknown error'}`;
        }
        resultDiv.style.display = 'block';
    })
    .catch(error => {
        const resultDiv = document.getElementById('garageControlResult');
        if (!resultDiv) return;
        resultDiv.className = 'alert alert-danger mt-3';
        resultDiv.innerHTML = `<strong>Request error:</strong> ${error}`;
        resultDiv.style.display = 'block';
    });
}