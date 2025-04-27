/**
 * Housing Calculator - Buy vs Rent Comparison Tool
 * Main JavaScript file for the calculator functionality
 */

// Chart instances
let netWorthChart = null;
let costsChart = null;
let homeDetailsChart = null;

// Format large numbers with commas
function formatNumber(num) {
    return Math.round(num).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    // Form submission handler
    document.getElementById('calculatorForm').addEventListener('submit', function(e) {
        e.preventDefault();
        calculateResults();
    });
});

// Main calculation function
function calculateResults() {
    // Show loading indicator
    document.getElementById('loadingIndicator').style.display = 'block';
    document.getElementById('resultsContainer').style.display = 'none';
    
    // Get form values
    const formData = {
        home_price: document.getElementById('homePrice').value,
        down_payment_percent: document.getElementById('downPaymentPercent').value,
        loan_term: document.getElementById('loanTerm').value,
        interest_rate: document.getElementById('interestRate').value,
        annual_property_tax: document.getElementById('annualPropertyTax').value,
        annual_insurance: document.getElementById('annualInsurance').value,
        annual_maintenance: document.getElementById('annualMaintenance').value,
        monthly_rent: document.getElementById('monthlyRent').value,
        annual_rent_increase: document.getElementById('annualRentIncrease').value,
        annual_home_appreciation: document.getElementById('annualHomeAppreciation').value,
        investment_return_rate: document.getElementById('investmentReturnRate').value,
        time_horizon: document.getElementById('timeHorizon').value,
        monthly_hoa: document.getElementById('monthlyHoa').value
    };
    
    // Send data to the server for calculation
    fetch('/calculate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
    })
    .then(response => response.json())
    .then(data => {
        // Hide loading indicator
        document.getElementById('loadingIndicator').style.display = 'none';
        document.getElementById('resultsContainer').style.display = 'block';
        
        // Update summary information
        document.getElementById('monthlyMortgage').textContent = formatNumber(data.monthly_mortgage);
        document.getElementById('totalMonthlyCost').textContent = formatNumber(data.total_monthly_cost_homeowner);
        document.getElementById('initialMonthlyRent').textContent = formatNumber(data.initial_monthly_rent);
        document.getElementById('finalMonthlyRent').textContent = formatNumber(data.final_monthly_rent);
        document.getElementById('finalNetWorthBuying').textContent = formatNumber(data.net_worths_buying[data.net_worths_buying.length - 1]);
        document.getElementById('finalNetWorthRenting').textContent = formatNumber(data.net_worths_renting[data.net_worths_renting.length - 1]);
        
        // Update break-even point
        const breakEvenContainer = document.getElementById('breakEvenContainer');
        if (data.break_even_year) {
            document.getElementById('breakEvenYear').textContent = data.break_even_year;
            breakEvenContainer.className = 'alert alert-success';
        } else {
            document.getElementById('breakEvenYear').textContent = '在计算周期内未达到';
            breakEvenContainer.className = 'alert alert-warning';
        }
        
        // Create/update charts
        createNetWorthChart(data);
        createCostsChart(data);
        createHomeDetailsChart(data);
    })
    .catch(error => {
        console.error('Error:', error);
        document.getElementById('loadingIndicator').style.display = 'none';
        alert('计算过程中出现错误，请重试。');
    });
}

// Create Net Worth Comparison Chart
function createNetWorthChart(data) {
    const ctx = document.getElementById('netWorthChart').getContext('2d');
    
    // Destroy previous chart instance if it exists
    if (netWorthChart) {
        netWorthChart.destroy();
    }
    
    netWorthChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.years,
            datasets: [
                {
                    label: '买房净资产',
                    data: data.net_worths_buying,
                    borderColor: '#28a745',
                    backgroundColor: 'rgba(40, 167, 69, 0.1)',
                    borderWidth: 2,
                    fill: true
                },
                {
                    label: '租房净资产',
                    data: data.net_worths_renting,
                    borderColor: '#007bff',
                    backgroundColor: 'rgba(0, 123, 255, 0.1)',
                    borderWidth: 2,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: '净资产对比 - 买房 vs 租房'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            let label = context.dataset.label || '';
                            if (label) {
                                label += ': ';
                            }
                            label += '¥' + formatNumber(context.parsed.y);
                            return label;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: '净资产 (元)'
                    },
                    ticks: {
                        callback: function(value) {
                            return '¥' + formatNumber(value);
                        }
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: '年数'
                    }
                }
            }
        }
    });
}

// Create Costs Comparison Chart
function createCostsChart(data) {
    const ctx = document.getElementById('costsChart').getContext('2d');
    
    // Destroy previous chart instance if it exists
    if (costsChart) {
        costsChart.destroy();
    }
    
    costsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.years,
            datasets: [
                {
                    label: '买房累计支出',
                    data: data.buying_total_costs,
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    borderWidth: 2,
                    fill: true
                },
                {
                    label: '租房累计支出',
                    data: data.renting_total_costs,
                    borderColor: '#fd7e14',
                    backgroundColor: 'rgba(253, 126, 20, 0.1)',
                    borderWidth: 2,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: '累计支出对比 - 买房 vs 租房'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            let label = context.dataset.label || '';
                            if (label) {
                                label += ': ';
                            }
                            label += '¥' + formatNumber(context.parsed.y);
                            return label;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: '累计支出 (元)'
                    },
                    ticks: {
                        callback: function(value) {
                            return '¥' + formatNumber(value);
                        }
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: '年数'
                    }
                }
            }
        }
    });
}

// Create Home Details Chart
function createHomeDetailsChart(data) {
    const ctx = document.getElementById('homeDetailsChart').getContext('2d');
    
    // Destroy previous chart instance if it exists
    if (homeDetailsChart) {
        homeDetailsChart.destroy();
    }
    
    homeDetailsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.years,
            datasets: [
                {
                    label: '房屋价值',
                    data: data.home_values,
                    borderColor: '#20c997',
                    backgroundColor: 'rgba(32, 201, 151, 0.1)',
                    borderWidth: 2,
                    fill: true
                },
                {
                    label: '剩余贷款',
                    data: data.remaining_mortgage,
                    borderColor: '#6c757d',
                    backgroundColor: 'rgba(108, 117, 125, 0.1)',
                    borderWidth: 2,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: '房产价值与贷款余额'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            let label = context.dataset.label || '';
                            if (label) {
                                label += ': ';
                            }
                            label += '¥' + formatNumber(context.parsed.y);
                            return label;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: '金额 (元)'
                    },
                    ticks: {
                        callback: function(value) {
                            return '¥' + formatNumber(value);
                        }
                    }
                },
                x: {
                    title: {
                        display: true,
                        text: '年数'
                    }
                }
            }
        }
    });
}
