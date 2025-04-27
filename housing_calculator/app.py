"""
Housing Calculator - Buy vs Rent Comparison Tool
A web application to compare the financial outcomes of buying versus renting a home.
"""
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

@app.route('/')
def index():
    """Render the main page of the application."""
    return render_template('index.html')

@app.route('/calculate', methods=['POST'])
def calculate():
    """Calculate and compare buying vs renting financial outcomes."""
    # Get form data
    data = request.json
    
    # Extract parameters
    home_price = float(data.get('home_price', 0))
    down_payment_percent = float(data.get('down_payment_percent', 0)) / 100
    loan_term = int(data.get('loan_term', 30))
    interest_rate = float(data.get('interest_rate', 0)) / 100
    annual_property_tax = float(data.get('annual_property_tax', 0)) / 100
    annual_insurance = float(data.get('annual_insurance', 0)) / 100
    annual_maintenance = float(data.get('annual_maintenance', 0)) / 100
    monthly_rent = float(data.get('monthly_rent', 0))
    annual_rent_increase = float(data.get('annual_rent_increase', 0)) / 100
    annual_home_appreciation = float(data.get('annual_home_appreciation', 0)) / 100
    investment_return_rate = float(data.get('investment_return_rate', 0)) / 100
    time_horizon = int(data.get('time_horizon', 30))
    monthly_hoa = float(data.get('monthly_hoa', 0))
    
    # Calculate down payment amount
    down_payment = home_price * down_payment_percent
    loan_amount = home_price - down_payment
    
    # Calculate monthly mortgage payment (principal and interest)
    monthly_interest_rate = interest_rate / 12
    num_payments = loan_term * 12
    
    if monthly_interest_rate > 0:
        monthly_mortgage = loan_amount * (monthly_interest_rate * (1 + monthly_interest_rate) ** num_payments) / ((1 + monthly_interest_rate) ** num_payments - 1)
    else:
        monthly_mortgage = loan_amount / num_payments
    
    # Calculate other monthly costs for homeowner
    monthly_property_tax = home_price * annual_property_tax / 12
    monthly_insurance = home_price * annual_insurance / 12
    monthly_maintenance = home_price * annual_maintenance / 12
    
    # Total monthly cost for homeowner
    total_monthly_cost_homeowner = monthly_mortgage + monthly_property_tax + monthly_insurance + monthly_maintenance + monthly_hoa
    
    # Initialize results arrays for each year
    years = list(range(1, time_horizon + 1))
    buying_total_costs = []
    renting_total_costs = []
    home_values = []
    remaining_mortgage = []
    net_worths_buying = []
    net_worths_renting = []
    
    # Simulation for each year
    current_home_value = home_price
    current_loan_balance = loan_amount
    current_rent = monthly_rent
    
    investment_portfolio_renter = down_payment  # Renter invests down payment
    investment_portfolio_buyer = 0  # Buyer puts down payment into house
    
    for year in range(1, time_horizon + 1):
        # Calculate home value for this year
        current_home_value *= (1 + annual_home_appreciation)
        home_values.append(current_home_value)
        
        # Calculate annual costs for homeowner
        annual_mortgage_payments = monthly_mortgage * 12
        annual_property_tax_payments = monthly_property_tax * 12
        annual_insurance_payments = monthly_insurance * 12
        annual_maintenance_payments = monthly_maintenance * 12
        annual_hoa_payments = monthly_hoa * 12
        
        total_annual_cost_homeowner = annual_mortgage_payments + annual_property_tax_payments + annual_insurance_payments + annual_maintenance_payments + annual_hoa_payments
        
        # Calculate remaining mortgage after this year
        # Simplified mortgage amortization
        interest_payment = current_loan_balance * interest_rate
        principal_payment = min(annual_mortgage_payments - interest_payment, current_loan_balance)
        current_loan_balance -= principal_payment
        remaining_mortgage.append(current_loan_balance)
        
        # Calculate annual costs for renter
        annual_rent_payments = current_rent * 12
        
        # Update rent for next year
        current_rent *= (1 + annual_rent_increase)
        
        # Update investment portfolios
        monthly_savings_renter = total_monthly_cost_homeowner - current_rent
        
        if monthly_savings_renter > 0:  # If renting is cheaper, invest the difference
            investment_portfolio_renter += monthly_savings_renter * 12
        
        # Apply investment returns
        investment_portfolio_renter *= (1 + investment_return_rate)
        investment_portfolio_buyer *= (1 + investment_return_rate)
        
        # Track cumulative costs
        buying_total_costs.append(total_annual_cost_homeowner * year)
        renting_total_costs.append(annual_rent_payments * year)
        
        # Calculate net worths
        net_worth_buying = current_home_value - current_loan_balance + investment_portfolio_buyer
        net_worth_renting = investment_portfolio_renter
        
        net_worths_buying.append(net_worth_buying)
        net_worths_renting.append(net_worth_renting)
    
    # Determine break-even point
    break_even_year = None
    for i in range(len(net_worths_buying)):
        if net_worths_buying[i] > net_worths_renting[i]:
            break_even_year = i + 1
            break
    
    # Prepare results
    result = {
        'years': years,
        'buying_total_costs': buying_total_costs,
        'renting_total_costs': renting_total_costs,
        'home_values': home_values,
        'remaining_mortgage': remaining_mortgage,
        'net_worths_buying': net_worths_buying,
        'net_worths_renting': net_worths_renting,
        'break_even_year': break_even_year,
        'monthly_mortgage': monthly_mortgage,
        'total_monthly_cost_homeowner': total_monthly_cost_homeowner,
        'initial_monthly_rent': monthly_rent,
        'final_monthly_rent': current_rent,
    }
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
