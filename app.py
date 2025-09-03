# app.py

import os
# Add timedelta for date calculations and jsonify to send data to JavaScript
from datetime import datetime, timedelta
from flask import Flask, render_template, url_for, flash, redirect, session, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, Regexp
from sqlalchemy.sql import func
from functools import wraps

# --- App Config, DB, and Extensions (Unchanged) ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key_for_builderco'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Database Models (Unchanged) ---
class User(db.Model, UserMixin): # ... (same)
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    orders = db.relationship('Order', backref='customer', lazy=True)

class Product(db.Model): # ... (same)
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    stock = db.Column(db.Integer, nullable=False, default=0)

class Order(db.Model): # ... (same)
    id = db.Column(db.Integer, primary_key=True)
    total_price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Pending')
    date_ordered = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    items = db.relationship('OrderItem', backref='order', lazy=True, cascade="all, delete-orphan")

class OrderItem(db.Model): # ... (same)
    id = db.Column(db.Integer, primary_key=True)
    quantity = db.Column(db.Integer, nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    product = db.relationship('Product')
    
class Worker(db.Model): # ... (same)
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    contact = db.Column(db.String(100), nullable=False)

# --- Forms (Unchanged) ---
class RegistrationForm(FlaskForm): # ... (same)
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Regexp('^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d]{8,}$', message='Password must be 8+ characters with a letter and a number.')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm): # ... (same)
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class CheckoutForm(FlaskForm): # ... (same)
    address = TextAreaField('Delivery Address', validators=[DataRequired()])
    submit = SubmitField('Place Order')

class WorkerForm(FlaskForm): # ... (same)
    name = StringField('Worker Name', validators=[DataRequired(), Length(max=100)])
    role = StringField('Role', validators=[DataRequired(), Length(max=50)])
    contact = StringField('Contact Details', validators=[DataRequired(), Length(max=100)])
    submit = SubmitField('Save Worker')

# --- Helper Functions and Decorators (Unchanged) ---
@app.context_processor
def inject_year(): # ... (same)
    return {'current_year': datetime.utcnow().year}
    
# ... (get_cart_items and admin_required are the same) ...
def get_cart_items():
    cart_products = []
    total_price = 0
    if 'cart' in session:
        for product_id, quantity in session['cart'].items():
            product = Product.query.get(product_id)
            if product:
                subtotal = product.price * quantity
                cart_products.append({'product': product, 'quantity': quantity, 'subtotal': subtotal})
                total_price += subtotal
    return cart_products, total_price

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- Public & Cart Routes (Unchanged) ---
@app.route("/")
@app.route("/home")
def home(): # ... (same)
    products = Product.query.all()
    return render_template('index.html', title='Home', products=products)

@app.route("/about")
def about(): # ... (same)
    return render_template('about.html', title='About Us')
# ... (All other public, login, cart, and checkout routes are the same) ...
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    if 'cart' in session: session.pop('cart', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

@app.route("/add_to_cart/<int:product_id>", methods=['POST'])
@login_required
def add_to_cart(product_id):
    if 'cart' not in session: session['cart'] = {}
    cart = session['cart']
    product_id_str = str(product_id)
    quantity = int(request.form.get('quantity', 1))
    product = Product.query.get(product_id)
    if product and quantity <= product.stock:
        if product_id_str in cart:
            cart[product_id_str] += quantity
        else:
            cart[product_id_str] = quantity
        session.modified = True
        flash('Item added to your cart!', 'success')
    else:
        flash('Not enough stock available.', 'danger')
    return redirect(url_for('home'))

@app.route("/cart")
@login_required
def view_cart():
    cart_products, total_price = get_cart_items()
    return render_template('cart.html', title='Shopping Cart', cart_products=cart_products, total_price=total_price)

@app.route("/update_cart/<int:product_id>", methods=['POST'])
@login_required
def update_cart(product_id):
    if 'cart' in session:
        cart = session['cart']
        product_id_str = str(product_id)
        new_quantity = int(request.form.get('quantity'))
        product = Product.query.get(product_id)
        if product and new_quantity <= product.stock:
            if product_id_str in cart:
                if new_quantity > 0:
                    cart[product_id_str] = new_quantity
                else:
                    cart.pop(product_id_str)
                session.modified = True
                flash('Cart updated.', 'success')
        else:
            flash('Not enough stock available for that quantity.', 'danger')
    return redirect(url_for('view_cart'))

@app.route("/remove_from_cart/<int:product_id>", methods=['POST'])
@login_required
def remove_from_cart(product_id):
    if 'cart' in session:
        cart = session['cart']
        product_id_str = str(product_id)
        if product_id_str in cart:
            cart.pop(product_id_str)
            session.modified = True
    return redirect(url_for('view_cart'))

@app.route("/checkout", methods=['GET', 'POST'])
@login_required
def checkout():
    cart_products, total_price = get_cart_items()
    if not cart_products: return redirect(url_for('home'))
    form = CheckoutForm()
    if form.validate_on_submit():
        new_order = Order(total_price=total_price, customer=current_user)
        db.session.add(new_order)
        for item in cart_products:
            order_item = OrderItem(order=new_order, product_id=item['product'].id, quantity=item['quantity'])
            db.session.add(order_item)
            product = Product.query.get(item['product'].id)
            product.stock -= item['quantity']
        db.session.commit()
        session.pop('cart', None)
        return redirect(url_for('order_confirmation', order_id=new_order.id))
    return render_template('checkout.html', title='Checkout', cart_products=cart_products, total_price=total_price, form=form)

@app.route("/order_confirmation/<int:order_id>")
@login_required
def order_confirmation(order_id):
    order = Order.query.get_or_44(order_id)
    if order.customer != current_user and not current_user.is_admin:
        flash('You are not authorized to view this order.', 'danger')
        return redirect(url_for('home'))
    return render_template('order_confirmation.html', title='Order Confirmation', order=order)
    
# --- Admin Routes ---
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard(): # ... (same)
    stats = {
        'total_revenue': db.session.query(func.sum(Order.total_price)).scalar(),
        'pending_orders': Order.query.filter_by(status='Pending').count(),
        'total_customers': User.query.filter_by(is_admin=False).count()
    }
    return render_template('admin/dashboard.html', title='Dashboard', stats=stats)
# ... (admin_orders, update_order_status, admin_inventory, update_inventory routes are the same) ...
@app.route("/admin/orders")
@admin_required
def admin_orders():
    orders = Order.query.order_by(Order.date_ordered.desc()).all()
    return render_template('admin/orders.html', title='Manage Orders', orders=orders)

@app.route("/admin/orders/update_status/<int:order_id>", methods=['POST'])
@admin_required
def update_order_status(order_id):
    order = Order.query.get_or_404(order_id)
    new_status = request.form.get('status')
    if new_status in ['Pending', 'Shipped', 'Delivered']:
        order.status = new_status
        db.session.commit()
        flash(f'Order #{order.id} status updated to {new_status}.', 'success')
    else:
        flash('Invalid status.', 'danger')
    return redirect(url_for('admin_orders'))

@app.route("/admin/inventory")
@admin_required
def admin_inventory():
    products = Product.query.all()
    return render_template('admin/inventory.html', title='Manage Inventory', products=products)

@app.route("/admin/inventory/update/<int:product_id>", methods=['POST'])
@admin_required
def update_inventory(product_id):
    product = Product.query.get_or_404(product_id)
    try:
        new_stock = int(request.form.get('stock'))
        if new_stock >= 0:
            product.stock = new_stock
            db.session.commit()
            flash(f"Stock for {product.name} updated to {new_stock}.", 'success')
        else:
            flash("Stock cannot be negative.", 'danger')
    except (ValueError, TypeError):
        flash("Invalid input for stock.", 'danger')
    return redirect(url_for('admin_inventory'))

@app.route("/admin/workers")
@admin_required
def admin_workers(): # ... (same)
    workers = Worker.query.all()
    return render_template('admin/workers.html', title='Manage Workers', workers=workers)

@app.route("/admin/workers/add", methods=['GET', 'POST'])
@admin_required
def add_worker(): # ... (same)
    form = WorkerForm()
    if form.validate_on_submit():
        new_worker = Worker(name=form.name.data, role=form.role.data, contact=form.contact.data)
        db.session.add(new_worker)
        db.session.commit()
        flash(f'Worker {new_worker.name} has been added.', 'success')
        return redirect(url_for('admin_workers'))
    return render_template('admin/worker_form.html', title='Add New Worker', form=form)

@app.route("/admin/workers/edit/<int:worker_id>", methods=['GET', 'POST'])
@admin_required
def edit_worker(worker_id): # ... (same)
    worker = Worker.query.get_or_404(worker_id)
    form = WorkerForm(obj=worker)
    if form.validate_on_submit():
        worker.name = form.name.data
        worker.role = form.role.data
        worker.contact = form.contact.data
        db.session.commit()
        flash(f'Worker {worker.name} has been updated.', 'success')
        return redirect(url_for('admin_workers'))
    return render_template('admin/worker_form.html', title='Edit Worker', form=form)

@app.route("/admin/workers/delete/<int:worker_id>", methods=['POST'])
@admin_required
def delete_worker(worker_id): # ... (same)
    worker = Worker.query.get_or_404(worker_id)
    db.session.delete(worker)
    db.session.commit()
    flash(f'Worker {worker.name} has been deleted.', 'success')
    return redirect(url_for('admin_workers'))

# --- NEW ROUTE FOR CHART DATA ---
@app.route("/admin/sales_data")
@admin_required
def get_sales_data():
    # Get data for the last 7 days
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    
    # Query and group orders by date
    sales = db.session.query(
        func.date(Order.date_ordered).label('date'),
        func.sum(Order.total_price).label('total')
    ).filter(Order.date_ordered >= seven_days_ago).group_by(func.date(Order.date_ordered)).order_by('date').all()
    
    # Format the data for Chart.js
    labels = [sale.date.strftime('%b %d') for sale in sales]
    data = [sale.total for sale in sales]
    
    return jsonify({'labels': labels, 'data': data})


if __name__ == '__main__':
    app.run(debug=True)