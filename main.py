from flask import Flask, request, jsonify, session, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///marketplace.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_blocked = db.Column(db.Boolean, default=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    is_blocked = db.Column(db.Boolean, default=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    amount = db.Column(db.Float, nullable=False)

# Login loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template_string('<form method="post">Username: <input name="username"><br>Password: <input name="password"><br><input type="submit"></form>')
    data = request.form if request.form else request.json
    user = User(username=data['username'], password=data['password'])
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User registered'})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template_string('<form method="post">Username: <input name="username"><br>Password: <input name="password"><br><input type="submit"></form>')
    data = request.form if request.form else request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and user.password == data['password'] and not user.is_blocked:
        login_user(user)
        return jsonify({'message': 'Logged in'})
    return jsonify({'message': 'Login failed'}), 401

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out'})

@app.route('/product', methods=['GET', 'POST'])
@login_required
def post_product():
    if request.method == 'GET':
        return render_template_string('<form method="post">Title: <input name="title"><br>Description: <input name="description"><br>Price: <input name="price" type="number"><br><input type="submit"></form>')
    data = request.form if request.form else request.json
    product = Product(title=data['title'], description=data['description'], price=float(data['price']), owner_id=current_user.id)
    db.session.add(product)
    db.session.commit()
    return jsonify({'message': 'Product added'})

@app.route('/products')
def list_products():
    products = Product.query.filter_by(is_blocked=False).all()
    return jsonify([{ 'title': p.title, 'description': p.description, 'price': p.price } for p in products])

@app.route('/message', methods=['GET', 'POST'])
@login_required
def send_message():
    if request.method == 'GET':
        return render_template_string('<form method="post">To (User ID): <input name="receiver_id"><br>Message: <input name="content"><br><input type="submit"></form>')
    data = request.form if request.form else request.json
    message = Message(sender_id=current_user.id, receiver_id=int(data['receiver_id']), content=data['content'])
    db.session.add(message)
    db.session.commit()
    return jsonify({'message': 'Message sent'})

@app.route('/block_user', methods=['GET', 'POST'])
@login_required
def block_user():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    if request.method == 'GET':
        return render_template_string('<form method="post">User ID to block: <input name="user_id"><br><input type="submit"></form>')
    user = User.query.get(int(request.form['user_id']))
    user.is_blocked = True
    db.session.commit()
    return jsonify({'message': 'User blocked'})

@app.route('/block_product', methods=['GET', 'POST'])
@login_required
def block_product():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    if request.method == 'GET':
        return render_template_string('<form method="post">Product ID to block: <input name="product_id"><br><input type="submit"></form>')
    product = Product.query.get(int(request.form['product_id']))
    product.is_blocked = True
    db.session.commit()
    return jsonify({'message': 'Product blocked'})

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    if request.method == 'GET':
        return render_template_string('<form method="post">Receiver ID: <input name="receiver_id"><br>Amount: <input name="amount" type="number"><br><input type="submit"></form>')
    data = request.form if request.form else request.json
    transaction = Transaction(sender_id=current_user.id, receiver_id=int(data['receiver_id']), amount=float(data['amount']))
    db.session.add(transaction)
    db.session.commit()
    return jsonify({'message': 'Transfer completed'})

@app.route('/search')
def search():
    query = request.args.get('q')
    products = Product.query.filter(Product.title.contains(query), Product.is_blocked == False).all()
    return jsonify([{ 'title': p.title, 'description': p.description } for p in products])

@app.route('/admin/all_data')
@login_required
def admin_all_data():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    users = User.query.all()
    products = Product.query.all()
    return jsonify({
        'users': [{ 'id': u.id, 'username': u.username, 'is_blocked': u.is_blocked } for u in users],
        'products': [{ 'id': p.id, 'title': p.title, 'is_blocked': p.is_blocked } for p in products]
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
