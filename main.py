from flask import Flask, request, jsonify, session, redirect, url_for, render_template, flash
from werkzeug.utils import escape
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///market.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    bio = db.Column(db.String(255), default="")
    is_dormant = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    balance = db.Column(db.Integer, default=10000)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.Text)
    price = db.Column(db.Float)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    reported = db.Column(db.Boolean, default=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text)

    # sender와 receiver를 User 모델과 연결
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_type = db.Column(db.String(10))  # 'user' or 'product'
    target_id = db.Column(db.Integer)
    reason = db.Column(db.String(255), nullable=True)  # 신고 사유 추가

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # 비밀번호와 사용자 이름 검증
        if not username or not password:
            return render_template('register.html', error_message="사용자 이름과 비밀번호는 필수입니다.")

        # 사용자 이름 중복 체크
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error_message="이 사용자 이름은 이미 존재합니다.")

        # 새로운 사용자 생성
        new_user = User(username=username, password=password)
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()  # 예외 발생 시 롤백
            return render_template('register.html', error_message="회원가입 중 오류가 발생했습니다. 다시 시도해주세요.")

    return render_template('register.html')

@app.route('/admin/reports', methods=['GET', 'POST'])
@login_required
def admin_reports():
    if not current_user.is_admin:
        return redirect(url_for('home'))  # 관리자가 아니면 홈으로 리디렉션

    # 신고된 상품과 유저를 Report 테이블에서 조회
    reported_products = Report.query.filter_by(report_type='product').all()
    reported_users = Report.query.filter_by(report_type='user').all()

    # 신고된 상품과 유저 정보 추가
    products = [Product.query.get(report.target_id) for report in reported_products]
    users = [User.query.get(report.target_id) for report in reported_users]

    # 신고된 내역이 없으면 팝업을 띄우기 위한 플래그 설정
    no_reports = not reported_products and not reported_users

    # zip()을 사용하여 신고된 상품과 유저 정보를 한 번에 전달
    reports_with_products = zip(reported_products, products)
    reports_with_users = zip(reported_users, users)

    # POST 요청을 처리하여 신고 내역 삭제
    if request.method == 'POST':
        report_id = request.form.get('report_id')  # 신고 내역 ID
        if report_id:
            report = Report.query.get_or_404(report_id)
            db.session.delete(report)
            db.session.commit()
            return redirect(url_for('admin_reports'))  # 삭제 후 다시 목록 페이지로 리디렉션

    return render_template('admin_reports.html', 
                           reports_with_products=reports_with_products, 
                           reports_with_users=reports_with_users,
                           no_reports=no_reports)






@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username'], password=request.form['password']).first()
        if user:
            if user.is_dormant:
                return render_template('login.html', error="이 계정은 휴면 상태입니다. 관리자에게 문의하세요.")
            login_user(user)
            return redirect(url_for('profile'))
        else:
            return render_template('login.html', error="아이디 또는 비밀번호가 올바르지 않습니다.")
    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.bio = request.form['bio']
        current_user.password = request.form['password']
        db.session.commit()
    return render_template('profile.html', user=current_user)

@app.route('/users')
@login_required
def users():
    # admin 계정을 제외한 사용자 목록을 가져옵니다.
    users = User.query.filter_by(is_admin=False).all()  # admin이 아닌 사용자만 조회
    return render_template('users.html', users=users)


@app.route('/products', methods=['GET', 'POST'])
@login_required
def products():
    search_query = request.args.get('search', '')  # 검색어 가져오기
    if search_query:
        # 검색어가 있을 경우 제목에 검색어가 포함된 상품만 필터링
        products = Product.query.filter(Product.title.contains(search_query)).all()
    else:
        # 검색어가 없으면 모든 상품 조회
        products = Product.query.all()

    return render_template('products.html', products=products)


@app.route('/product/<int:id>')
@login_required
def product_detail(id):
    product = Product.query.get_or_404(id)
    if product.reported:
        return "<script>alert('이 상품은 차단되어 접속할 수 없습니다.'); window.location.href='/products';</script>"
    return render_template('product_detail.html', product=product)


@app.route('/manage_products')
@login_required
def manage_products():
    return render_template('manage_products.html', products=Product.query.filter_by(user_id=current_user.id))


@app.route('/report_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def report_product(product_id):
    product = Product.query.get_or_404(product_id)

    if request.method == 'POST':
        reason = request.form.get('reason')
        
        if reason:
            # 신고 내역만 Report 테이블에 저장
            report = Report(report_type='product', target_id=product_id, reason=reason)
            db.session.add(report)
            db.session.commit()

        return redirect(url_for('products'))

    # GET 요청일 때는 신고 사유 입력 form 보여주기
    return render_template('report.html', type='product', target=product)




@app.route('/report_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def report_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        reason = request.form.get('reason')
        if reason:
            # 신고 내역만 Report 테이블에 저장
            report = Report(report_type='user', target_id=user_id, reason=reason)
            db.session.add(report)
            db.session.commit()

            return redirect(url_for('users'))

    return render_template('report_user.html', reported_user=user)


@app.route('/send_money', methods=['GET', 'POST'])
@login_required
def send_money():
    if request.method == 'POST':
        receiver_username = request.form['receiver_username']  # 수신자 이름
        amount = float(request.form['amount'])  # 송금액

        # 수신자 이름을 통해 User 모델에서 해당 사용자 검색
        receiver = User.query.filter_by(username=receiver_username).first()

        if not receiver:
            return "수신자를 찾을 수 없습니다.", 404

        if current_user.id == receiver.id:
            return "자기 자신에게 송금할 수 없습니다.", 400

        # 잔액 확인 (사용자 잔액을 가진 필드가 있다고 가정)
        if current_user.balance < amount:
            return "잔액이 부족합니다.", 400

        # 거래 기록 생성
        transaction = Transaction(sender_id=current_user.id, receiver_id=receiver.id, amount=amount)
        db.session.add(transaction)

        # 사용자 잔액 업데이트
        current_user.balance -= amount
        receiver.balance += amount

        db.session.commit()

        return redirect(url_for('profile'))  # 송금 후 프로필로 리디렉션

    return render_template('send_money.html')  # GET 요청 시 송금 폼 페이지 렌더링

@app.route('/transaction_history')
@login_required
def transaction_history():
    transactions = Transaction.query.filter((Transaction.sender_id == current_user.id) | (Transaction.receiver_id == current_user.id)).all()
    return render_template('transaction_history.html', transactions=transactions)




@app.route('/submit_report', methods=['POST'])
@login_required
def submit_report():
    report_type = request.form['type']
    target_id = request.form['id']
    reason = request.form['reason']
    
    # 신고 사유도 함께 저장
    report = Report(report_type=report_type, target_id=target_id, reason=reason)
    db.session.add(report)
    db.session.commit()
    
    # 신고한 상품의 상세 페이지로 리디렉션
    return redirect(url_for('product_detail', id=target_id))


@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html')
@app.route('/chat/<int:user_id>')
@login_required
def private_chat(user_id):
    other_user = User.query.get_or_404(user_id)

    # 메시지 조회 (양방향 모두 포함)
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
        ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
    ).all()

    return render_template('private_chat.html', current_user=current_user, other_user=other_user, messages=messages)

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = float(request.form['price'])

        # 상품 등록
        product = Product(title=title, description=description, price=price, user_id=current_user.id)
        db.session.add(product)
        db.session.commit()

        return redirect(url_for('products'))  # 상품 목록 페이지로 리디렉션

    return render_template('add_product.html')

@app.route('/buy_product/<int:product_id>', methods=['POST'])
@login_required
def buy_product(product_id):
    # 상품 찾기
    product = Product.query.get_or_404(product_id)

    # 사용자의 잔액과 상품 가격 비교
    if current_user.balance >= product.price:
        # 잔액 차감
        current_user.balance -= product.price
        db.session.commit()

        # 상품 삭제
        db.session.delete(product)
        db.session.commit()

        # 구매 완료 메시지
        flash("상품을 구매하셨습니다.", "success")
    else:
        flash("잔액이 부족합니다.", "danger")

    return redirect(url_for('products'))
@app.route('/manage_users')
@login_required
def manage_users():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    
    users = User.query.all()  # 모든 유저 조회
    return render_template('manage_users.html', users=users)

@app.route('/toggle_user_status/<int:user_id>')
@login_required
def toggle_user_status(user_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    
    user = User.query.get(user_id)
    if user:
        user.is_dormant = not user.is_dormant  # 유저 휴면 상태 변경
        db.session.commit()
    
    return redirect(url_for('manage_users'))

@app.route('/manage_all_products')
@login_required
def manage_all_products():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    
    products = Product.query.all()  # 모든 상품 조회
    return render_template('manage_all_products.html', products=products)

@app.route('/toggle_product_status/<int:product_id>')
@login_required
def toggle_product_status(product_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    
    product = Product.query.get(product_id)
    if product:
        product.reported = not product.reported  # 상품 차단/차단 해제
        db.session.commit()
    
    return redirect(url_for('manage_all_products'))

# Chat
# app.py의 아래쪽에 SocketIO 이벤트 추가
@socketio.on('join_private')
def handle_join_private(data):
    user1 = data['user1']
    user2 = data['user2']
    room = get_private_room_name(user1, user2)
    join_room(room)

@socketio.on('private_message')
def handle_private_message(data):
    sender = data['sender']
    receiver = data['receiver']
    sender_username = data.get('sender_username', 'Unknown')
    content = data['content']
    room = get_private_room_name(sender, receiver)

    # XSS 방지를 위해 메시지 내용 HTML escape 처리
    safe_content = escape(content)

    # 메시지 DB에 저장
    message = Message(sender_id=sender, receiver_id=receiver, content=safe_content)
    db.session.add(message)
    db.session.commit()

    # 발신자에게는 메시지를 전송하지 않음
    if sender != receiver:
        emit('private_message', {
            'id': message.id,
            'sender': sender,
            'receiver': receiver,
            'sender_username': sender_username,
            'content': safe_content
        }, to=room)


# app.py에서 실시간 채팅을 위한 연결
@socketio.on('join')
def handle_join(data):
    room = data['room']
    join_room(room)  # 채팅방에 참여
    print(f'User has entered the room: {room}')

@socketio.on('message')
def handle_message(data):
    room = data['room']
    user = data['user']
    text = data['text']

    # 해당 방에 메시지를 전파
    emit('message', {'user': user, 'text': text}, room=room)



# 공통 룸 이름 생성 함수
def get_private_room_name(user1, user2):
    return f"room_{min(user1, user2)}_{max(user1, user2)}"



if __name__ == '__main__':
    # 애플리케이션 컨텍스트 내에서 실행
    with app.app_context():
        db.create_all()  # 데이터베이스 테이블 생성
        
        # 관리자 계정 생성
        admin_user = User(username='admin', password='123123', is_admin=True)
        
        # 관리자가 이미 존재하는지 확인하고 추가 (중복 생성 방지)
        existing_admin = User.query.filter_by(username='admin').first()
        if not existing_admin:
            db.session.add(admin_user)
            db.session.commit()  # 변경사항을 커밋하여 DB에 저장

    socketio.run(app, debug=True, host='0.0.0.0', port=5000)


             
