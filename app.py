from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import bcrypt
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Replace with a secure key in production

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chatbot.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# ----- Database Models -----

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    # For demo purposes only: storing both hashed and plaintext password
    password_hash = db.Column(db.String(255), nullable=False)
    plain_password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    conversations = db.relationship('Conversation', backref='user', lazy=True)


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    # Store the entire conversation as a plain text log
    conversation_data = db.Column(db.Text, nullable=True)


class FAQ(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.Text, nullable=False)
    answer = db.Column(db.Text, nullable=False)


# ----- Helper: Create a default admin if not exists -----
def create_admin():
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        plain = "adminpass"  # For demo only
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(plain.encode('utf-8'), salt).decode('utf-8')
        admin = User(username="admin", password_hash=hashed, plain_password=plain, is_admin=True)
        db.session.add(admin)
        db.session.commit()


# ----- Routes -----

@app.route('/')
def home():
    if 'user_id' in session:
        if session.get('is_admin'):
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('chat'))
    return render_template('index.html', title="Login")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        if session.get('is_admin'):
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('chat'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            flash("Login successful!", "success")
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('chat'))
        else:
            flash("Invalid username or password", "error")
    return render_template('index.html', title="Login")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        if session.get('is_admin'):
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('chat'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash("Username already exists", "error")
        else:
            salt = bcrypt.gensalt()
            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
            new_user = User(username=username, password_hash=hashed_pw, plain_password=password)
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for('login'))
    return render_template('register.html', title="Register")


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('is_admin', None)
    session.pop('conversation_id', None)
    flash("Logged out successfully", "success")
    return redirect(url_for('login'))


@app.route('/chat')
def chat():
    if 'user_id' not in session or session.get('is_admin'):
        return redirect(url_for('login'))
    # Create a new conversation each time the chat page is loaded/refreshed
    new_conversation = Conversation(user_id=session['user_id'], conversation_data="")
    db.session.add(new_conversation)
    db.session.commit()
    session['conversation_id'] = new_conversation.id
    return render_template('chat.html', title="Chat", username=session['username'])


def generate_response(message):
    # Check FAQs for an exact match (case-insensitive)
    message_clean = message.strip().lower()
    faqs = FAQ.query.all()
    for faq in faqs:
        if faq.question.strip().lower() == message_clean:
            return faq.answer

    # Fallback responses if no FAQ match is found
    message_lower = message.lower()
    if "hello" in message_lower:
        return "Hello there! How can I help you today?"
    elif "how are you" in message_lower:
        return "I'm just a bot, but I'm doing great! Thanks for asking."
    elif "bye" in message_lower:
        return "Goodbye! Have a great day!"
    else:
        return f"I received your message: '{message}'. Tell me more!"


@app.route('/chat_api', methods=['POST'])
def chat_api():
    if 'user_id' not in session or session.get('is_admin'):
        return jsonify({'reply': "Please log in to chat."})
    data = request.get_json()
    message = data.get('message', '')

    conversation = Conversation.query.get(session.get('conversation_id'))
    conversation_text = conversation.conversation_data or ""

    # Append user's message on a new line
    if conversation_text:
        conversation_text += "\n" + message
    else:
        conversation_text = message

    reply = generate_response(message)
    # Append bot's reply with "bot:" prefix on a new line
    conversation_text += "\n" + "bot: " + reply

    conversation.conversation_data = conversation_text
    db.session.commit()

    return jsonify({'reply': reply})


# ----- Admin Dashboard -----

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or not session.get('is_admin'):
        flash("Access denied", "error")
        return redirect(url_for('login'))
    users = User.query.all()
    return render_template('admin.html', title="Admin Dashboard", users=users)


# ----- FAQ Management (Admin Only) -----

@app.route('/admin/faq', methods=['GET', 'POST'])
def admin_faq():
    if 'user_id' not in session or not session.get('is_admin'):
        flash("Access denied", "error")
        return redirect(url_for('login'))
    if request.method == 'POST':
        question = request.form.get('question')
        answer = request.form.get('answer')
        if question and answer:
            faq = FAQ(question=question, answer=answer)
            db.session.add(faq)
            db.session.commit()
            flash("FAQ added successfully!", "success")
        else:
            flash("Please provide both question and answer", "error")
    faqs = FAQ.query.all()
    return render_template('faq.html', title="Manage FAQs", faqs=faqs)


@app.route('/admin/faq/edit/<int:faq_id>', methods=['GET', 'POST'])
def edit_faq(faq_id):
    if 'user_id' not in session or not session.get('is_admin'):
        flash("Access denied", "error")
        return redirect(url_for('login'))
    faq = FAQ.query.get_or_404(faq_id)
    if request.method == 'POST':
        question = request.form.get('question')
        answer = request.form.get('answer')
        if question and answer:
            faq.question = question
            faq.answer = answer
            db.session.commit()
            flash("FAQ updated successfully!", "success")
            return redirect(url_for('admin_faq'))
        else:
            flash("Please provide both question and answer", "error")
    return render_template('edit_faq.html', title="Edit FAQ", faq=faq)


@app.route('/admin/faq/delete/<int:faq_id>', methods=['POST'])
def delete_faq(faq_id):
    if 'user_id' not in session or not session.get('is_admin'):
        flash("Access denied", "error")
        return redirect(url_for('login'))
    faq = FAQ.query.get_or_404(faq_id)
    db.session.delete(faq)
    db.session.commit()
    flash("FAQ deleted successfully!", "success")
    return redirect(url_for('admin_faq'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin()  # Create default admin if needed
    app.run(debug=True)
