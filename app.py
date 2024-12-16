from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, SubmitField, SelectField, FloatField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer
import pyotp
from sqlalchemy import update

import logging
from authlib.integrations.flask_client import OAuth
from authlib.common.security import generate_token
from apscheduler.schedulers.background import BackgroundScheduler
import pytz
import hashlib
import requests
import asyncio
from bot import TradingBot
import ccxt
import threading
import random, string

app = Flask(__name__)
app.config['SECRET_KEY'] = 'KaranYadav'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'nextlevelstrades@gmail.com'
app.config['MAIL_PASSWORD'] = 'iasm waqt qlut jjek'
app.config['MAIL_DEFAULT_SENDER'] = 'nextlevelstrades@gmail.com'
active_bots = {}
mail = Mail(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bot_status={}
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='606914266477-kogstbs60m7cnvplpa48hvr88tttm2m9.apps.googleusercontent.com',
    client_secret='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',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    userinfo_endpoint='https://www.googleapis.com/oauth2/v3/userinfo',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
    client_kwargs={'scope': 'openid profile email'},
)
app.config['TEMPLATES_AUTO_RELOAD'] = True

PAYU_KEY = "BfHohf"
PAYU_SALT = "YdxXtt8DiMRExSSRTE5itKa1Auu3FpfR"
PAYU_URL = "https://test.payu.in/_payment"  # Use https://secure.payu.in/_payment 

NOWPAYMENTS_API_KEY = "4AYSPQK-7VR4MSB-P87FM1X-H43V2CQ"  # Your merchant API key
NOWPAYMENTS_API_URL = "https://api.nowpayments.io/v1/invoice"


logging.basicConfig(level=logging.DEBUG)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['SESSION_PERMANENT'] = True


@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user:
        if user.subscription_end and user.subscription_end <= datetime.utcnow():
            user.subscription_active = False
            db.session.commit()
    return user


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False, default=pyotp.random_base32())
    subscription_plan = db.Column(db.String(20), nullable=True)
    subscription_start = db.Column(db.DateTime, nullable=True)
    subscription_end = db.Column(db.DateTime, nullable=True)
    subscription_active = db.Column(db.Boolean, default=False)
    referral_code = db.Column(db.String(10), unique=True, nullable=True)  # Referral code
    referred_by = db.Column(db.String(10), nullable=True)  # Referrer code
    points = db.Column(db.Integer, default=0)  # Points earned


    def check_password(self, password):
        return check_password_hash(self.password, password)

    def get_reset_token(self, expires_sec=1800):
        s = URLSafeTimedSerializer(
            app.config['SECRET_KEY'],
            salt=b'email-reset-salt'
        )
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'], salt=b'email-reset-salt')
        try:
            user_id = s.loads(token, max_age=1800)['user_id']
        except Exception as e:
            return None
        return User.query.get(user_id)

@app.route('/refer')
@login_required
def refer():
    if not current_user.referral_code:
        current_user.referral_code = generate_referral_code()  # Use the unique referral code generator
        db.session.commit()
    redemption_costs = {
        "1_month": 30,
        "3_months": 80,
        "6_months": 150,
        "1_year": 250,
    }
    return render_template(
        'refer.html',
        referral_code=current_user.referral_code,
        points=current_user.points,
        redemption_costs=redemption_costs
    )

@app.route('/redeem', methods=['POST'])
@login_required
def redeem():
    subscription = request.form.get('subscription')
    redemption_costs = {
        "1_month": 30,
        "3_months": 80,
        "6_months": 150,
        "1_year": 250,
    }

    # Ensure the selected subscription is valid and the user has enough points
    if subscription in redemption_costs:
        cost = redemption_costs[subscription]
        if current_user.points >= cost:
            # Deduct points and update subscription
            current_user.points -= cost
            plans = get_plans()
            current_user.subscription_plan = subscription.replace('_', ' ')
            current_user.subscription_start = datetime.utcnow()
            current_user.subscription_end = datetime.utcnow() + plans[subscription]["duration"]
            current_user.subscription_active = True

            db.session.commit()
            flash(f"You have successfully redeemed points for a {subscription.replace('_', ' ').title()} subscription!", "success")
        else:
            flash("You do not have enough points to redeem this subscription.", "danger")
    else:
        flash("Invalid subscription selected for redemption.", "danger")

    return redirect(url_for('refer'))


def generate_referral_code():
    """Generate a unique referral code."""
    while True:
        # Generate a random 8-character alphanumeric code
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        # Ensure it is unique
        if not User.query.filter_by(referral_code=code).first():
            return code
class TradingBotConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    api_key = db.Column(db.String(120), nullable=False)
    secret = db.Column(db.String(120), nullable=False)
    asset_name = db.Column(db.String(20), nullable=False)
    trade_size_usdt = db.Column(db.Float, nullable=False)
    indicator = db.Column(db.String(20), nullable=False)
    timeframe = db.Column(db.String(20), nullable=False)
    exchange = db.Column(db.String(20), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is already registered. Please log in or use a different email.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class OTPForm(FlaskForm):
    otp = StringField('OTP', validators=[DataRequired(), Length(6)])
    submit = SubmitField('Verify OTP')



class DashboardForm(FlaskForm):
    api_key = StringField('API Key', 
                          validators=[DataRequired()], 
                          render_kw={"placeholder": "APIKEY"})
    
    secret = StringField('Secret', 
                         validators=[DataRequired()], 
                         render_kw={"placeholder": "SECRETKEY"})
    
    asset_name = StringField('Asset Name', 
                             validators=[DataRequired()], 
                             render_kw={"placeholder": "BTC/USDT(In capital letters)"})
    
    trade_size_usdt = FloatField('Trade Size (USDT)', 
                                 validators=[DataRequired()], 
                                 render_kw={"placeholder": "100"})
    
    
    indicator = SelectField('Indicator', 
                            choices=[
                                ('ma', 'Moving Average'), 
                                ('stochastic', 'Stochastic'), 
                                ('macd', 'MACD'),
                                ('atr', 'ATR (Average True Range)'),
                                ('vwap', 'VWAP (Volume Weighted Average Price)'),
                                ('fibonacci', 'Fibonacci Retracement'),
                                ('rsi', 'RSI (Relative Strength Index)'),
                                ('bollinger', 'Bollinger Bands')
                            ], 
                            validators=[DataRequired()])
    timeframe = SelectField('timeframe',
                            choices=[
                                ('1m' , '1m'),
                                ('5m', '5m'),
                                ('15m', '15m'),
                                ('1h', '1h'),
                                ('6h' , '6h'),
                                ('12h' , '12h'),
                                ('1d' , '1d'),
                                ('7d', '7d')
                            ],
                            validators=[DataRequired()])
    exchange = SelectField('Exchange', 
                           choices=[
                               ('binance', 'Binance'), 
                               ('bingx', 'BingX'), 
                               ('bitget', 'Bitget'), 
                               ('bybit', 'Bybit'), 
                               ('kucoin', 'KuCoin'), 
                               ('mexc', 'MEXC'), 
                               ('okx', 'OKX')
                            ], 
                            validators=[DataRequired()])
    
    submit = SubmitField('Save Configuration')

def send_otp_email(user):
    totp = pyotp.TOTP(user.otp_secret)
    otp = totp.now()
    logging.debug(f"Generated OTP: {otp}")
    
    msg = Message('Your OTP Code', recipients=[user.email])
    msg.body = f'Your OTP code is {otp}. It is valid for the next 10 minutes.'
    
    try:
        mail.send(msg)
        session['otp_timestamp'] = datetime.utcnow()
        logging.debug("OTP email sent successfully.")
    except Exception as e:
        logging.error(f"Error sending OTP email: {e}")


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', 
                  sender=app.config['MAIL_DEFAULT_SENDER'], 
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    try:
        mail.send(msg)
        logging.debug("Password reset email sent successfully.")
    except Exception as e:
        logging.error(f"Error sending password reset email: {e}")

def get_plans():
    return {
        "1_month": {"amount": "15.49", "duration": timedelta(days=30)},
        "3_months": {"amount": "24.99", "duration": timedelta(days=90)},
        "6_months": {"amount": "44.99", "duration": timedelta(days=180)},
        "1_year": {"amount": "84.99", "duration": timedelta(days=365)},
    }

def generate_payu_hash(data):
    hash_string = f"{data['key']}|{data['txnid']}|{data['amount']}|{data['productinfo']}|{data['firstname']}|{data['email']}|||||||||||{PAYU_SALT}"
    return hashlib.sha512(hash_string.encode('utf-8')).hexdigest()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=16)

        session['temp_user'] = {
            'username': form.username.data,
            'email': form.email.data,
            'password': hashed_password,
            'otp_secret': pyotp.random_base32()
        }

        temp_user = session['temp_user']
        user = User(username=temp_user['username'], email=temp_user['email'], 
                    password=temp_user['password'], otp_secret=temp_user['otp_secret'])
        send_otp_email(user)

        flash('An OTP has been sent to your email. Please enter it to complete the registration.', 'info')
        return redirect(url_for('verify_otp'))
    return render_template('register.html', form=form)

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    temp_user = session.get('temp_user')
    if not temp_user:
        flash('Session expired or no registration data found. Please register again.', 'danger')
        return redirect(url_for('register'))

    form = OTPForm()
    if form.validate_on_submit():
        otp_timestamp = session.get('otp_timestamp')
        if otp_timestamp and otp_timestamp.tzinfo is not None:
            otp_timestamp = otp_timestamp.replace(tzinfo=None)
        
        if otp_timestamp and datetime.utcnow() > otp_timestamp + timedelta(minutes=10):
            flash('Your OTP has expired. Please request a new one.', 'danger')
            return redirect(url_for('verify_otp'))

        totp = pyotp.TOTP(temp_user['otp_secret'])

        if totp.verify(form.otp.data, valid_window=20):  
            user = User(username=temp_user['username'], email=temp_user['email'],
                        password=temp_user['password'], otp_secret=temp_user['otp_secret'])
            db.session.add(user)
            db.session.commit()
            session.pop('temp_user', None)
            session.pop('otp_timestamp', None)
            
            login_user(user)
            flash('Your account has been created and verified successfully.', 'success')
            return redirect(url_for('pricing'))
        else:
            flash('Invalid or expired OTP.', 'danger')
            return redirect(url_for('verify_otp'))
    
    return render_template('verify_otp.html', form=form)

@app.route('/resend_otp', methods=['GET', 'POST'])
def resend_otp():
    temp_user = session.get('temp_user')
    if not temp_user:
        flash('Session expired or no registration data found. Please register again.', 'danger')
        return redirect(url_for('register'))
    
    user = User(username=temp_user['username'], email=temp_user['email'], 
                password=temp_user['password'], otp_secret=temp_user['otp_secret'])
    send_otp_email(user)
    flash('A new OTP has been sent to your email.', 'info')
    return redirect(url_for('verify_otp'))

# Route to display pricing plans
@app.route('/pricing')
@login_required
def pricing():
    return render_template('pricing.html')


# Route to create NowPayments invoice
@app.route('/nowpayments_payment/<plan>', methods=['POST'])
@login_required
def nowpayments_payment(plan):
    referral_code = request.form.get('referral_code', '').strip()
    logging.info(f"Referral Code Received in POST: {referral_code}")
    
    plans = get_plans()
    if plan not in plans:
        flash("Invalid plan selected.", "danger")
        return redirect(url_for('pricing'))

    # Create invoice data
    nowpayments_data = {
        "price_amount": plans[plan]["amount"],
        "price_currency": "USD",
        "order_id": f"txn_{datetime.utcnow().timestamp()}_{current_user.id}",
        "success_url": url_for('nowpayments_success', plan=plan, referral_code=referral_code, _external=True),
        "cancel_url": url_for('nowpayments_failure', _external=True),
    }

    headers = {"x-api-key": NOWPAYMENTS_API_KEY, "Content-Type": "application/json"}
    try:
        response = requests.post(NOWPAYMENTS_API_URL, json=nowpayments_data, headers=headers)
        response_data = response.json()

        if response.status_code == 200 and response_data.get("invoice_url"):
            return redirect(response_data["invoice_url"])
        else:
            flash("Error creating payment invoice. Please try again.", "danger")
            logging.error(f"NowPayments error: {response_data}")
    except Exception as e:
        logging.error(f"NowPayments Exception: {str(e)}")
        flash("Payment service is currently unavailable.", "danger")

    return redirect(url_for('pricing'))





@app.route('/nowpayments_success/<plan>')
@login_required
def nowpayments_success(plan):
    referral_code = request.args.get('referral_code', '').strip()
    logging.info(f"Referral code received: {referral_code}")

    referrer = None
    if referral_code:
        if referral_code == current_user.referral_code:
            logging.warning("Self-referral detected. Points not awarded.")
        else:
            referrer = User.query.filter_by(referral_code=referral_code).first()
            if not referrer:
                logging.warning(f"No user found with referral code: {referral_code}")
            else:
                logging.info(f"Referrer found: {referrer.username}, current points: {referrer.points}")

    plans = get_plans()
    if plan not in plans:
        flash("Invalid plan selected.", "danger")
        return redirect(url_for('pricing'))

    try:
        # Update current user's subscription
        current_user.subscription_plan = plan.replace('_', ' ')
        current_user.subscription_start = datetime.utcnow()
        current_user.subscription_end = datetime.utcnow() + plans[plan]["duration"]
        current_user.subscription_active = True

        # Increment referrer's points using explicit update
        if referrer:
            logging.info(f"Incrementing points for referrer {referrer.username}")
            db.session.execute(
                update(User)
                .where(User.id == referrer.id)
                .values(points=(referrer.points or 0) + 10)
            )
            logging.info("Referrer points incremented successfully.")

        # Commit changes
        db.session.commit()
        logging.info("Database commit successful.")

        # Reload and log referrer points to verify update
        if referrer:
            db.session.refresh(referrer)
            logging.info(f"Referrer {referrer.username} updated points: {referrer.points}")

        flash(f'You have successfully subscribed to the {plan.replace("_", " ").title()} plan!', 'success')
        if referrer:
            flash(f'Referrer {referrer.username} has been credited with 10 points.', 'info')

    except Exception as e:
        db.session.rollback()
        logging.error(f"Error while updating points: {e}")
        flash("An error occurred while updating your subscription. Please try again.", "danger")

    return redirect(url_for('home'))



# Failure route after payment failure
@app.route('/nowpayments_failure')
@login_required
def nowpayments_failure():
    flash('Payment failed or cancelled. Please try again.', 'danger')
    return redirect(url_for('pricing'))


# Background job to check expired subscriptions
def check_expired_subscriptions():
    with app.app_context():
        now = datetime.utcnow()
        expired_users = User.query.filter(User.subscription_active == True, User.subscription_end <= now).all()
        for user in expired_users:
            user.subscription_active = False
            db.session.commit()
            logging.debug(f"Subscription expired for user {user.username}")

scheduler = BackgroundScheduler(timezone=pytz.utc)
scheduler.add_job(check_expired_subscriptions, 'interval', days=1)
scheduler.start()

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Invalid email or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/login/google')
def google_login():
    nonce = generate_token()
    session['nonce'] = nonce
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri, nonce=nonce)


@app.route('/callback')
def google_callback():
    try:
        token = google.authorize_access_token()
        nonce = session.pop('nonce', None)
        user_info = google.parse_id_token(token, nonce=nonce)
        
        username = user_info.get('name', user_info.get('email', 'Unknown'))
        email = user_info.get('email')
        
        user = User.query.filter_by(email=email).first()
        
        if user is None:
            user = User(username=username, email=email, password='')
            db.session.add(user)
            db.session.commit()
        
        login_user(user)
        
        return redirect(url_for('home'))
    
    except Exception as e:
        logging.error(f"Error during Google login: {e}")
        flash(f'Error during Google login: {str(e)}', 'danger')
        return redirect(url_for('login'))


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=16)
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form, token=token)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = DashboardForm()

    if form.validate_on_submit():
        try:
            config = TradingBotConfig.query.filter_by(user_id=current_user.id).first()
            if not config:
                config = TradingBotConfig(user_id=current_user.id)

            config.api_key = form.api_key.data
            config.secret = form.secret.data
            config.asset_name = form.asset_name.data
            config.trade_size_usdt = form.trade_size_usdt.data
            config.indicator = form.indicator.data
            config.timeframe = form.timeframe.data
            config.exchange = form.exchange.data
 
            db.session.add(config)
            db.session.commit()

            flash('Configuration saved successfully!', 'success')

        except Exception as e:
            flash(f'An error occurred while saving configuration: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

    config = TradingBotConfig.query.filter_by(user_id=current_user.id).first()

    user_bot_status = 'running' if current_user.id in active_bots else 'stopped'

    return render_template(
        'dashboard.html',
        config=config,
        form=form,
        user_bot_status=user_bot_status
    )

@app.route('/start_bot', methods=['POST'])
@login_required
def start_bot():
    try:
        config = TradingBotConfig.query.filter_by(user_id=current_user.id).first()
        if not config:
            flash('Please configure your bot settings first.', 'danger')
            return redirect(url_for('dashboard'))

        if config.trade_size_usdt < 30:
            flash('Trade size must be at least 30 USDT.', 'danger')
            return redirect(url_for('dashboard'))

        assets = config.asset_name
        if isinstance(assets, str):
            assets = [asset.strip() for asset in assets.split(',')]


        bot = TradingBot(
            api_key=config.api_key,
            secret=config.secret,
            assets=assets,
            trade_size_usdt=config.trade_size_usdt,
            indicator=config.indicator,
            timeframe= config.timeframe,
            exchange=config.exchange
        )
        active_bots[current_user.id] = bot

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_in_executor(None, asyncio.run, bot.start_trading())
        flash('Trading bot started successfully!', 'success')

    except ccxt.NetworkError as e:
        logging.error(f"Network error: {str(e)}")
        flash('Network error. Check your internet connection.', 'danger')

    except ccxt.ExchangeError as e:
        if "Invalid symbol" in str(e):
            logging.error(f"Invalid asset name provided: {str(e)}")
            flash("Invalid asset name provided. Please check your asset configuration.", 'danger')
        elif "Incorrect apiKey" in str(e):
            logging.error(f"Incorrect API key provided: {str(e)}")
            flash("Incorrect API key provided. Please check your API key and try again.", 'danger')
        else:
            logging.error(f"Exchange error: {str(e)}")
            flash(f'Exchange error: {str(e)}', 'danger')

    except ValueError as e:
        logging.error(f"Validation error: {str(e)}")
        flash(f'Error: {str(e)}', 'danger')

    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        flash(f'An unexpected error occurred: {str(e)}', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/stop_bot', methods=['POST'])
@login_required
def stop_bot():
    try:
        bot = active_bots.get(current_user.id)
        if not bot:
            flash('No bot is currently running.', 'danger')
            return redirect(url_for('dashboard'))

        bot.stop()  
        del active_bots[current_user.id]

        flash('Trading bot stopped successfully!', 'success')

    except Exception as e:
        error_message = f"An error occurred while stopping the bot: {str(e)}"
        logging.error(error_message)
        flash(f'An error occurred while stopping the bot: {str(e)}', 'danger')

    return redirect(url_for('dashboard'))

@app.route('/edit_config', methods=['GET', 'POST'])
@login_required
def edit_config():
    config = TradingBotConfig.query.filter_by(user_id=current_user.id).first()
    if not config:
        flash('Please configure your bot settings first.', 'danger')
        return redirect(url_for('dashboard'))

    form = DashboardForm(obj=config)

    if form.validate_on_submit():
        config.api_key = form.api_key.data
        config.secret = form.secret.data
        config.asset_name = form.asset_name.data
        config.trade_size_usdt = form.trade_size_usdt.data
        config.indicator = form.indicator.data
        config.timeframe = form.timeframe.data
        config.exchange = form.exchange.data
        db.session.commit()
        flash('Configuration updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_config.html', form=form)
@app.route('/policy')
def policy():
    return render_template('policy.html')

@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
