import flask
import flask_login

from flaskext.markdown import Markdown
from markdown.extensions.wikilinks import WikiLinkExtension
from markdown.extensions.codehilite import CodeHiliteExtension

from urllib.parse import urlparse, urljoin

from peewee import *

import hashlib
from hmac import compare_digest

db = SqliteDatabase('db.sqlite3')
current_timestamp = [SQL('DEFAULT CURRENT_TIMESTAMP')]		

def hash_password(password: str) -> str:
	return hashlib.sha512(password.encode()).hexdigest()

# begin models

class User(Model):
	# associate with a database
	class Meta:
		database = db

	# model fields
	username = CharField(unique=True)
	password_hash = CharField()
	can_login = BooleanField(default=False)

	def __init__(self, *args, **kwargs):
		super().__init__(self, **kwargs)
		# additional non-model property:
		# Flask-Login requires this property to mark
		# authenticated status
		self.is_authenticated = False

	# flask-login required properties for User class

	'''(defined above: .is_authenticated is a required field)'''

	@property
	def is_active(self) -> bool:
		# user has activated, is not suspended, etc.
		return self.can_login

	@property
	def is_anonymous(self) -> bool:
		# i.e. guest or unauthenticated individual
		return False

	# method, not a property
	def get_id(self) -> str:
		# returns a `unique` identifier for the user
		return self.username

class Article(Model):
	title = CharField()
	# to avoid circular dependency problem: classes evaluated in-order
	current_revision = DeferredForeignKey('ArticleRevision', null=True)
	created = DateTimeField(constraints=current_timestamp)
	class Meta:
		database = db

class ArticleRevision(Model):
	author = ForeignKeyField(User, backref='contributed_revisions')
	article = ForeignKeyField(Article, backref='revisions')
	content = TextField()
	created = DateTimeField(constraints=current_timestamp)
	class Meta:
		database = db

# end models

# Checks if a redirect URL is within the same domain
# to avoid malicious redirect tampering
def is_safe_url(target):
	ref_url = urlparse(flask.request.host_url)
	test_url = urlparse(urljoin(flask.request.host_url, target))
	is_http_or_https = test_url.scheme in ('http', 'https')
	return is_http_or_https and ref_url.netloc == test_url.netloc

# initialize the flask app
app = flask.Flask(__name__)
app.secret_key = 'super secret string'

# register the Markdown plugin
# so we can render markdown used in the Wiki articles
Markdown(app, extensions=[
	'fenced_code', 
	WikiLinkExtension(base_url='/w/', end_url=''), 
	CodeHiliteExtension(guess_lang=False, css_class='highlight')
])

# register Flask-Login to manage authentication
login_manager = flask_login.LoginManager()
login_manager.init_app(app)

# we can change this one (arbitrarily named)
# property to change the name of the site in the templates
app.config['wiki_name'] = 'PHWiki'

@app.before_first_request
def _setup():
	# setup the DB
	with db:
		db.create_tables([User, Article, ArticleRevision])

	should_make_home = False
	with db:
		# Create the `site` user if it doesn't exist
		try:
			user = User.get(User.username == 'site')
		except User.DoesNotExist:
			user = User(username='site', password_hash='', can_login=False)
			user.save()

		# Create the `home` article if it doesn't exist
		if not Article.select().where(Article.title == 'Home').exists():
			# Model.create saves the model immediately, so we create an article
			# with no revisions and then add one later.
			home_article = Article.create(title='Home')

			revision = ArticleRevision.create(
				article=home_article, 
				content='New home page. Log in and click Edit to populate it!',
				author=user
			)

			home_article.current_revision = revision
			home_article.save()



'''
Flask-Login: return a Flask-Login-compatible User model
given a username, or None if it does not exist.
'''
@login_manager.user_loader
def load_user(username: str) -> User:
	with db:
		try:
			return User.get(User.username == username)
		except User.DoesNotExist:
			return None

'''
Flask-Login: return a Flask-Login-compatible User model
given a request object (form data), and additionally
mark the user as authenticated (`is_authenticated: bool`)
if authentication succeeds. 

we don't need this, we're not doing Token auth.
'''
@login_manager.request_loader
def request_loader(request):
	return None

@login_manager.unauthorized_handler
def unauthorized_handler():
	flask.flash('You need to be logged in.')
	return flask.redirect(flask.url_for('login', redirect=flask.request.full_path))

@app.route('/')
def home():
	return flask.redirect(flask.url_for('article', name='Home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
	# reusable failure condition
	def login_fail():
		flask.flash('Please try a different username or password.')
		return flask.redirect(flask.request.full_path)

	# show the login page unless a login form was submitted.
	if flask.request.method == 'GET':
		return flask.render_template('login.html')

	given_username = flask.request.form.get('username')
	given_password = flask.request.form.get('password')

	# check that the user exists
	with db:
		try:
			user = User.get(User.username == given_username)
		except User.DoesNotExist:
			return login_fail()

	# check that the user is flagged as being able to login
	# (not an artificial user like `site`)
	if not user.can_login:
		return login_fail()

	# check the password
	given_password_hash = hash_password(given_password)
	print(given_password_hash)
	# constant time comparison
	if not compare_digest(user.password_hash, given_password_hash):
		return login_fail()

	# Remember Me is a checkbox in the form.
	# Checkboxes are part of options sets:
	# the list is named "remember_me", and the checkbox is named "yes".
	# So to see if its checked, we have to determine set membership.
	should_remember_me = 'yes' in flask.request.form.getlist('remember_me')

	flask.flash('You are now logged in 👌')

	print(f'Logging in {user} (remember me = {should_remember_me})')

	# manually set `is_authenticated` property on *this instance* of User
	# (unrelated to DB model) - this tells Flask-Login it's all good
	user.is_authenticated = True
	flask_login.login_user(user, remember=should_remember_me)

	redirect_url = flask.request.args.get('redirect')

	if not is_safe_url(redirect_url):
		return flask.abort(400)

	return flask.redirect(redirect_url)

@app.route('/logout')
def logout():
	print(f'Logging out user { flask_login.current_user.get_id() }')
	flask_login.logout_user()
	flask.flash('Logged out.')
	return flask.redirect(flask.url_for('article', name='Home'))

@app.route('/w/<name>')
def article(name: str):
	with db:
		try:
			article = Article.get(Article.title == name)
		except Article.DoesNotExist:
			flask.abort(404)
	
	return flask.render_template('article.html', article=article)

@app.route('/edit/<name>', methods=['GET', 'POST'])
@flask_login.login_required
def edit(name: str):
	article = Article.get_name(name)
	if article is None:
		flask.abort(404)
	if flask.request.method == 'GET':
		return flask.render_template('edit.html', article=article)
	article.change_content(flask.request.form['content']) 
	flask.flash(f'Commited edit to "{name}"')
	return flask.redirect(flask.url_for('edit', name=name))

@app.errorhandler(404)
def page_not_found(error):
	return flask.render_template('page_not_found.html'), 404
