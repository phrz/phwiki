import flask
import flask_login

from flaskext.markdown import Markdown
from markdown.extensions.wikilinks import WikiLinkExtension
from markdown.extensions.codehilite import CodeHiliteExtension

from urllib.parse import urlparse, urljoin

from peewee import *



class User(flask_login.UserMixin):
	pass

class Article:
	def __init__(self, name: str, content: str):
		self.name = name
		self.content = content
	def get_name(name: str):
		with sqlite3_connection('articles.db') as db:
			db.execute('SELECT * FROM articles WHERE name=?', (name,))
			entry = db.fetchone()
		if entry is None:
			return None
		print(entry)
		article_name = entry[0]
		article_content = entry[1]
		return Article(article_name, article_content)

	def change_content(self, content: str):
		with sqlite3_connection('articles.db') as db:
			db.execute('UPDATE articles SET content=? WHERE name=?', (content, self.name))

def is_safe_url(target):
	ref_url = urlparse(flask.request.host_url)
	test_url = urlparse(urljoin(flask.request.host_url, target))
	is_http_or_https = test_url.scheme in ('http', 'https')
	return is_http_or_https and ref_url.netloc == test_url.netloc

app = flask.Flask(__name__)
app.secret_key = 'super secret string'

Markdown(app, extensions=[
	'fenced_code', 
	WikiLinkExtension(base_url='/w/', end_url=''), 
	CodeHiliteExtension(guess_lang=False, css_class='highlight')
])

login_manager = flask_login.LoginManager()
login_manager.init_app(app)

app.config['wiki_name'] = 'PHWiki'

# FAKE USERS DB
users = {'phrz': {'password': 'password'}}

@login_manager.user_loader
def load_user(username: str) -> User:
	if username not in users:
		return None
	user = User()
	user.id = username
	return user

@login_manager.request_loader
def request_loader(request):
	username = request.form.get('username')
	if username not in users:
		return None

	user = User()
	user.id = username

	# DO NOT ever store passwords in plaintext and always compare password
	# hashes using constant-time comparison!
	user.is_authenticated = request.form['password'] == users[username]['password']

	return user

@login_manager.unauthorized_handler
def unauthorized_handler():
	flask.flash('You need to be logged in.')
	return flask.redirect(flask.url_for('login', redirect=flask.request.full_path))

@app.route('/')
def home():
	# return '''
	# <h1>Hello</h1>
	# <a href="/login">Log In</a>
	# '''
	return flask.redirect(flask.url_for('article', name='Home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
	if flask.request.method == 'GET':
		return flask.render_template('login.html')

	username = flask.request.form['username']
	if username in users and flask.request.form['password'] == users[username]['password']:
		user = User()
		user.id = username
		should_remember_me = 'yes' in flask.request.form.getlist('remember_me')
		flask.flash('You are now logged in 👌')
		print(f'Logging in {user} (remember me = {should_remember_me})')
		flask_login.login_user(user, remember=should_remember_me)

		redirect_url = flask.request.args.get('redirect')
		if not is_safe_url(redirect_url):
			return flask.abort(400)
		return flask.redirect(redirect_url)

	flask.flash('Please try a different username or password.')
	return flask.redirect(flask.request.full_path)

@app.route('/logout')
def logout():
	print(f'Logging out user {flask_login.current_user.id}')
	flask_login.logout_user()
	flask.flash('Logged out.')
	return flask.redirect(flask.url_for('article', name='Home'))

@app.route('/w/<name>')
def article(name: str):
	article = Article.get_name(name)
	if article is None:
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
