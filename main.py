#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import re
import os
import webapp2
import jinja2
import random
import string
import hashlib
import hmac

from google.appengine.ext import db

"""
    secret code used in hashing the cookie val
"""
secret = 'gfdgf78h97.jk,shfsgsgeieu..t45d.gd.g'

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

"""
    Regular expressions used to validate the user inputs for username,
    password and email during signup
"""
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    """
        Hashes the value using hmac algorithm and secret code
    """
    return '%s|%s' % (val, hmac.new(secret,val).hexdigest())

def check_secure_val(secure_val):
    """
        Verifies whether the hashed value is secure or not
        using against the secret code
    """
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def make_salt(length=5):
    """
        Generates a random code of length 5
    """
    return ''.join(random.choice(string.ascii_letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
    """
        Hashes the password using sha256 and salt
    """
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    #h = hashlib.sha256(''.join([name, pw, salt])).hexdigest()
    return '%s|%s' % (salt,h)

def valid_pw(name, password, h):
    """
        Verifies the hashed value of the password
        to check if it is secure or not
    """
    salt = h.split('|')[0]
    return h == make_pw_hash(name, password, salt)


class Handler(webapp2.RequestHandler):
    """
        Generic functions which are inherited by all the child handlers

    """
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


    def set_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/'
                                        % (name,cookie_val))

    def read_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def initialize(self, *a, **kw):
        """
            This function is invoked by webapp for every page load
            Reads the cookie and returns the user login status
        """
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_cookie('user_id')
        self.user = uid and Users.by_id(int(uid))


class Post(db.Model):
    """
        This Google DataStore kind that stores the information about each post

        Properties:
                    subject: Title of the post
                    content: Post content
                    created: Date the post is created on
                    last_modified: Date when the post is last updated
                    createdBy: Owner of the post
                    likes: Number of likes a particular post got
                    likedBy: list of users who liked the post
    """
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    createdBy = db.StringProperty(required = False)
    likes = db.IntegerProperty(required = False)
    likedBy = db.ListProperty(str)

    def render(self):
        """
            This method renders the details of the post and
            preseves the newlines of the post
        """
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

    @classmethod
    def get_posts_by_user(cls, username):
        """
            This method returns the posts created by a particular user
        """
        posts = db.GqlQuery("SELECT * FROM Post WHERE createdBy = :name order by created desc", name=username)  # NOQA
        return posts

class Comments(db.Model):
    """
        This is a Google Datastore Kind
        that stores the details about the comments of a post

        Properties:
                    comment: comment about the post
                    createdBy: owner of the comment
                    post_id: id of the post a specific comment belongs to
                    created: Date a comment is created on
    """
    comment = db.TextProperty(required = True)
    createdBy = db.StringProperty(required = True)
    post_id= db.IntegerProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def get_comments(cls, post_id):
        """
            This returns all the comments that a specific post has got
        """
        comments = db.GqlQuery("SELECT * FROM Comments WHERE post_id = :post", post=int(post_id))   # NOQA
        return comments

class Users(db.Model):
    """
        This is a Google Datastore Kind that stores the
        information about registered users

        Properties:
                    username: unique username that a specific user has given
                              during the registration
                    password: Hashed value of the password that a user uses to login
                    email: email that a user has given during registration
    """
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty(required = True)

    @classmethod
    def by_id(cls, uid):
        """
            This method returns the id of an Users entity
        """
        return Users.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        """
            This method returns an entity of a specific user
        """
        u = db.GqlQuery("SELECT * FROM Users WHERE username= :name",name=name).get()    # NOQA
        return u

    @classmethod
    def register(cls, name, pw, email):
        """
            This method hashes the user enterd password and returns the entity
            of an user with the given details
        """
        pw_hash = make_pw_hash(name, pw)
        return Users(username = name,
                     password = pw_hash,
                     email = email)

    @classmethod
    def login(cls, name, pw):
        user = cls.by_name(name)
        h_pw = user.password
        return valid_pw(name,pw,h_pw)



class MainHandler(Handler):
    """
        This handler displays the main page of the blog which includes
        all the posts sorted by date they were created
    """

    def render_front(self,user):
        self.display_content = db.GqlQuery("SELECT * FROM Post order by created desc")      # NOQA
        self.render("blog_main_page.html",display_content=self.display_content,
                     user=user)

    def get(self):
        self.render_front(user = self.user)


class NewPostHandler(Handler):
    """
        This handler displays the new post submission page if an user is logged
        in otherwise it redirects to homepage
    """
    def render_form(self, user, subject="", content="", error=""):
        self.render("blog_form.html", subject=subject, content=content,
                     error=error, user=user)

    def get(self):
        if self.user:
            self.render_form(user=self.user)
        else:
            self.redirect('/')

    def post(self):
        """
            When the user has entered both the subject and content
            this method stores the post in the database.
        """
        self.subject = self.request.get("subject")
        self.content = self.request.get("content")
        self.owner = self.user.username

        if self.subject and self.content:
            b = Post(subject=self.subject, content=self.content,
                     createdBy=self.owner)
            b.put()
            self.redirect('/%s' % str(b.key().id()))

        else:
            error = "We need both subject and content"
            self.render_form(subject=self.subject, content=self.content,
                             error=self.error, user=self.user)

class PostPage(Handler):
    """
        This handler displays a specific post with its like and comments
    """
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        self.post = db.get(key)

        if not self.post:
            self.error(404)
            return

        self.render("permalink.html", post = self.post, user=self.user)


class SignupPage(Handler):
    """
        This handler helps registering the users details into datastore
    """
    def render_signup_form(self, username="", password="", verify="", email="", error=""):      # NOQA
        self.render("signup_form.html", username=username, password=password,
                     verify=verify, email=email, error=error)

    def get(self):
        """
            This method displays an empty signup form
        """
        self.render_signup_form()

    def post(self):
        """
            This method validates the user entered details
            If an user has entered all valid details then they are stored in the
            datastore and sets the cookie and redirects to the welcome page of an user
        """
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify   = self.request.get("verify")
        self.email    = self.request.get("email")

        if self.username and self.password and self.verify and self.email:
            if not valid_username(self.username):
                self.error = "Not a valid username"
                self.render_signup_form(username=self.username,
                                        password=self.password,
                                        verify=self.verify, email=self.email,
                                        error=self.error)

            elif not valid_password(self.password):
                self.error="Not a valid password"
                self.render_signup_form(username=self.username,
                                        password=self.password,
                                        verify=self.verify, email=self.email,
                                        error=self.error)

            elif not valid_email(self.email):
                self.error = "Not a valid email"
                self.render_signup_form(username=self.username,
                                        password=self.password,
                                        verify=self.verify, email=self.email,
                                        error=self.error)

            elif not self.password==self.verify:
                self.error = "Passwords didn't match!!"
                self.render_signup_form(username=self.username,
                                        password=self.password,
                                        verify=self.verify, email=self.email,
                                        error=self.error)

            else:
                x = Users.by_name(self.username)
                if x:
                    self.error = "Username already exists!!"
                    self.render_signup_form(username=self.username,
                                            password=self.password,
                                            verify=self.verify,
                                            email=self.email, error=self.error)

                else:
                    u =Users.register(self.username, self.password, self.email)
                    u.put()

                    self.set_cookie('user_id',str(u.key().id()))

                    self.redirect('/welcome')
        else:
            self.error = "We need all fields to be entered"
            self.render_signup_form(username=self.username,
                                    password=self.password,
                                    verify=self.verify,
                                    email=self.email, error=self.error)


class Welcome(Handler):
    def get(self):
        """
            This method displays all the posts creted by a specific user
        """
        if self.user:
            self.posts = Post.get_posts_by_user(self.user.username)
            self.render("welcome.html", username = self.user.username,
                        posts = self.posts, user=self.user)
        else:
            self.redirect('/signup')

class LoginHandler(Handler):
    def render_login(self, username="", password="", error=""):
        self.render("login.html", username=username,
                     password=password, error=error)

    def get(self):
        """
            This method displays an empty login form
        """
        self.render_login()

    def post(self):
        """
            If a registered user details are entered this method
            sets the cookie and redirects to welcome page of an user
        """
        self.username = self.request.get("username")
        self.password = self.request.get("password")

        if self.username and self.password:
            self.existing_user = Users.by_name(self.username)

            if not self.existing_user:
                self.error = "Username doesnot exist"
                self.render_login(username=self.username,
                                  password=self.password,
                                  error=self.error)
            else:
                self.pwd_valid= Users.login(self.username, self.password)
                if self.pwd_valid:
                    self.set_cookie('user_id',
                                    str(self.existing_user.key().id()))
                    self.redirect('/welcome')
                else:
                    self.error="Invalid Password"
                    self.render_login(username=self.username,
                                      password=self.password,
                                      error=self.error)

        else:
            self.error="Enter both the fields"
            self.render_login(username=username,
                              password=password,
                              error=self.error)

class LogoutHandler(Handler):
    def get(self):
        """
            This method sets the cookie to empty value
            and redirects to login page
        """
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/login')

class EditPostHandler(Handler):
    def get(self, post_id):
        """
            This method checks whether the user has logged in and
            whether he/she is the owner of the post to edit it
        """
        key = db.Key.from_path('Post', int(post_id))
        self.post = db.get(key)
        if self.user:
            if self.post:
                if self.post.createdBy == self.user.username:
                    self.render("editPost.html", post = self.post,
                                 post_id = post_id, user=self.user)
                else:
                    self.error = "You don't have permissions to edit this post"
                    self.redirect('/welcome')
            else:
                error="This Post does not exist!!"
                self.redirect('/login')
        else:
            self.redirect('/login')

    def post(self, post_id):
        """
            If the user is the owner of that specific post
            then it displays a post form to edit the post
        """
        if self.user:
            self.subject = self.request.get("subject")
            self.content = self.request.get("content")

            key = db.Key.from_path('Post', int(post_id))
            self.post = db.get(key)
            if self.subject and self.content:
                self.post.subject = self.subject
                self.post.content = self.content
                self.post.put()
                self.redirect('/%s' % post_id)
            else:
                self.error = "You should enter both Subject and Content"
                self.render("editPost.html",post=self.post,
                                            error=self.error,
                                            user=self.user)
        else:
            self.redirect('/login')

class DeletePostHandler(Handler):
    def get(self, post_id):
        """
            This method checks whether the user is logged in and
            is owner of the post. If yes, it deletes the post
        """
        key = db.Key.from_path('Post', int(post_id))
        self.post = db.get(key)
        if self.user:
            if self.post:
                if self.post.createdBy == self.user.username:
                    db.delete(key)
                    self.redirect('/welcome')
                else:
                    self.error="You don't have permissions to delete this post"
                    self.redirect('/welcome')
            else:
                self.error="This Post does not exist!!"
                self.redirect('/welcome')
        else:
            self.redirect('/login')

class LikeHandler(Handler):
    def get(self,post_id):
        """
            This method increases or decreases the like count of a post
            If a user, who is not the owner of the post, likes/unlike the post
            it increases/decreases and displays post with updated likes
        """
        if self.user:
            key = db.Key.from_path('Post', int(post_id))
            self.post = db.get(key)
            if self.post.createdBy == self.user.username:
                self.redirect('/')
            else:
                if self.post.likes == None:
                    self.post.likes = 0
                if self.user.username in self.post.likedBy:
                    self.post.likes -= 1
                    self.post.likedBy.remove(self.user.username)
                    self.post.put()
                    self.redirect('/')
                else:
                    self.post.likes += 1
                    self.post.likedBy.append(self.user.username)
                    self.post.put()
                    self.redirect('/')

        else:
            self.redirect('/login')

class CommentHandler(Handler):
    def get(self, post_id):
        """
            This method displays the post along with its comments when a
            user clicks on the comments link of the post
        """
        key = db.Key.from_path('Post', int(post_id))
        self.post = db.get(key)

        self.comments = Comments.get_comments(post_id)
        self.render("permalink.html", post = self.post,
                                      comments = self.comments,
                                      user=self.user)

    def post(self, post_id):
        """
            This method adds the new comments entered by an user
            to the datastore and displays the post along with
            its comments
        """
        key = db.Key.from_path('Post', int(post_id))
        self.post = db.get(key)
        if self.user:
            self.comment = self.request.get("newComment")
            if self.comment:
                c = Comments(comment = self.comment,
                             createdBy = self.user.username,
                             post_id = int(post_id))
                c.put()
                self.comments = Comments.get_comments(int(post_id))
                self.render("permalink.html", post = self.post,
                                              comments = self.comments,
                                              user=self.user)
            else:
                self.redirect('/')
        else:
            self.redirect('/login')

class CommentEditHandler(Handler):
    def get(self, comment_id, post_id):
        """
            This method displays the comment of a post to be edited
        """
        key = db.Key.from_path('Comments', int(comment_id))
        self.comment = db.get(key)

        key = db.Key.from_path('Post', int(post_id))
        self.post = db.get(key)

        if self.user.username == self.comment.createdBy:
            self.render("editcomment.html", comment=self.comment,
                                            post = self.post,
                                            user=self.user)
        else:
            self.error = "You do not have permissions to edit this comment"
            self.comments = Comments.get_comments(int(post_id))
            self.render("permalink.html", post = post,
                                          comments = self.comments,
                                          error = self.error, user=self.user)

    def post(self, comment_id, post_id):
        """
            When an user edits the comment it updates in the datastore and
            displays the post with updated comments.
        """
        if self.user:
            self.updated_comment = self.request.get("comment")

            key = db.Key.from_path('Comments', int(comment_id))
            self.comment = db.get(key)

            key = db.Key.from_path('Post', int(post_id))
            self.post = db.get(key)

            self.comment.comment = self.updated_comment
            self.comment.put()
            self.comments = Comments.get_comments(int(post_id))
            self.render("permalink.html", post = self.post,
                                          comments = self.comments,
                                          user=self.user)

        else:
            self.redirect('/login')

class CommentDeleteHandler(Handler):
    def get(self, comment_id, post_id):
        """
            When an user, who is the owner of the comment, deletes the comment
            this method updates the comments in datastore and displays the post
            with updated comments
        """
        if self.user:
            c_key = db.Key.from_path('Comments', int(comment_id))
            self.comment = db.get(c_key)

            p_key = db.Key.from_path('Post', int(post_id))
            self.post = db.get(p_key)
            self.comments = Comments.get_comments(int(post_id))
            if self.comment:
                if self.user.username == self.comment.createdBy:
                    db.delete(c_key)
                    self.render("permalink.html", post = self.post,
                                                  comments = self.comments)
                else:
                    self.error = "You do not have permissions to delete this comment"       # NOQA
                    self.render("permalink.html", post = self.post,
                                                  comments = self.comments,
                                                  error = self.error)
            else:
                self.redirect('/welcome')
        else:
            self.redirect('/login')


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/newpost', NewPostHandler),
    ('/([0-9]+)', PostPage),
    ('/signup', SignupPage),
    ('/welcome', Welcome),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/editpost/([0-9]+)', EditPostHandler),
    ('/deletepost/([0-9]+)', DeletePostHandler),
    ('/like/([0-9]+)', LikeHandler),
    ('/comment/([0-9]+)', CommentHandler),
    ('/commentedit/([0-9]+)/([0-9]+)', CommentEditHandler),
    ('/commentdelete/([0-9]+)/([0-9]+)', CommentDeleteHandler)
], debug=True)
