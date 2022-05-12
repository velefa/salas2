require('dotenv').config();
const express = require('express');
const {body, validationResult} = require('express-validator');
const mysql = require('mysql');
const session = require('express-session');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const ejs = require('ejs');
const { cookie } = require('express/lib/response');

const app = express();
app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: true}));
app.use(cookieParser());
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {maxAge: 10000}
}));

const conn = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'usersDB'
});

conn.connect(function (err) {
    if (err) throw err;
});


const tableQuery = `create table if not exists users (
    id int auto_increment primary key,
    username varchar(30) not null,
    password varchar(255) not null
)`;

conn.query(tableQuery, function (err) {
    if (err) throw err;
});

var num_of_tries = [];


app.get('/login', function (req, res) {
    if (req.session.bruteForce) {
        res.end("I will kill you");
    } else {
        res.render('login', {errors: null});
    }
});

app.get('/register', function (req, res) {
    if (req.session.bruteForce) {
        res.end("I will kill you");
    } else {
        res.render('register', {errors: null});
    }
});

app.get('/home', function (req, res) {
    if (req.session.bruteForce) {
        res.end("I will kill you");
    } else {
        if (req.session.isAuth) {
            const userdata = req.cookies.user_data;
            res.render('home', {username: userdata.username});
        } else {
            res.redirect('/login');
    }
    }
});

app.get('/change_password', function (req, res) {
    if (req.session.bruteForce) {
        res.end("I will kill you");
    } else {
        res.render('change_password', {errors: null});
    }
});

app.post('/register', 
    body('username').trim().escape().isLength({min: 3, max: 15}).withMessage('Username length should be between 3 and 15'),
    body('password').trim().escape().isLength({min: 5}).withMessage("Password length should be at least 5")
        .matches('[A-Z]').withMessage('Password should contain at least one Capital letter')
        .matches('[0-9]').withMessage('Password should contain at least one digit'),
    async function (req, res) {
        if (req.session.bruteForce) {
        res.end("I will kill you");
    } else {
        const validationErrors = validationResult(req);
        if(!validationErrors.isEmpty()) {
            const errors = [];
            validationErrors.array().forEach(elem => {
                errors.push(elem.msg);
            })
            res.render('register', {errors: errors});
        } else {    
            const {username, password, confirm_password} = req.body;
            const search_query = `select * from users where username = "${username}"`;
            conn.query(search_query, async function (err, results) {
                if (results.length === 1) {
                    res.render('register', {errors: ['This user already exists']});
                } else {
                    if (password === confirm_password) {
                        const hashedPassword = await bcrypt.hash(password, 10);
                        const insert_sql = `insert into users(username, password) values("${username}", "${hashedPassword}")`;
                        await conn.query(insert_sql, function (err) {
                            if (err) throw err;
                        });
                        res.redirect('/login');
                    } else {
                        res.render('register', {errors: ['Confirmation password did not match']});
                    } 
                    
                }
            });
        }
    }
});


app.post('/login', async function (req, res) {
    if (req.session.bruteForce) {
        res.end("I will kill you");
    } else {
        const {username, password} = req.body;
        const search_sql = `select * from users where username = "${username}"`;
        conn.query(search_sql, async function (err, results) {
           if (results.length === 1) {
                const result = results[0];
                bcrypt.compare(password, result.password, function (err, match) {
                    if (match) {
                        req.session.isAuth = true;
                        req.session.bruteForce = false;
                        num_of_tries = [];
                        res.cookie('user_data', {username: username}, {maxAge: 10000});
                        res.redirect('/home');
                    } else {
                        var count = 0;
                        num_of_tries.forEach(elem => {
                            if (elem === username) {
                                count++;
                            }
                        });
                        if (count > 2) {
                            req.session.bruteForce = true;
                            num_of_tries = [];
                            res.redirect('/login');
                        } else {
                            num_of_tries.push(username);
                            res.render('login', {errors: ["Incorrect password"]});
                        }
                        
                    }
                })
           } else {
               res.render('login', {errors: ["This user does not exist"]});
           }
        });
    }
});


app.post('/change_password', 
    body('new_password').trim().escape().isLength({min: 5}).withMessage("Password length should be at least 5")
        .matches('[A-Z]').withMessage('Password should contain at least one Capital letter')
        .matches('[0-9]').withMessage('Password should contain at least one digit'),
    async function (req, res) {
        if (req.session.bruteForce) {
            res.end("I will kill you");
        } else {
            const validationErrors = validationResult(req);
            if (!validationErrors.isEmpty()) {
                const errors = [];
                validationErrors.array().forEach(elem => {
                    errors.push(elem.msg);
                });
                res.render('change_password', {errors: errors});
            } else {    
                const {username, password, new_password, confirm_new} = req.body;
                const search_sql = `select * from users where username = "${username}"`;
                conn.query(search_sql, async function (err, results) {
                        if (results.length === 1) {
                            const result = results[0];
                            await bcrypt.compare(password, result.password, async function (err, match) {
                                if (err) throw err;
                                if (match) {
                                    if (new_password !== password) {
                                        if(confirm_new === new_password) {
                                            const hashedNewPassword = await bcrypt.hash(new_password, 10)
                                            const update_sql = `update users set password  = "${hashedNewPassword}" where username = "${username}"`;
                                            await conn.query(update_sql, function (err) {
                                                if (err) throw err;
                                            });
                                            res.redirect('/login');
                                        } else {
                                            res.render('change_password', {errors: ['Confirmation password did not match']});
                                        }
                                    } else {
                                        res.render('change_password', {errors: ['New password should be different from old password']});
                                    }
                                } else {  
                                    res.render('change_password', {errors: ['Incorrect password']});
                                }
                            })
                        } else {
                            res.render('change_password', {errors: ['This user does not exist']});
                        }
                });
            }
        }
});


app.post('/logout', function (req, res) {
    if (req.session.isAuth) {
        req.session.isAuth = false;
        res.clearCookie('user_data');
        res.redirect('/login');
    } else {
        res.end('Police are coming bro :>');
    }
});

app.listen(3000, function () {
    console.log('Server started on port 3000');
});
