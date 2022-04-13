const express = require('express');
const path = require('path');
const cookieSession = require('cookie-session');
const bcrypt = require('bcrypt');
const dbConnection = require('./database');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(express.urlencoded({extended:false}));
app.use(express.static("public"));
// SET OUR VIEWS AND VIEW ENGINE
app.set('views', path.join(__dirname,'views'));
app.set('view engine','ejs');

// APPLY COOKIE SESSION MIDDLEWARE
app.use(cookieSession({
    name: 'session',
    keys: ['key1', 'key2'],
    maxAge:  3600 * 1000 // 1hr
}));

// DECLARING CUSTOM MIDDLEWARE
// const ifNotLoggedin = (req, res, next) => {
//     if(!req.session.isLoggedIn){
//         return res.render('main');
//     }
//     next();
// }

const ifNotLoggedin = (req, res, next) => {
    if(!req.session.isLoggedIn){
        return res.render('main');
    }
    next();
}
const ifLoggedin = (req,res,next) => {
    if(req.session.isLoggedIn){
        return res.redirect('/dashboard');
    }
    next();
}

app.get('/dashboard',(req,res)=>{
    //session destroy

    if(req.session.isLoggedIn){
        dbConnection.execute("SELECT `username` FROM `users` WHERE `id`=?",[req.session.userID])
    .then(([rows]) => {
        res.render('dashboard',{
            username:rows[0].username
        });
    });
    
}else{
    return res.redirect('/backend');
}

});
// END OF CUSTOM MIDDLEWARE
// ROOT PAGE
app.get('/', ifNotLoggedin, (req,res,next) => {
    dbConnection.execute("SELECT `name` FROM `users` WHERE `id`=?",[req.session.userID])
    .then(([rows]) => {
        res.render('home',{
            name:rows[0].name
        });
    });
    
});// END OF ROOT PAGE


// REGISTER PAGE
app.post('/register', ifLoggedin, 
// post data validation(using express-validator)
[
    body('user_email','Invalid email address!').isEmail().custom((value) => {
        return dbConnection.execute('SELECT `email` FROM `users` WHERE `email`=?', [value])
        .then(([rows]) => {
            if(rows.length > 0){
                return Promise.reject('This E-mail already in use!');
            }
            return true;
        });
    }),
    body('user_name','Username is Empty!').trim().not().isEmpty(),
    body('user_pass','The password must be of minimum length 6 characters').trim().isLength({ min: 6 }),
],// end of post data validation
(req,res,next) => {

    const validation_result = validationResult(req);
    const {user_name, user_pass, user_email} = req.body;
    // IF validation_result HAS NO ERROR
    if(validation_result.isEmpty()){
        // password encryption (using bcryptjs)
        bcrypt.hash(user_pass, 12).then((hash_pass) => {
            // INSERTING USER INTO DATABASE
            dbConnection.execute("INSERT INTO `users`(`name`,`email`,`password`) VALUES(?,?,?)",[user_name,user_email, hash_pass])
            .then(result => {
                res.send(`your account has been created successfully, Now you can <a href="/">Login</a>`);
            }).catch(err => {
                // THROW INSERTING USER ERROR'S
                if (err) throw err;
            });
        })
        .catch(err => {
            // THROW HASING ERROR'S
            if (err) throw err;
        })
    }
    else{
        // COLLECT ALL THE VALIDATION ERRORS
        let allErrors = validation_result.errors.map((error) => {
            return error.msg;
        });
        // REDERING main PAGE WITH VALIDATION ERRORS
        res.render('main',{
            register_error:allErrors,
            old_data:req.body
        });
    }
});// END OF REGISTER PAGE


// LOGIN PAGE
app.post('/', ifLoggedin, [
    body('user_email').custom((value) => {
        return dbConnection.execute('SELECT email FROM users WHERE email=?', [value])
        .then(([rows]) => {
            if(rows.length == 1){
                return true;
                
            }
            return Promise.reject('Invalid Email Address!');
            
        });
    }),
    body('user_pass','Password is empty!').trim().not().isEmpty(),
], (req, res) => {
    const validation_result = validationResult(req);
    const {user_pass, user_email} = req.body;
    if(validation_result.isEmpty()){
        
        dbConnection.execute("SELECT * FROM `users` WHERE `email`=?",[user_email])
        .then(([rows]) => {
            bcrypt.compare(user_pass, rows[0].password).then(compare_result => {
                if(compare_result === true){
                    req.session.isLoggedIn = true;
                    req.session.userID = rows[0].id;

                    res.redirect('/');
                }
                else{
                    res.render('main',{
                        login_errors:['Invalid Password!']
                    });
                }
            })
            .catch(err => {
                if (err) throw err;
            });


        }).catch(err => {
            if (err) throw err;
        });
    }
    else{
        let allErrors = validation_result.errors.map((error) => {
            return error.msg;
        });
        // REDERING main PAGE WITH LOGIN VALIDATION ERRORS
        res.render('main',{
            login_errors:allErrors
        });
    }
});
// END OF LOGIN PAGE

// LOGOUT
app.get('/logout',(req,res)=>{
    //session destroy
    req.session = null;
    res.redirect('/');
});
// END OF LOGOUT

app.get('/about',(req,res)=>{
    //session destroy
    req.session = null;
    res.render('about');
});

app.post('/signup',(req,res)=>{
    //session destroy
    console.log(req.body.password1);
    let user = {
        "username": req.body.email,
        "password": req.body.password1
}

    // req.session = null;
    bcrypt.hash(req.body.password1, 12).then((hash_pass) => {
        console.log(hash_pass);
        // INSERTING USER INTO DATABASE
        dbConnection.execute("INSERT INTO `users`(`username`,`password`) VALUES(?,?)",[req.body.email ,hash_pass])
        .then(result => {
            res.send(`your account has been created successfully, Now you can <a href="/backend">Login</a>`);
        }).catch(err => {
            // THROW INSERTING USER ERROR'S
            console.log("err:",err);
            if (err)   res.render('signup');;
        });
    })
    .catch(err => {
        // THROW HASING ERROR'S
        console.log(err);
        if (err)   res.render('signup');;
    })
    // res.render('signup');
});

app.get('/signup',(req,res)=>{
    //session destroy
    req.session = null;
    res.render('signup');
});

app.get('/backend',(req,res)=>{
    //session destroy
    req.session = null;
    res.render('backend');
});



app.post('/signIn',ifLoggedin, [
    body('user_email').custom((value) => {
        return dbConnection.execute('SELECT username FROM users WHERE username=?', [value])
        .then(([rows]) => {
            if(rows.length == 1){
                return true;
                
            }
            return Promise.reject('Invalid username!');
            
        });
    }),
    body('user_pass','Password is empty!').trim().not().isEmpty(),
], (req, res) => {
    const validation_result = validationResult(req);
    const {user_pass, user_email} = req.body;
    console.log("user_pass, user_email:",user_pass, user_email);
    if(validation_result.isEmpty()){
        console.log("user_pass, sssssssuser_email:",user_pass, user_email);
        dbConnection.execute("SELECT * FROM `users` WHERE `username`=?",[user_email])
        .then(([rows]) => {
            bcrypt.compare(user_pass, rows[0].password).then(compare_result => {
                if(compare_result === true){
                    req.session.isLoggedIn = true;
                    req.session.userID = rows[0].id;
                 
                    res.redirect('/dashboard');
                }
                else{
                    res.redirect('/backend');
                }
            })
            .catch(err => {
                if (err) throw err;
            });


        }).catch(err => {
            if (err) throw err;
        });
    }
    else{
        console.log("user_pass, useddddddddr_email:");
        let allErrors = validation_result.errors.map((error) => {
            return error.msg;
        });
        // REDERING main PAGE WITH LOGIN VALIDATION ERRORS
        res.redirect('/backend');
    }
});
// END OF LOGIN PAGE




app.use('/', (req,res) => {
    res.status(404).send('<h1>404 Page Not Found!</h1>');
});



app.listen(3000, () => console.log("Server is Running..."));
