// dependencies
const express = require('express')
const path = require("path");
const mongodb = require("mongodb");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const { auth } = require('./auth')
const session = require("express-session");
const { TASK } = require('./task');

const app = express()
app.set('view engine', 'ejs'); 

app.use(express.json())
app.use(express.urlencoded());
app.use(session({ secret: "XASDASDA" }));

mongoose.Promise = global.Promise;
const MongoClient = mongodb.MongoClient;
const connectionUrl = "mongodb://127.0.0.1:27017";   // connection to the databse
const databaseName = "credentials";                  // to store users credentials
const databaseName_2 = "permissions";                // to store permissions assigned to each role


// to set the initial state of the database
// admin and manager are inserted initially to the database
MongoClient.connect(connectionUrl, {useNewUrlParser:true}, (error,client) => {
  if(error){
    console.log(error)
  }
  const db=client.db(databaseName);
  
  // admin credentials are inserted initially to the database
  db.collection('users').findOne({username: 'admin'}, (error,user) => {
    if(!user){
      var adminPassword=bcrypt.hashSync('admin@123', 8)
      db.collection('users').insertOne({
          firstName: 'chiraag',
          lastName: 'mittal',
          username: 'admin',
          password: adminPassword,
          role: 'admin',
          isBlock: false
          })
    }
  })

  // manager credentials are inserted initially to the database
  db.collection('users').findOne({username: 'manager'}, (error,user) => {
    if(!user){
      var managerPassword=bcrypt.hashSync('manager@123', 8)
      db.collection('users').insertOne({
      firstName: 'chiraag',
      lastName: 'mittal',
      username: 'manager',
      password: managerPassword,
      role: 'manager',
      isBlock: false
      })
    }
  })
})


// permissions are assigned initially to the admin, manager, user
MongoClient.connect(connectionUrl, {useNewUrlParser:true}, (error,client) => {
  if(error){
    console.log("error")
  }
  const db=client.db(databaseName_2);


  // admin permissions
  db.collection('access').findOne({role: 'admin'}, (error,isRole) => {
    if(!isRole){
      db.collection('access').insertOne({
          role: 'admin',
          createUser:true,
          blockUser:true,
          updateProfile:true,
          updateOtherProfile:true,
          viewUsers: true,
          createRole: true
          })
    }
  })

  //manager permissions
  db.collection('access').findOne({role: 'manager'}, (error,isRole) => {
    if(!isRole){
      db.collection('access').insertOne({
          role: 'manager',
          createUser:false,
          blockUser:true,
          updateProfile:true,
          updateOtherProfile:true,
          viewUsers: true,
          createRole: false
          })
    }
  })

  // user permissions
  db.collection('access').findOne({role: 'user'}, (error,isRole) => {
    if(!isRole){
      db.collection('access').insertOne({
          role: 'user',
          createUser:false,
          blockUser:false,
          updateProfile:true,
          updateOtherProfile:false,
          viewUsers: true,
          createRole: false
          })
    }
  })
})


const publicDirectoryPath = path.join(__dirname, "/public");
app.use(express.static(publicDirectoryPath));

mongoose.connect("mongodb://localhost:27017/credentials", {useNewUrlParser: true,useUnifiedTopology: true});  // connection to the database

// details schema for creating a new user
var nameSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
    trim: true
  },
  lastName: {
    type: String,
    required: true,
    trim: true
  },
  username: {
    type: String,
    unique: true,
    required: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true,
    minlength: 7,
    trim: true,
    validate(value) {
      if (value.toLowerCase().includes("password")) {
        throw new Error('Password cannot conatin "password"');
      }
    }
  },
  role: {
    type: String,
    required: true,
    trim: true
  },
  isBlock: {
    type: Boolean,
    required: true,
    trim: true
  }
});

var User = mongoose.model("users", nameSchema);

// home page
app.get("/", (req, res) => {
    res.sendFile(__dirname + "/home.html");
});

// login to an existing account
app.post("/login", (request, response) => {
  try {
    User.findOne({ username: request.body.username }, (err, user) => {
      if (!user) {                                                                    // check if username already exists
        return response.status(400).send({
          message: "No user with this username exists.Try another one."
        });
      }
      if (!bcrypt.compareSync(request.body.password, user.password)){                // check if password is wrong
        return response.status(400).send({
          message: "Wrong Password"
        })
      }                                                                             // check if the user id blocked
      if (user.isBlock){
        return response.status(400).send({
          message: "Access Denied"
        })
      }
      request.session.role=user.role;
      request.session.isBlock=user.isBlock;
      response.sendFile(__dirname + "/public/dashboard.html");
    });
  } catch (err) {
    response.status(500).send(err);
  }
});

// middleware to check if the given user has the access to create a user
app.get('/createuser',auth(TASK.createUser), (req, res)=>{
  res.sendFile(__dirname + "/public/createUser.html");
})

// create a new user
app.post('/createUser', (request, response)=>{
  try {
    User.findOne({ username: request.body.username }, (err, user) => {                      // check if username already exists
      if (user) {
        return response.status(400).send({
          message: "Username already exists.Try another one."
        });
      }
      request.body.password = bcrypt.hashSync(request.body.password, 8);
      request.body.isBlock=false;
      var myData = new User(request.body);
      myData.save();                                                                         // saving the data to the database
      response.sendFile(__dirname + "/public/dashboard.html");
    });
  } catch (err) {
    response.status(500).send(err);
  }
  
})

// middleware to check if the given user has the access to block a user
app.get('/blockuser',auth(TASK.blockUser), (req, res)=>{
  res.sendFile(__dirname + "/public/blockUser.html");
})

// block an existing user
app.post('/blockUser', (request, response)=>{
  
  MongoClient.connect(connectionUrl, {useNewUrlParser:true}, (error,client) => {
    if(error){
      console.log(error)
    }
    const db=client.db(databaseName);
    
  const updateStatus=db.collection('users').updateOne({username: request.body.username}, { $set: { isBlock:true}})

   updateStatus.then(() => {
    response.sendFile(__dirname + "/public/dashboard.html")
   }).catch((error) => {
     console.log(error)
   })
  })
});

// middleware to check if the given user has the access to update the profile
app.get('/updateprofile',auth(TASK.updateProfile), (req, res)=>{
  console.log("chison")
  res.sendFile(__dirname + "/public/updateProfile.html");
})

// middleware to check if the given user has the access to update others profile
app.get('/updateOtherProfile',auth(TASK.updateOtherProfile), (req, res)=>{
  res.sendFile(__dirname + "/public/updateProfile.html");
})

// update profile
app.post('/updateProfile', (request, response)=>{
  MongoClient.connect(connectionUrl, {useNewUrlParser:true}, (error,client) => {
    if(error){
      console.log(error)
    }
    const db=client.db(databaseName);
    
  const updateStatus=db.collection('users').updateOne({username: request.body.oldUsername}, { $set: { username:request.body.username, firstName:request.body.firstName, lastName:request.body.lastName}})

   updateStatus.then(() => {
    response.sendFile(__dirname + "/public/dashboard.html")
   }).catch((error) => {
     console.log(error)
   })
  })
});

// middleware to check if the given user has the access to create a new role
app.get('/createRole',auth(TASK.createRole), (req, res)=>{
  res.sendFile(__dirname + "/public/createRole.html");
})

// create a new role
app.post('/createRole', (request, response)=>{
  MongoClient.connect(connectionUrl, {useNewUrlParser:true}, (error,client) => {
    if(error){
      console.log(error)
    }
    const db=client.db(databaseName_2);
    db.collection('access').findOne({role: request.body.role}, (error,Role) => {
      if(Role){
          return response.status(400).send({
          message: "This role already exists.Try another one."
        });
      }
    })
    db.collection('access').insertOne(request.body);
    response.sendFile(__dirname + "/public/dashboard.html");
  })
})

// view all users 
app.get('/viewUser', (request, response)=>{  
  MongoClient.connect(connectionUrl, {useNewUrlParser:true}, (error,client) => {
    if(error){
      console.log(error)
    }
    const db=client.db(databaseName);
    db.collection('users').find({type:request.body.username}).toArray((error,result) => {
      response.render('users', {data:result}); 
    })
  })    
});


app.listen(3000)