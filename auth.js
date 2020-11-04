const mongodb = require("mongodb");
const MongoClient = mongodb.MongoClient;
const connectionUrl = "mongodb://127.0.0.1:27017";
const databaseName = "credentials";
const databaseName_2 = "permissions";

// middleware function to check the authorisation
function auth(task) {
  return (req, res, next) => {
    MongoClient.connect(connectionUrl, {useNewUrlParser:true}, (error,client) => {
      if(error){
        console.log(error)
      }
      const db=client.db(databaseName_2);
      
    db.collection('access').findOne({role: req.session.role}, (error,user) => {
      var hasAccess=false;

      if(task==='createUser'){
        hasAccess=user.createUser?true:false
      }
      if(task==='blockUser'){
        hasAccess=user.blockUser?true:false
      }
      if(task==='updateProfile'){
        hasAccess=user.updateProfile?true:false
      }
      if(task==='updateOtherProfile'){
        hasAccess=user.updateOtherProfile?true:false
      }
      if(task==='createRole'){
        hasAccess=user.createRole?true:false
      }
      if(hasAccess){
        next();
      }
      else{
        return res.status(400).send({
          message: "Access Denied"
       });
      }
    })
    })
  }
}


module.exports = {
  auth
}