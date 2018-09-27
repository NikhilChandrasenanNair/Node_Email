const User = require("../models/employee-login.models");
const bcrypt = require("bcryptjs");
const jwt = require("jwt-simple");
const nodemailer = require("nodemailer");
const async = require("async");
const crypto = require("crypto");

const secret = require("../config/employee.config");

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, secret.secretToken);
}

exports.login = (req, res, next) => {
  // User has already had their email and password Auth'd
  // We just need to give them a token
  res.send({ token: tokenForUser(req.user) });
};

exports.register = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  if (!email) {
    return res.status(422).send({ error: "You must provide email" });
  } else if (!password) {
    return res.status(422).send({ error: "You must provide password" });
  }

  // see if user with a given email exists
  User.findOne({ email: email }, (err, existingUser) => {
    if (err) {
      return next(err);
    }

    // If user with email exist, return error
    if (existingUser) {
      return res.status(422).send({ error: "Email is in use" });
    }

    // if user with email does NOT exist, create and save user record
    const user = new User({
      email,
      password
    });

    // Generate a salt and then callback
    bcrypt.genSalt(10, (err, salt) => {
      if (err) {
        return next(err);
      }
      // Hash our password using salt
      bcrypt.hash(user.password, salt, (err, hash) => {
        if (err) {
          return next(err);
        }

        // overwright plain text password with encrypted passwords
        user.password = hash;
        user.save(err => {
          if (err) {
            return next(err);
          }
          // respond to request indication user was created
          res.json({ token: tokenForUser(user) });
        });
      });
    });
  });
};

exports.forgot = (req, res, next) => {
  async.waterfall(
    [
      function(done) {
        crypto.randomBytes(20, function(err, buf) {
          var token = buf.toString("hex");
          done(err, token);
        });
      },
      function(token, done) {
        const email = req.body.email;
        if (!email) {
          return res.status(422).send({ error: "You must provide email" });
        }
        User.findOne({ email: req.body.email }, function(err, user) {
          if (!user) {
            return res
              .status(422)
              .send({ error: "No account with that email address exists." });
          }

          user.resetPasswordToken = token;
          user.resetPasswordExpires = Date.now() + 3600000;
          user.save(function(err) {
            done(err, token, user);
          });
        });
      },
      function(token, user, done) {
        var smtpTransport = nodemailer.createTransport({
          service: "Gmail",
          auth: {
            type: "OAuth2",
            user: secret.gmail.senderMailId,
            clientId: secret.gmail.clientId,
            clientSecret: secret.gmail.clientSecret,
            refreshToken: secret.gmail.refreshToken,
            accessToken: secret.gmail.accessToken
          }
        });

        var mailOptions = {
          to: user.email,
          from: secret.gmail.senderMailId,
          subject: "Node.js Password Reset",
          text:
            "You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n" +
            "Please click on the following link, or paste this into your browser to complete the process:\n\n" +
            "http://" +
            req.headers.host +
            "/reset/" +
            token +
            "\n\n" +
            "If you did not request this, please ignore this email and your password will remain unchanged.\n"
          //html:
          //"<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'><meta http-equiv='X-UA-Compatible' content='ie=edge'><title>Resume</title><style>* {font-family: 'M PLUS Rounded 1c', sans-serif;}#template {font-family: 'M PLUS Rounded 1c', sans-serif;border-collapse: collapse;width: 100%;}td,th {/* border: 1px solid #dddddd; */text-align: left;padding: 8px 20px;}li {list-style-type: none;font-weight: normal;}li::before {content: '+';margin-left: -15px;margin-right: 5px;}#template__left {float: left;width: 15%;background-color: #434343;color: #fff;}#template__right {display: inline-block;width: 85%;}.template__profile--image {text-align: center;padding-top: 20px;}#template__right--header--container {display: block;}#template__right--header--content {position: relative;width: 13%;}#template__header {position: absolute;top: 50%;transform: translateY(-50%);}.template__right--logo {float: right;}.template__right--profSummary,.template__right--profSummary th,.template__right--edSummary,.template__right--edSummary th,.template__right--skSummary,.template__right--skSummary th {display: block;}.template__right--profSummary--label,.template__right--edSummary--label,.template__right--skSummary--label {padding: 0 0 15px 0;border-bottom: 1px solid #ff8787;}.template__right--skSummary th ul {width: 40%;display: inline-block;}.border {border: 1px solid #ccc !important;margin-bottom: 10px;}.red {color: #000 !important;background-color: #ff0000 !important;height: 24px;}#exper-section {padding-top: 16px;}.exper {float: left;padding: 5px;}.template__profile--name,.template__profile--title,.template__profile--office,.template__profile--roles,.template__profile--about,.template__profile--expertise {padding: 20px 0;border-bottom: 1px solid #ff8787;}ul {padding-left: 15px;}.template__profile--expertise {border-bottom: none;}@media (max-width: 1200px) {#template__left,#template__right {width: 100%;}#template__left tr {display: block;}.template__profile--image {display: block;}#template__right,.template__profile--image {margin-top: 30px;}.template__profile--name,.template__profile--title,.template__profile--office,.template__profile--roles,.template__profile--about,.template__profile--expertise {border-bottom: none;}}</style></head><body><table id='template'><tbody id='template__left'><tr><th class='template__profile--image'><img src='http://via.placeholder.com/150x150' alt=''></th></tr><tr><td class='template__profile--details'><div class='template__profile--name'><strong>John Doe</strong></div><div class='template__profile--title'><strong>Lorem:</strong><div>Lorem</div></div><div class='template__profile--office'><strong>Lorem:</strong><div>Lorem Ipsum is simply dummy text of</div></div><div class='template__profile--roles'><strong>Lorem:</strong><ul><li>Lorem Ipsum is simply dummy text of</li><li>Lorem Ipsum is simply dummy text of</li><li>Lorem Ipsum is simply dummy text of</li></ul></div><div class='template__profile--about'><strong>Lorem: </strong><div>Lorem Ipsum is simply dummy text of the printing and typesetting industry.</div></div><div class='template__profile--expertise'><strong>Lorem:</strong><div id='exper-section'><span class='exper'>Lorem</span><div class='border'><div class='red' style='width:50%;'></div></div><span class='exper'>Lorem</span><div class='border'><div class='red' style='width:30%;'></div></div><span class='exper'>Lorem</span><div class='border'><div class='red' style='width:70%;'></div></div><span class='exper'>Lorem</span><div class='border'><div class='red' style='width:60%;'></div></div><span class='exper'>Lorem</span><div class='border'><div class='red' style='width:80%;'></div></div><span class='exper'>Lorem</span><div class='border'><div class='red' style='width:60%;'></div></div></div></div></td></tr></tbody><tbody id='template__right'><tr id='template__right--header--container'><th id='template__right--header--content'><div id='template__header'><div id='template__companyName'>XACASDFEN DWSTALR</div><div id='template__designation'>Lorem</div></div><img src='http://via.placeholder.com/200x80' class='template__right--logo' alt=''></th></tr><tr class='template__right--profSummary'><th><div class='template__right--profSummary--label'>Lorem</div></th></tr><tr class='template__right--profSummary'><th><ul><li>Lorem Ipsum is simply dummy text of the printing and typesetting industry.</li><li>Lorem Ipsum is simply dummy text of the printing and typesetting industry.</li><li>Lorem Ipsum is simply dummy text of the printing and typesetting industry.</li><li>Lorem Ipsum is simply dummy text of the printing and typesetting industry.</li><li>Lorem Ipsum is simply dummy text of the printing and typesetting industry.</li><li>Lorem Ipsum is simply dummy text of the printing and typesetting industry.</li><li>Lorem Ipsum is simply dummy text of the printing and typesetting industry.</li><li>Lorem Ipsum is simply dummy text of the printing and typesetting industry.</li></ul></th></tr><tr class='template__right--edSummary'><th><div class='template__right--edSummary--label'>Lorem</div></th></tr><tr class='template__right--edSummary'><th><ul><li>Lorem Ipsum is simply dummy text of the printing and typesetting industry.</li></ul></th></tr><tr class='template__right--skSummary'><th><div class='template__right--skSummary--label'>Lorem</div></th></tr><tr class='template__right--skSummary'><th><ul><li>Lorem</li><li>Lorem</li><li>Lorem</li><li>Lorem</li><li>Lorem</li></ul><ul><li>Lorem</li><li>Lorem</li><li>Lorem</li><li>Lorem</li><li>Lorem</li></ul><ul><li>Lorem</li><li>Lorem</li><li>Lorem</li><li>Lorem</li><li>Lorem</li></ul> <ul><li>Lorem</li><li>Lorem</li><li>Lorem</li><li>Lorem</li><li>Lorem</li></ul><ul><li>Lorem</li><li>Lorem</li><li>Lorem</li><li>Lorem</li><li>Lorem</li></ul></th></tr></tbody></table></body></html>"
        };

        smtpTransport.sendMail(mailOptions, function(err) {
          if (err) return next(err);

          res.json({ email: `Sent successfully to ${user.email}` });
        });
      }
    ],
    function(err) {
      if (err) return next(err);
    }
  );
};

exports.reset = (req, res) => {
  async.waterfall(
    [
      function(done) {
        User.findOne(
          {
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() }
          },
          function(err, user) {
            if (!user) {
              return res.redirect("back");
            }

            // Generate a salt and then callback
            bcrypt.genSalt(10, (err, salt) => {
              if (err) {
                return next(err);
              }
              // Hash our password using salt
              bcrypt.hash(req.body.password, salt, (err, hash) => {
                if (err) {
                  return next(err);
                }

                // overwright plain text password with encrypted passwords
                user.password = hash;
                user.resetPasswordToken = undefined;
                user.resetPasswordExpires = undefined;

                user.save(err => {
                  if (err) {
                    return next(err);
                  }
                  // respond to request indication user was created
                  res.json({ token: tokenForUser(user) });
                  done(err, user);
                });
              });
            });
          }
        );
      },
      function(user, done) {
        var smtpTransport = nodemailer.createTransport({
          service: "Gmail",
          auth: {
            type: "OAuth2",
            user: secret.gmail.senderMailId,
            clientId: secret.gmail.clientId,
            clientSecret: secret.gmail.clientSecret,
            refreshToken: secret.gmail.refreshToken,
            accessToken: secret.gmail.accessToken
          }
        });

        var mailOptions = {
          to: user.email,
          from: secret.gmail.senderMailId,
          subject: "Your password has been changed",
          text:
            "Hello,\n\n" +
            "This is a confirmation that the password for your account " +
            user.email +
            " has just been changed.\n"
        };

        smtpTransport.sendMail(mailOptions, function(err) {
          if (err) return next(err);

          res.json({ success: "Success! Your password has been changed." });
        });
      }
    ],
    function(err) {
      res.redirect("/");
    }
  );
};

exports.test = (req, res, next) => {
  res.send("Test Controller");
};
