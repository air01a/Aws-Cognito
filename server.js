const awsRegion = 'eu-west-1'; // AWS Region
const awsUserPoolId = '';      // AwS Cognito User Pool ID
const awsAppId = '';           // AWS Application ID 
const awsAppSecret = '';       // AWS Application Secret
const awsDomain = '';          // AWS Domain used for cognito endpoint
const awsAppUrl = '';          // Application URL

const https = require('https');
const fs = require('fs');
const qs = require('querystring');
const url = require('url');
const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const express = require('express');
const cookieParser = require('cookie-parser')


const options = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem')
};

let pem='';
session = {};

// Get AWS Public Key and convert to PEM
//https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
function getPem() {

        console.log("get pem");
        var options = {
                        hostname: 'cognito-idp.'+awsRegion+'.amazonaws.com',
                        port: 443,
                        path: '/'+awsUserPoolId+'/.well-known/jwks.json',
                        method: 'GET'
        };
        data='';
        get_req =https.request(options, function(resp){
                resp.on('data', function (chunk) {
                        data=data+chunk;
                });
                resp.on('end',function() {
                        var jsonContent = JSON.parse(data);
                        keys = jsonContent.keys[0];
                        pem = jwkToPem(keys);
                });
        });
        get_req.end();
}

function createCookie() {
        let randomNumber=Math.random().toString();
        randomNumber=randomNumber.substring(2,randomNumber.length);
        return randomNumber;
}

function getPage(decodedToken) {
        email = decodedToken.email;
        page = "<html><body>Hello " + email +"<br><b>Groups : </b></br>";
        for (group in decodedToken['cognito:groups']){
                page+="&nbsp;&nbsp;&nbsp;"+decodedToken['cognito:groups'][group]+"<br>";
        };
        console.log(decodedToken);
        page += "<br /><a href='https://"+awsDomain+".auth."+awsRegion+".amazoncognito.com/logout?client_id="+awsAppId+"&logout_uri="+awsAppUrl+">Logout</a></body></html>";
        return page;

}

function getErrorPage(error) {
        page = "<html><body>Error during token validation : "+error+"</body></html>";
        return page;
}

//Validate Token with AWS Key
//https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html

function validateToken(token,res) {
        jwt.verify(token, pem, { algorithms: ['RS256'] }, function(err, decodedToken) {
                if (err != null) {
                        res.write(getErrorPage('Token with invalid signature'));
                } else {
                        expectedISS = 'https://cognito-idp.eu-west-1.amazonaws.com/'+ awsUserPoolId
                        expectedAud = awsAppId ;
                        var date = new Date();
                        timestamp = date.getTime()/1000; // AWS time stamp in seconds, not milliseconds
                        if ((timestamp>decodedToken.exp) || (expectedISS!=decodedToken.iss)||(expectedAud!=decodedToken.aud)){
                                res.write(getErrorPage('Token not valid'));
                        } else {
                                cookie = createCookie();
                                session[cookie]=decodedToken;
                                res.cookie('auth',cookie);
                                res.write(getPage(decodedToken));
                        }
                }
                res.end();
        });
}

// Get Token from auth code
// https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html

function getToken(code,res) {

        // Url bonduelle44.auth.eu-west-1.amazoncognito.com//oauth2/token expect Authorization header with appid:appsecret
        // appsecret visible in config appclients in cognito
        var post_data = qs.stringify({
                'grant_type' : 'authorization_code',
                'code' : code,
                'redirect_uri':awsAppUrl
          });

        var post_options = {
                host: awsDomain+'.auth.'+awsRegion+'.amazoncognito.com',
                port: '443',
                path: '/oauth2/token',
                method: 'POST',
                headers: {
                                'Content-Type': 'application/x-www-form-urlencoded',
                                'Authorization': 'Basic '+Buffer.from(awsAppId+':'+awsAppSecret).toString('base64'),
                                'Content-Length': Buffer.byteLength(post_data)
                        }
                };

        data='';


        var post_req = https.request(post_options, function(resP) {
              resP.setEncoding('utf8');
                resP.on('data', function (chunk) {
                          data=data+chunk;
                });
                resP.on('end',function() {
                        var jsonContent = JSON.parse(data);
                        // If error with the auth code, display page
                        if ('error' in jsonContent) {
                                console.log(jsonContent);
                                res.writeHead(500);
                                res.write(getErrorPage('authentication code not valid'));
                                res.end();
                        } else {
                                // Else, we get the token and validate it
                                token=jsonContent.id_token;
                                validateToken(token,res);
                        }
                });
         });
        post_req.write(post_data);
        post_req.end();
}

// Main
//

const app = express()
app.use(cookieParser());

app.get('/logout', function(req,res){
        let cookie = req.cookies.auth;

        if ((cookie!=undefined)&&(session[cookie]!=undefined)) {
                delete session[cookie];
        }
        res.clearCookie('auth');
        res.send('<html><body>Cookie deleted<br /><a href="'+awsAppUrl+'">Login</a></body></html>');
});



app.get('/*',function (req, res) {
        let reqUrlString = req.url;
        let urlObject = url.parse(reqUrlString, true);
        let cookie = req.cookies.auth;

        if ((cookie!=undefined)&&(session[cookie]!=undefined))
        {
                console.log('Cookie found');
                res.write(getPage(session[cookie]));
                res.end();
        } else {

                if ( !('code' in urlObject.query) || (urlObject.query.code == 'undefined')) {
                        res.redirect('https://'+awsDomain+'.auth.'+awsRegion+'.amazoncognito.com/login?client_id='+ awsAppId +'&response_type=code&redirect_uri='+qs.stringify(awsAppUrl));
                        res.end();

                } else {
                        accessCode =  urlObject.query.code;
                        getToken(accessCode,res);
                }
        }
});


getPem();
https.createServer(options, app).listen(443);
