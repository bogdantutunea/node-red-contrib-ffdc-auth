const {
  Console
} = require('console')

module.exports = function (RED) {
  'use strict'

  const Issuer = require('openid-client').Issuer
  const crypto = require('crypto')
  const os = require('os')
  var copilas = require('child_process').exec;
  var name_of_id = ""
  var type = 0
  let request = require("request");
  var linkAutorizare = "empty"

  function OpenIDNode(n) {
    RED.nodes.createNode(this, n);
  }

  RED.nodes.registerType('openid-credentials', OpenIDNode, {
    credentials: {
      display_name: {
        type: 'text'
      },
      discovery_url: {
        type: 'text'
      },
      client_id: {
        type: 'text'
      },
      client_secret: {
        type: 'text'
      },
      scopes: {
        type: 'text'
      },
      id_token: {
        type: 'password'
      },
      refresh_token: {
        type: 'password'
      },
      access_token: {
        type: 'password'
      },
      expires_at: {
        type: 'text'
      }
    }
  })

  RED.httpAdmin.get('/linkautorizare', (req, res) => {
    if (linkAutorizare.localeCompare("empty")) {
      res.redirect(linkAutorizare);
    } else
      res.send(linkAutorizare);
  })

  RED.httpAdmin.get('/openid-credentials/auth', function (req, res) {
    if (!req.query.discovery || !req.query.clientId || !req.query.clientSecret || !req.query.id || !req.query.callback) {
      res.send(400)
      return
    }
    const node_id = req.query.id
    const discovery_url = req.query.discovery
    const redirect_uri = req.query.callback
    const client_id = req.query.clientId
    const client_secret = req.query.clientSecret
    name_of_id = req.query.nameOfId
    console.log("req.query.nameOfId: " + req.query.nameOfId)
    const scopes = req.query.scopes.trim() !== '' ? req.query.scopes.trim() : 'openid'
    Issuer.discover(discovery_url).then((issuer) => {
      const csrf_token = crypto.randomBytes(18).toString('base64').replace(/\//g, '-').replace(/\+/g, '_')
      const client = new issuer.Client({
        client_id,
        client_secret
      })
      const authorization_url = client.authorizationUrl({
        redirect_uri,
        scope: scopes,
        state: `${node_id}:${csrf_token}`,
        access_type: 'offline'
      })
      res.cookie('csrf', csrf_token)
      res.redirect(authorization_url)
      RED.nodes.addCredentials(node_id, {
        discovery_url,
        client_id,
        client_secret,
        scopes,
        redirect_uri,
        csrf_token,
        display_name: name_of_id
      })
    }, (err) => {
      console.log('Discover error %j', err)
      return res.send(RED._('openid.error.bad-discovery-url'))
    })
  })

  RED.httpAdmin.get('/openid-credentials/auth/callback', function (req, res) {
    if (req.query.error) {
      return res.send('ERROR: ' + req.query.error + ': ' + req.query.error_description)
    }
    const state = req.query.state.split(':')
    const node_id = state[0]
    const credentials = RED.nodes.getCredentials(node_id)
    if (!credentials || !credentials.client_id || !credentials.client_secret) {
      return res.send(RED._('openid.error.no-credentials'))
    }
    console.log('Credentials:' + JSON.stringify(credentials))
    console.log('Query:' + JSON.stringify(req.query))
    if (state[1] !== credentials.csrf_token) {
      return res.status(401).send(
        RED._('openid.error.token-mismatch')
      )
    }

    Issuer.discover(credentials.discovery_url).then(issuer => {
      const client = new issuer.Client(credentials)
      client.authorizationCallback(credentials.redirect_uri, {
        code: req.query.code
      }).then((tokenSet) => {
        const claims = tokenSet.claims
        RED.nodes.addCredentials(node_id, Object.assign({}, credentials, {
          id_token: tokenSet.id_token,
          refresh_token: tokenSet.refresh_token,
          access_token: tokenSet.access_token,
          expires_at: tokenSet.expires_at
        }))
        console.log("Authorized")
        var data = "";
        const http = require('http');
        http.get('http://127.0.0.1:1880/flows', (res2) => {
          console.log("eee");
          res2.on('data', (code) => {
            data = "{\"flows\":" + code.toString() + "}";
          });

          res2.on('end', () => {
            const options = {
              hostname: '127.0.0.1',
              port: 1880,
              path: '/flows',
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Content-Length': data.length,
                'Node-RED-API-Version': 'v2'
              }
            }

            const req = http.request(options, res => {
              console.log(`statusCode: ${res.statusCode}`)
              res.on('data', d => {
                process.stdout.write(d)
              })
            })

            req.on('error', error => {
              console.error(error)
            })

            req.write(data)
            req.end()
          })

        })
        return res.send(RED._('openid.error.authorized'))
      }, err => {
        console.log('OpenID err:', err)
        return res.send(RED._('openid.error.something-broke'))
      })
    }, err => {
      console.log('Discover error %j', err)
      return res.send(RED._('openid.error.bad-discovery-url'))
    })
  })

  function OpenIDRequestNode(n) {
    RED.nodes.createNode(this, n)
    const cred_test = RED.nodes.getCredentials(n.openid);
    this.name = n.name || "";
    this.container = n.container || "";
    this.access_token_url = n.access_token_url || "";
    this.grant_type_auth = n.grant_type_auth || "";
    this.username = n.username || "";
    this.password = n.password || "";
    this.client_id = n.client_id || "";
    this.client_secret = n.client_secret || "";
    this.scope = n.scope || "";
    this.headers = n.headers || 'headers';
    this.openid = RED.nodes.getNode(n.openid)


    if (n.grant_type_auth === "client_credentials") {
      this.on("input", function (msg) {
        let node = this;
        if (n.headers) {
          for (var h in n.headers) {
            if (n.headers[h] && !Headers.hasOwnProperty(h)) {
              Headers[h] = n.headers[h];
            }
          }
        }

        // Put all together
        var options = {}
        if (node.grant_type === "set_by_credentials") {
          options = {
            'method': 'POST',
            'url': msg.oauth2Request.access_token_url,
            'headers': {
              'Authorization': "Basic " +
                Buffer.from(`${msg.oauth2Request.credentials.client_id}:${msg.oauth2Request.credentials.client_secret}`).toString(
                  "base64"
                ),
              'Content-Type': 'application/x-www-form-urlencoded',
              'Accept': 'application/json',
            },
            form: {
              'grant_type': msg.oauth2Request.credentials.grant_type,
              'scope': msg.oauth2Request.credentials.scope
            }
          };
          if (msg.oauth2Request.credentials.grant_type === "password") {
            options.form.username = msg.oauth2Request.credentials.username;
            options.form.password = msg.oauth2Request.credentials.password;
          };
          if (msg.oauth2Request.credentials.grant_type === "refresh_token") {
            options.form.refresh_token = msg.oauth2Request.credentials.refresh_token;
          }
        } else {
          options = {
            'method': 'POST',
            'url': node.access_token_url,
            'headers': {
              'Authorization': "Basic " +
                Buffer.from(`${node.client_id}:${node.client_secret}`).toString(
                  "base64"
                ),
              'Content-Type': 'application/x-www-form-urlencoded',
              'Accept': 'application/json'
            },
            form: {
              'grant_type': node.grant_type_auth,
              'scope': node.scope
            }
          };
          if (node.grant_type_auth === "password") {
            options.form.username = node.username;
            options.form.password = node.password;
          };
        };
        delete msg.oauth2Request;



        // make a post request
        request(options, function (error, response) {
          try {
            if (error) {
              msg[node.container] = JSON.parse(JSON.stringify(error));
              node.status({
                fill: "red",
                shape: "dot",
                text: `ERR ${error.code}`
              });
            } else {
              msg[node.container] = JSON.parse(response.body ? response.body : JSON.stringify("{}"));
              msg["headers"] = {
                "Authorization": msg[node.container].token_type + " " + msg[node.container].access_token
              };
              if (response.statusCode === 200) {
                node.status({
                  fill: "green",
                  shape: "dot",
                  text: `HTTP ${response.statusCode}, ok`,
                });
              } else {
                node.status({
                  fill: "yellow",
                  shape: "dot",
                  text: `HTTP ${response.statusCode}, nok`,
                });
              };
            }
          } catch (e) {
            msg[node.container] = response;
            msg.error = e;
            node.status({
              fill: "red",
              shape: "dot",
              text: `HTTP ${response.statusCode}, nok`,
            });
          };
          node.send(msg);
        });
      });
    } else {
      if (n.grant_type_auth === "authorisation_code") {
        if (!this.openid || !this.openid.credentials.access_token) {
          this.warn(RED._('openid.warn.missing-credentials'))
          return
        }
        let issuer = null
        Issuer.discover(this.openid.credentials.discovery_url).then(iss => {
          issuer = iss
        }, err => {
          this.error(RED._('openid.error.bad-discovery_url'))
          console.log('Discover error %j', err)
          return
        })


        this.on('input', msg => {
          // Refresh the access token if expired
          console.log(this);
          const paragraph = this.openid.credentials.redirect_uri;
          const regex = ".+?(?=openid-credentials\/auth)";
          const found = paragraph.match(regex);
          console.log(found[0]);
          linkAutorizare = found[0] + "openid-credentials/auth?id=" + this.openid.id + "&discovery=" + this.openid.credentials.discovery_url + "&clientId=" + this.openid.credentials.client_id + "&clientSecret=" + this.openid.credentials.client_secret + "&scopes=" + this.openid.credentials.scopes + "&nameOfId=" + this.openid.credentials.display_name + "&callback=" + found[0] + "openid-credentials%2Fauth%2Fcallback";
          const expires_at = this.openid.credentials.expires_at
          const now = new Date()
          now.setSeconds(now.getSeconds() + 30)
          const current_time = Math.floor(now.getTime() / 1000)
          let token_is_valid = Promise.resolve()
          console.log("token_is_valid promise resolve")
          if (current_time > expires_at) {
            console.log("current_Time > expires_at");
            this.status({
              fill: 'yellow',
              shape: 'dot',
              text: 'openid.status.refreshing'
            })
            // const refresh_token = this.openid.credentials.refresh_token
            const refresh_token = "gotoerror";
            const oidcClient = new issuer.Client(this.openid.credentials)
            token_is_valid = oidcClient.refresh(refresh_token).then(tokenSet => {
              this.openid.credentials.access_token = tokenSet.access_token
              this.openid.credentials.expires_at = tokenSet.expires_at
              RED.nodes.addCredentials(this.id, this.openid.credentials)
              return Promise.resolve()
            }, err => {
              this.error(RED._('openid.error.refresh-failed', {
                err: JSON.stringify(err)
              }))
              this.status({
                fill: 'red',
                shape: 'ring',
                text: 'openid.status.failed'
              })
              msg.payload = err
              msg.error = err
              this.send(msg)
              //copilas('start ' +"\"\" \"" + linkAutorizare +"\"");
              // linkAutorizare = "empty";
              return Promise.reject(err)
            })
          }

          token_is_valid.then(() => {
            console.log("token_is_valid then");
            delete msg.error
            msg.access_token = this.openid.credentials.access_token
            const headers = msg.headers || {}
            headers['Authorization'] = `Bearer ${msg.access_token}`
            msg.headers = headers
            this.status({})
            this.send(msg)
          })
        })
      }
    }
  }

  RED.nodes.registerType('openid', OpenIDRequestNode)
}