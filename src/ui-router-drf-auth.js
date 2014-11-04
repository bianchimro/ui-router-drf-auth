

    angular.module("urda", [] )


    .constant('AUTH_EVENTS', {
        loginSuccess: 'auth-login-success',
        loginFailed: 'auth-login-failed',
        logoutSuccess: 'auth-logout-success',
        sessionTimeout: 'auth-session-timeout',
        notAuthenticated: 'auth-not-authenticated',
        notAuthorized: 'auth-not-authorized',

        // generic login required, should happen after a failed call
        // #TODO: not sure if to keep it
        loginRequired : 'auth-login-required'
    })

    .provider("urdaConfig", function() {

        this.loginUrl = null;
        this.tokenUrl = null;
        this.servervaluesUrl = null;

        /*
            direct: go to tokenUrl and get token/session
            social: login via socialLoginUrl and get token/session data
            form: login via formLoginUrl, to to tokenUrl and get token/session
        */
        this.mode = null;


        /*
            token
            session
        */
        this.apiAuthMode = null;



        this.$get = function() {
            var url = this.url;
            return {
                formLoginUrl : this.formLoginUrl,
                tokenUrl : this.tokenUrl,
                socialLoginUrl : this.socialLoginUrl,
                mode : this.mode,
                apiAuthMode : this.apiAuthMode,
                tokenVerifyUrl : this.tokenVerifyUrl,
            };
        };


        this.setFormLoginUrl = function(url) {
            this.formLoginUrl = url;
        };


        this.setTokenUrl = function(url) {
            this.tokenUrl = url;
        };

        this.setTokenVerifyUrl = function(url) {
            this.tokenVerifyUrl = url;
        };


        this.setSocialLoginUrl = function(url) {
            this.socialLoginUrl = url;
        };


        this.setMode = function(mode) {
            this.mode = mode;
        };


        this.setApiAuthMode = function(mode) {
            this.apiAuthMode = mode;
        };


    })

    
    .service('urdaSession', ['urdaConfig', function(urdaConfig){
        this.create = function (data) {
            this.sessionData = data;
        };

        this.destroy = function(){
            this.sessionData = null;
        };

    }])


    .factory('urdaService', ['$rootScope',  '$http', '$q', 'AUTH_EVENTS', 'urdaSession', 'urdaConfig','$window','$timeout','$location',
        function($rootScope, $http, $q, AUTH_EVENTS, urdaSession, urdaConfig,$window,$timeout,$location){

        var svc = { headers : [] };

        var loginUrl = urdaConfig.loginUrl;
        var tokenUrl = urdaConfig.tokenUrl;
        var socialLoginUrl = urdaConfig.socialLoginUrl;
        var tokenVerifyUrl = urdaConfig.tokenVerifyUrl;

        var servervaluesUrl = urdaConfig.servervaluesUrl;

        svc.csrfToken = null;


        var loginSuccess = function(){
          console.log("login success!")
            //This will attache a Token header to all requests. (django rest framework auth_token in backend)
            if(urdaConfig.apiAuthMode == 'token'){
                $http.defaults.headers.common.Authorization = "Token " + urdaSession.sessionData.token;
                localStorage.setItem("xxx-token", urdaSession.sessionData.token);
                svc.headers.push(['Authorization', "Token " + urdaSession.sessionData.token]) ;
            }
            if(urdaConfig.apiAuthMode == 'session'){
                //#TODO: not implemented right now
                throw Error("Hey no session now...");
                //...probably we should put some interceptors. see: http://ionicframework.com/blog/angularjs-authentication/
                //$cookieStore.set(..something...)
            }
            // login success event is broadcasted
            $rootScope.$broadcast(AUTH_EVENTS.loginSuccess);
        };

        var loginError = function(){
            console.log("login error detected");
            urdaSession.destroy();
            $rootScope.$broadcast(AUTH_EVENTS.loginFailed);
        };


        var loginNeeded = function(){
          console.log("login missing (not authenticated)");
          urdaSession.destroy();
          $rootScope.$broadcast(AUTH_EVENTS.notAuthenticated);
        };



        var logout = function(){
            if(urdaConfig.apiAuthMode == 'token'){
                
                delete $http.defaults.headers.common["Authorization"];
                urdaSession.destroy();
                svc.headers = [];
                localStorage.removeItem("xxx-token");
                //$cookieStore.remove("sessionid");
            }
            if(urdaConfig.apiAuthMode == 'session'){
                //#TODO: not implemented right now
                throw Error("Hey no session now...");
                //$cookieStore.set(..something...)
                //$cookieStore.remove("sessionid");
            }
            console.log(100)
            $rootScope.$broadcast(AUTH_EVENTS.logoutSuccess);
        };


        svc.openPop = function(url){
          
          var promise = new Promise(function(resolve, reject) {
      
            var w = window.open(url, "namedWindow","menubar=0,resizable=1,width=400,height=400");
            
            w.onload = function(){
              var lateHanlder = setTimeout(function(){
                reject(Error("It broke, too late"), 30000);
              });
            }

            var listener = window.addEventListener('message', function (event) {
                
                if(event.data.indexOf("token:") != 0){
                  return;
                }
                var token = event.data.split(":")[1];
                console.log("worked", token);
                //clearTimeout(lateHanlder);
                resolve(token);
            });

          });

          return promise;
        };



        svc.loginDjango = function(providerName){
          var authKey = Math.random() * 10000;
          var url = socialLoginUrl + providerName + "?authkey="+authKey + "&next=/popuptoken?authkey="+authKey;
          var promise = new Promise(function(resolve, reject) {

              svc.openPop(url)
              .then(function(res){
                console.log("wwwwo", res)
                  resolve(res);
              })
              .catch(function(err){
                console.error(err)
                  reject(err);
              })
          });

          return promise;
        };




        svc.loginViaToken = function(token){
          $http.defaults.headers.common.Authorization = "Token " + token;
          return $http
                .get(tokenVerifyUrl)
                .error(function(err){
                  console.error("tokenVerifyUrl err", err)
                    loginError();
                    localStorage.removeItem("xxx-token");
                })
                .then(function () {
                    console.log("ok, tokenVerifyUrl")
                    urdaSession.create({token:token});
                    //console.log(urdaSession)
                    loginSuccess();
                    return token;
                });

        }


        

        var tokenLogin = function (credentials) {
            return $http
                .post(tokenUrl, credentials)
                .error(function(data){
                    loginError();
                })
                .then(function (res) {
                    urdaSession.create(res.data);
                    //console.log(urdaSession)
                    loginSuccess();
                    return res;
                });
        };


        var socialLogin = function (credentials) {
            //do the magic and return token
            console.error("sl",credentials)
              svc.loginDjango(credentials.provider)
              .then(function (token) {
                  urdaSession.create({token:token });
                  //console.log(urdaSession)
                  loginSuccess(token);
                  return token;
              })
              .catch(function(err){
                console.error("x", err)
                  loginError();
              });
        };




        svc.getCrf = function(){
            var deferred = $q.defer();

             $http
                .get(loginUrl)
                .then(function(data){
                    var input = $(data.data).find("input[name='csrfmiddlewaretoken']");
                    if(!input.length){
                        return;
                    }
                    var token = input.val();
                    $http.defaults.headers.common["X-CSRFToken"]= token;
                    svc.csrfToken = token;
                    deferred.resolve(token);

                });

            return deferred.promise;
        };

        svc.login = function (credentials) {

            console.log(100, urdaConfig)
            if(urdaConfig.mode == 'social')  {

                  return socialLogin(credentials);
            }
            if(urdaConfig.mode == 'token')  {
                  return tokenLogin(credentials);
            }
            if(urdaConfig.mode == 'form' && !csrfToken){
                  svc.getCrf()
                  .then(function(val){
                    credentials.csrfmiddlewaretoken = val;
                    return loginForm(credentials);
                  });
            }
            throw Error("mode must be form, social or token");
        };

        svc.logout = function () {
            return logout();
        };

        svc.isAuthenticated = function () {
            //console.log(urdaSession.sessionData)
            return !!urdaSession.sessionData;
        };



        //#TODO: check it
        svc.checkRoute = function(next, toParams, event){
          console.log("check")
          if(next.auth){
              if(next.auth.requiresAuth){
                console.log("xx, requires auth", next)
                if (!svc.isAuthenticated()) {
                  console.error("hhh")
                  // user is not allowed
                  if(event){
                    event.preventDefault();
                  }

                  $rootScope.$broadcast(AUTH_EVENTS.notAuthenticated, next, toParams);
                }
              }

              var authorizedRoles = next.auth.authorizedRoles;
              if(authorizedRoles){
                if (!svc.isAuthorized(authorizedRoles)) {
                  if(event){
                    event.preventDefault();
                  }
                  if (svc.isAuthenticated()) {
                      // user is not allowed
                      $rootScope.$broadcast(AUTH_EVENTS.notAuthorized);
                  } else {
                    // user is not logged in
                    $rootScope.$broadcast(AUTH_EVENTS.notAuthenticated);
                  }
                }
              }
          }
        };


        //#TODO: check it
        svc.forceLoginRoute = function(next, toParams, event, excudedRoutes){
          if(excudedRoutes.indexOf(next.name) != -1){
            return;
          }
          if (!svc.isAuthenticated()) {
            // user is not allowed
            if(event){
              event.preventDefault();
            }

            $rootScope.$broadcast(AUTH_EVENTS.notAuthenticated, next, toParams);
            return false;
          }
          if(!next.auth){return true;}
          var authorizedRoles = next.auth.authorizedRoles;
          if(authorizedRoles){
            if (!svc.isAuthorized(authorizedRoles)) {
              if(event){
                event.preventDefault();
              }
              if (svc.isAuthenticated()) {
                  // user is not allowed
                  $rootScope.$broadcast(AUTH_EVENTS.notAuthorized);
              } else {
                // user is not logged in
                $rootScope.$broadcast(AUTH_EVENTS.notAuthenticated);
              }
            }
          }
        };
        return svc;
    }])




.config(['$httpProvider',  function($httpProvider) {

    $httpProvider.interceptors.push(['AUTH_EVENTS', '$rootScope', '$q', 'httpBuffer', function(AUTH_EVENTS, $rootScope, $q, httpBuffer) {
      return {
        responseError: function(rejection) {

            var statuses = {
                401: AUTH_EVENTS.notAuthenticated,
                403: AUTH_EVENTS.notAuthorized,
                419: AUTH_EVENTS.sessionTimeout,
                440: AUTH_EVENTS.sessionTimeout
            };
            var msg = statuses[rejection.status] || AUTH_EVENTS.loginRequired;
            $rootScope.$broadcast(msg, rejection);


          if (rejection.status === 401 && !rejection.config.ignoreAuthModule) {
            var deferred = $q.defer();
            httpBuffer.append(rejection.config, deferred);
            $rootScope.$broadcast(msg, rejection);
            return deferred.promise;
          }
          // otherwise, default behaviour
          return $q.reject(rejection);
        }
      };
    }]);
  


  }])





/**
   * Private module, a utility, required internally by 'http-auth-interceptor'.
   */
  

  .factory('httpBuffer', ['$injector', function($injector) {
    /** Holds all the requests, so they can be re-requested in future. */
    var buffer = [];

    /** Service initialized later because of circular dependency problem. */
    var $http;

    function retryHttpRequest(config, deferred) {
      function successCallback(response) {
        deferred.resolve(response);
      }
      function errorCallback(response) {
        deferred.reject(response);
      }
      $http = $http || $injector.get('$http');
      $http(config).then(successCallback, errorCallback);
    }

    return {
      /**
       * Appends HTTP request configuration object with deferred response attached to buffer.
       */
      append: function(config, deferred) {
        buffer.push({
          config: config,
          deferred: deferred
        });
      },

      /**
       * Abandon or reject (if reason provided) all the buffered requests.
       */
      rejectAll: function(reason) {
        if (reason) {
          for (var i = 0; i < buffer.length; ++i) {
            buffer[i].deferred.reject(reason);
          }
        }
        buffer = [];
      },

      /**
       * Retries all the buffered requests clears the buffer.
       */
      retryAll: function(updater) {
        for (var i = 0; i < buffer.length; ++i) {
          retryHttpRequest(updater(buffer[i].config), buffer[i].deferred);
        }
        buffer = [];
      }
    };
  }]);
