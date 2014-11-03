(function() {



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
                mode : this.modem,
                apiAuthMode : this.apiAuthMode
            }
        };

     
        this.setFormLoginUrl = function(url) {
            this.formLoginUrl = url;
        };


        this.setTokenUrl = function(url) {
            this.tokenUrl = url;
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


    .factory('urdaService', ['$rootScope',  '$http', '$q', 'AUTH_EVENTS', 'urdaSession', 'urdaConfig', '$cookieStore',
                            '$window','$timeout','$location',
        function($rootScope, $http, $q, AUTH_EVENTS, urdaSession, urdaConfig, $cookieStore,$window,$timeout,$location){

        var svc = { };

        var loginUrl = urdaConfig.loginUrl;
        var tokenUrl = urdaConfig.tokenUrl;
        var servervaluesUrl = urdaConfig.servervaluesUrl;
        
        svc.csrfToken = null;

        
        var loginSuccess = function(){
            //This will attache a Token header to all requests. (django rest framework auth_token in backend)
            if(urdaConfig.apiAuthMode == 'token'){
                $http.defaults.headers.common["Authorization"] = "Token " + DrfSession.sessionData.token;
            }
            if(urdaConfig.apiAuthMode == 'session'){
                //#TODO: not implemented right now
                throw Error("Hey no session now...")
                //...probably we should put some interceptors. see: http://ionicframework.com/blog/angularjs-authentication/
                //$cookieStore.set(..something...)
            }
            // login success event is broadcasted
            $rootScope.$broadcast(AUTH_EVENTS.loginSuccess);
        };

        var loginError = function(){
            console.log("login error detected")
            urdaSession.destroy();
            $rootScope.$broadcast(AUTH_EVENTS.loginFailed);
        };

        
        var loginNeeded = function(){
          console.log("login missing (not authenticated)")
          urdaSession.destroy();
          $rootScope.$broadcast(AUTH_EVENTS.notAuthenticated);
        };



        var logout = function(){
            if(urdaConfig.apiAuthMode == 'token'){
                delete $http.defaults.headers.common["Authorization"];
                DrfSession.destroy();
                //$cookieStore.remove("sessionid");
            }
            if(urdaConfig.apiAuthMode == 'session'){
                //#TODO: not implemented right now
                throw Error("Hey no session now...")
                //$cookieStore.set(..something...)
                //$cookieStore.remove("sessionid");
            }

            $rootScope.$broadcast(AUTH_EVENTS.logoutSuccess);

        }
        

        var login = function (credentials) {
            return $http
                .post(loginUrl, credentials)
                .error(function(data){
                    loginError();
                })
                .then(function (res) {
                    DrfSession.create(res.data);
                    //console.log(DrfSession)
                    loginSuccess()
                    return res;
                });
        };


        var tokenLogin = function (credentials) {
            return $http
                .post(tokenUrl, credentials)
                .error(function(data){
                    loginError();
                })
                .then(function (res) {
                    DrfSession.create(res.data);
                    //console.log(DrfSession)
                    loginSuccess()
                    return res;
                });
        };


        var socialLogin = function (credentials) {
            //do the magic and return token
                socialAuthLogin.loginDjango(credentials.provider)
                .then(function (token) {
                    DrfSession.create({token:token });
                    //console.log(DrfSession)
                    loginSuccess()
                    return res;
                })
                .catch(function(err){
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
                    var token = input.val()
                    $http.defaults.headers.common["X-CSRFToken"]= token;
                    svc.csrfToken = token;
                    deferred.resolve(token)

                });

            return deferred.promise;
        }




        svc.login = function (credentials) {
            //console.log(1 , urdaConfig)
            
                
            if(urdaConfig.mode == 'social')  {
                  
                  return socialLogin(credentials);
            }
            if(urdaConfig.mode == 'token')  {
                  return tokenLogin(credentials);
            } 
            if(urdaConfig.mode == 'form' && !csrfToken){
                svc.getCrf().then(function(val){
                    credentials.csrfmiddlewaretoken = val;
                    return loginForm(credentials);                    
            });

            throw Error("mode must bu form, social or token") 
        };

        svc.logout = function () {
            return logout();
        } 
        
        svc.isAuthenticated = function () {
            //console.log(DrfSession.sessionData)
            return !!DrfSession.sessionData;
        };



        //#TODO: check it
        svc.checkRoute = function(next, toParams, event){
          if(next.auth){
              if(next.auth.requiresAuth){
                //console.log("xx, requires auth", next)
                if (!svc.isAuthenticated()) {
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


    }
])


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
}]);





/**
   * Private module, a utility, required internally by 'http-auth-interceptor'.
   */
  angular.module('http-auth-interceptor-buffer', [])

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

    


}())


}());
