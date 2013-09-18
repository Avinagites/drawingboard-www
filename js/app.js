'use strict';
var dialogCtrls, resolvables;

resolvables = {};

dialogCtrls = {};
angular.module('config', []);

angular.module('fork', []);

angular.module('account', []);

angular.module('admin', []);

angular.module('dashboard', []);

angular.module('pages', []);

angular.module('platform', []);

angular.module('common', ['ui.route', 'config', 'fork', 'ngCookies', 'restangular', 'ui.bootstrap', 'ui.select2']);

angular.module('app', ['config', 'common', 'dashboard', 'admin', 'account', 'pages', 'platform']);

angular.element(document).ready(function() {
  return angular.bootstrap(document, ['app']);
});
angular.module('account').config([
  '$routeProvider', 'WardenProvider', function($routeProvider, WardenProvider) {
    return WardenProvider.simplify($routeProvider).set_template_prefix('views/account').omit_controller().when('login').when('register.member').when('register.vendor').when('forgot_password').when('reset_password/:userId/:token').when('account.email_confirmation/:userId/:token', {
      omitView: true,
      omitController: false
    });
  }
]);
angular.module('account').controller('AccountEmailConfirmationCtrl', [
  '$scope', '$routeParams', 'Auth', 'User', function($scope, $routeParams, Auth, User) {
    User.activate_with_token($routeParams.userId, $routeParams.token).then(function(authenticated) {
      $scope.notify_success('Your email has been verified');
      return Auth.create_session({
        user_type: authenticated.user_type,
        auth_id: authenticated.auth_id,
        auth_provider: authenticated.auth_provider,
        token: authenticated.token
      });
    }, function() {
      return $scope.notify_error('We are unable to activate this account.');
    });
    return $scope.$on('session:created', function(ev, user) {
      return $scope.attemptLogin().then((function() {
        return $scope.redirect_to("dashboard." + (user.user_type.toLowerCase()) + ".profile", {
          success: 'Please proceed to furnish your account information'
        });
      }), function() {
        return $scope.notify_error('Unable to log you in');
      });
    });
  }
]);
dialogCtrls.forgotPassword = [
  '$scope', 'dialog', function($scope, dialog) {
    return $scope.close = function(result) {
      return dialog.close(result);
    };
  }
];
dialogCtrls.login = [
  '$scope', 'dialog', '$dialog', '$timeout', function($scope, dialog, $dialog, $timeout) {
    $scope.close = function(result) {
      return dialog.close(result);
    };
    $scope.openRegisterDialog = function() {
      dialog.close();
      return $timeout(function() {
        return $dialog.dialog({
          controller: dialogCtrls.register
        }).open('dialogs/account.register.html');
      }, 500);
    };
    return $scope.openForgotPasswordDialog = function() {
      dialog.close();
      return $timeout(function() {
        return $dialog.dialog({
          controller: dialogCtrls.forgotPassword
        }).open('dialogs/account.forgot_password.html');
      }, 500);
    };
  }
];
dialogCtrls.register = [
  '$scope', 'dialog', function($scope, dialog) {
    return $scope.close = function(result) {
      return dialog.close(result);
    };
  }
];
angular.module('account').run([
  '$rootScope', 'Auth', '$q', 'SiteName', function($rootScope, Auth, $q, SiteName) {
    $rootScope.logout = function() {
      Auth.logout();
      $rootScope.$broadcast('logged_out');
      return $rootScope.redirect_to('', {
        success: 'You are logged out'
      });
    };
    $rootScope.attemptLogin = function(opts) {
      var authenticated, deferred;
      if (opts == null) {
        opts = {};
      }
      deferred = $q.defer();
      if (($rootScope.authenticated != null) && $rootScope.authenticated) {
        deferred.resolve($rootScope.current_user);
      } else {
        authenticated = Auth.user({
          delegate: true
        });
        authenticated.then((function(user) {
          $rootScope.current_user = user;
          $rootScope.authenticated = true;
          $rootScope.user_class = user.user_type;
          $rootScope.user_type = user.user_type.toLowerCase();
          if (typeof opts.successHandler === "function") {
            opts.successHandler(user);
          }
          return deferred.resolve(user);
        }), function() {
          $rootScope.current_user = null;
          $rootScope.authenticated = false;
          $rootScope.user_class = 'User';
          $rootScope.user_type = 'guest';
          if (typeof opts.failedHandler === "function") {
            opts.failedHandler(user);
          }
          return deferred.reject('user is not logged in');
        });
      }
      return deferred.promise;
    };
    angular.forEach(['logged_out', 'login:started'], function(event) {
      return $rootScope.$on(event, function() {
        $rootScope.current_user = null;
        $rootScope.authenticated = false;
        $rootScope.user_class = 'User';
        return $rootScope.user_type = 'guest';
      });
    });
    $rootScope.$on('authenticate:success', function(event, response) {
      return $rootScope.attemptLogin({
        successHandler: function(user) {
          var success_msg;
          success_msg = response.register ? "Welcome to " + SiteName + "!" : 'You are logged in!';
          return $rootScope.redirect_to("dashboard." + (user.user_type.toLowerCase()) + ".profile", {
            success: success_msg
          });
        }
      });
    });
    return $rootScope.attemptLogin();
  }
]);
angular.module('account').directive('forgotPasswordForm', [
  function() {
    return {
      restrict: 'EA',
      replace: true,
      scope: {},
      templateUrl: 'forms/account/forgot_password.form.html',
      controller: [
        '$scope', '$rootScope', '$routeParams', 'Auth', function($scope, $rootScope, $routeParams, Auth) {
          var init;
          $scope.hasError = function(input) {
            return !input.$valid && (input.$dirty || $scope.submitted);
          };
          $scope.submitForm = function() {
            $scope.submitted = true;
            if ($scope.form.$valid) {
              $rootScope.clear_notifications();
              return Auth.forgot_password('Member', $scope.email, 'local');
            } else {
              return $rootScope.notify_error('Please enter a valid email');
            }
          };
          init = function() {
            return $scope.submitted = false;
          };
          return init();
        }
      ]
    };
  }
]);
angular.module('account').directive('loginForm', [
  function() {
    return {
      restrict: 'EA',
      replace: true,
      scope: {},
      templateUrl: 'forms/account/login.form.html',
      controller: [
        '$scope', '$rootScope', '$routeParams', 'Auth', function($scope, $rootScope, $routeParams, Auth) {
          var init;
          $scope.hasError = function(input) {
            return !input.$valid && (input.$dirty || $scope.submitted);
          };
          $scope.loginAsMember = function() {
            $scope.submitted = true;
            if ($scope.form.$valid) {
              $rootScope.clear_notifications();
              return Auth.authenticate('Member', $scope.user.email, 'local', $scope.user.password);
            }
          };
          $scope.loginAsVendor = function() {
            $scope.submitted = true;
            if ($scope.form.$valid) {
              $rootScope.clear_notifications();
              return Auth.authenticate('Vendor', $scope.user.email, 'local', $scope.user.password);
            }
          };
          init = function() {
            return $scope.submitted = false;
          };
          return init();
        }
      ]
    };
  }
]);
angular.module('account').directive('registerMemberForm', [
  function() {
    return {
      restrict: 'EA',
      replace: true,
      scope: {},
      templateUrl: 'forms/account/register.member.form.html',
      controller: [
        '$scope', '$rootScope', '$routeParams', 'Auth', 'FormHandler', function($scope, $rootScope, $routeParams, Auth, FormHandler) {
          var init;
          $scope.hasError = function(input) {
            return !input.$valid && (input.$dirty || $scope.submitted);
          };
          $scope.submitForm = function() {
            var additional_fields;
            $scope.submitted = true;
            if ($scope.form.$valid) {
              $rootScope.clear_notifications();
              additional_fields = {
                first_name: $scope.user.first_name,
                last_name: $scope.user.last_name
              };
              return Auth.register('Member', $scope.user.email, 'local', $scope.user.email, $scope.user.password, additional_fields);
            } else {
              return FormHandler.validate($scope.form.$error);
            }
          };
          init = function() {
            return $scope.submitted = false;
          };
          return init();
        }
      ]
    };
  }
]);
angular.module('account').directive('registerVendorForm', [
  function() {
    return {
      restrict: 'EA',
      replace: true,
      scope: {},
      templateUrl: 'forms/account/register.vendor.form.html',
      controller: [
        '$scope', '$rootScope', '$routeParams', 'Service', 'FormHandler', 'Auth', function($scope, $rootScope, $routeParams, Service, FormHandler, Auth) {
          var init;
          $scope.submitForm = function() {
            var additional_fields, provider_fields;
            if ($scope.terms_and_conditions) {
              $scope.submitted = true;
              if ($scope.form.$valid) {
                $rootScope.clear_notifications();
                additional_fields = {
                  first_name: $scope.user.vendor.first_name,
                  last_name: $scope.user.vendor.last_name,
                  mobile: $scope.user.vendor.mobile,
                  phone: $scope.user.vendor.phone,
                  role: $scope.user.vendor.role,
                  mailing_address: $scope.user.vendor.mailing_address,
                  acra_no: $scope.user.vendor.acra_no
                };
                provider_fields = {
                  name: $scope.user.provider.name,
                  address: $scope.user.provider.address,
                  map_address: $scope.user.provider.map_address,
                  browse_description: $scope.user.provider.browse_description,
                  profile_description: $scope.user.provider.profile_description,
                  provider_pictures: $scope.user.provider.provider_pictures
                };
                provider_fields.service_ids = [];
                angular.forEach($scope.user.provider.checked_services, function(checked, id) {
                  if (checked) {
                    return provider_fields.service_ids.push(id);
                  }
                });
                return Auth.register_vendor($scope.user.vendor.email, 'local', $scope.user.vendor.email, $scope.user.vendor.password, additional_fields, provider_fields);
              } else {
                return FormHandler.validate($scope.form.$error);
              }
            } else {
              return $rootScope.notify_error('Please check that you have read the terms and conditions');
            }
          };
          init = function() {
            FormHandler.formify($scope);
            $scope.user = {
              vendor: {},
              provider: {
                provider_pictures: []
              }
            };
            FormHandler.handleImage($scope, 'provider_picture', $scope.user.provider.provider_pictures);
            $scope.user.provider.checked_services = {};
            return $scope.services = Service.all({
              order: 'created_at ASC'
            });
          };
          return init();
        }
      ]
    };
  }
]);

var __hasProp = {}.hasOwnProperty,
  __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

angular.module('account').factory('Member', [
  'Restangular', '$rootScope', '$filter', function(Restangular, $rootScope, $filter) {
    var Member, _ref;
    Member = (function(_super) {
      __extends(Member, _super);

      function Member() {
        _ref = Member.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      return Member;

    })(BaseModel);
    return new Member(Restangular, $rootScope, $filter, 'member', 'members');
  }
]);
var __hasProp = {}.hasOwnProperty,
  __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

angular.module('account').factory('User', [
  'Restangular', '$rootScope', '$filter', function(Restangular, $rootScope, $filter) {
    var User, _ref;
    User = (function(_super) {
      __extends(User, _super);

      function User() {
        _ref = User.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      User.prototype.get_from_account = function(user_type, auth_id, auth_provider) {
        this.before_operation({
          user_type: user_type,
          auth_id: auth_id,
          auth_provider: auth_provider
        });
        return Restangular.all('users').customGET('get_from_account', {
          user_type: user_type,
          auth_id: auth_id,
          auth_provider: auth_provider
        });
      };

      User.prototype.authenticate_with_token = function(session) {
        this.before_operation({
          session: session
        });
        return Restangular.all('users').customGET('authenticate_with_token', session);
      };

      User.prototype.register = function(user_type, auth_id, auth_provider, email, password, additional_fields) {
        var fields;
        fields = {
          user_type: user_type,
          auth_id: auth_id,
          auth_provider: auth_provider,
          email: email,
          password: password,
          additional_fields: additional_fields
        };
        this.before_operation(fields);
        return Restangular.all('users').customPOST('register', {}, {}, fields);
      };

      User.prototype.authenticate = function(user_type, auth_id, auth_provider, password) {
        var fields;
        fields = {
          user_type: user_type,
          auth_id: auth_id,
          auth_provider: auth_provider,
          password: password
        };
        this.before_operation(fields);
        return Restangular.all('users').customGET('authenticate', fields);
      };

      User.prototype.activate_with_token = function(user_id, token) {
        var fields;
        fields = {
          token: token
        };
        this.before_operation(fields);
        return Restangular.one('users', user_id).customGET('activate_with_token', fields);
      };

      User.prototype.forgot_password = function(user_type, auth_id, auth_provider) {
        var fields;
        fields = {
          user_type: user_type,
          auth_id: auth_id,
          auth_provider: auth_provider
        };
        this.before_operation(fields);
        return Restangular.all('users').customPOST('forgot_password', {}, {}, fields);
      };

      User.prototype.reset_password_with_token = function(user_id, token, new_password) {
        var fields;
        fields = {
          token: token,
          new_password: new_password
        };
        console.log(fields);
        this.before_operation(fields);
        return Restangular.one('users', user_id).customPOST('reset_password_with_token', {}, {}, fields);
      };

      User.prototype.clear_notifications = function(user_id) {
        return Restangular.one('users', user_id).customPOST('clear_notifications', {}, {});
      };

      return User;

    })(BaseModel);
    return new User(Restangular, $rootScope, $filter, 'user', 'users');
  }
]);
resolvables['current_user'] = [
  'Auth', '$q', '$rootScope', function(Auth, $q, $rootScope) {
    var authenticated;
    authenticated = Auth.user({
      delegate: true
    });
    return authenticated.then((function(user) {
      $rootScope.current_user = user;
      $rootScope.authenticated = true;
      $rootScope.user_class = user.user_type;
      $rootScope.user_type = user.user_type.toLowerCase();
      return user;
    }), function() {
      $rootScope.current_user = null;
      $rootScope.authenticated = false;
      $rootScope.user_class = 'User';
      $rootScope.user_type = 'guest';
      $rootScope.notify_error('Please login first', false);
      return $q.reject('Access not allowed');
    });
  }
];
angular.module('account').service('Auth', [
  '$rootScope', '$http', 'ErrorProcessor', 'Session', 'User', 'Provider', '$q', function($rootScope, $http, ErrorProcessor, Session, User, Provider, $q) {
    this.create_session = function(authenticated) {
      Session.set(authenticated.user_type, authenticated.auth_id, authenticated.auth_provider, authenticated.token);
      $http.defaults.headers.common['User-Authorization'] = Session.as_json();
      console.log(authenticated);
      return $rootScope.$broadcast('session:created', authenticated);
    };
    this.user = function(options) {
      var promise;
      if (options == null) {
        options = {};
      }
      if (Session.isEmpty()) {
        return $q.reject('Session does not exist');
      } else {
        promise = this.authenticate_with_token(Session.attributes());
        if ((options.delegate != null) && options.delegate) {
          return promise;
        } else {
          return promise.then((function(user) {
            return user;
          }), function(response) {
            return ErrorProcessor.process_login(response);
          });
        }
      }
    };
    this.register = function(user_type, auth_id, auth_provider, email, password, additional_fields) {
      var _this = this;
      return User.register(user_type, auth_id, auth_provider, email, password, additional_fields).then((function(response) {
        if (response.email_confirmation) {
          return $rootScope.redirect_to('/', {
            info: 'An email has been sent to verify your email address.'
          });
        } else {
          return _this.authenticate(user_type, auth_id, auth_provider, password, true);
        }
      }), function(response) {
        console.log(response);
        return ErrorProcessor.process_registration(response);
      });
    };
    this.register_vendor = function(auth_id, auth_provider, email, password, additional_fields, provider_fields) {
      var _this = this;
      return User.register('Vendor', auth_id, auth_provider, email, password, additional_fields).then((function(response) {
        provider_fields.vendor_id = response.user.id;
        Provider.create(provider_fields);
        if (response.email_confirmation) {
          return $rootScope.notify_info('An email has been sent to verify your email address.');
        } else {
          return _this.authenticate('Vendor', auth_id, auth_provider, password, true);
        }
      }), function(response) {
        console.log(response);
        return ErrorProcessor.process_registration(response);
      });
    };
    this.authenticate = function(user_type, auth_id, auth_provider, password, register, opts) {
      var _this = this;
      if (password == null) {
        password = null;
      }
      if (register == null) {
        register = false;
      }
      if (opts == null) {
        opts = {};
      }
      Session.destroy();
      $rootScope.$broadcast('login:started');
      return User.authenticate(user_type, auth_id, auth_provider, password).then((function(authenticated) {
        _this.create_session(authenticated);
        $rootScope.$broadcast('authenticate:success', {
          authenticated: authenticated,
          register: register
        });
        return typeof opts.successHandler === "function" ? opts.successHandler(authenticated) : void 0;
      }), function(response) {
        ErrorProcessor.process_login(response);
        return typeof opts.errorHandler === "function" ? opts.errorHandler(response) : void 0;
      });
    };
    this.authenticate_with_token = function(session_attributes) {
      return User.authenticate_with_token(session_attributes);
    };
    this.logout = function() {
      return Session.destroy();
    };
    this.forgot_password = function(user_type, auth_id, auth_provider, opts) {
      if (opts == null) {
        opts = {};
      }
      return User.forgot_password(user_type, auth_id, auth_provider).then((function(success) {
        $rootScope.notify_success('An email has been sent to you to reset your password');
        return typeof opts.successHandler === "function" ? opts.successHandler(success) : void 0;
      }), function(response) {
        console.log(response);
        ErrorProcessor.process_forgot_password(response);
        return typeof opts.errorHandler === "function" ? opts.errorHandler(response) : void 0;
      });
    };
    return this;
  }
]);
angular.module('account').factory('CustomProvider', [
  'Auth', 'User', '$rootScope', 'MemoryStore', '$timeout', function(Auth, User, $rootScope, MemoryStore, $timeout) {
    var CustomProvider;
    CustomProvider = (function() {
      var authenticate_with_custom_provider, connectFailure, facebookCallback, linkedInCallback;

      function CustomProvider() {}

      connectFailure = function() {
        return $rootScope.notify_error('You need to authorize this app in order to log in');
      };

      authenticate_with_custom_provider = function(info) {
        return $timeout((function() {
          var promise;
          promise = User.get_from_account(info.user_class, info.auth_id, info.auth_provider);
          return promise.then(function() {
            MemoryStore.set('auth_info', info);
            return $rootScope.redirect_to("" + info.user_type + ".login.custom_provider");
          }, function() {
            MemoryStore.set('auth_info', info);
            return $rootScope.redirect_to("" + info.user_type + ".register.custom_provider");
          });
        }), 100);
      };

      facebookCallback = function(response, user_class, user_type) {
        if (response.authResponse) {
          return FB.api("/me", function(response) {
            var _ref;
            return authenticate_with_custom_provider({
              user_class: user_class,
              user_type: user_type,
              auth_id: response.id,
              auth_provider: 'facebook',
              email: response.email,
              additional_fields: {
                first_name: response.first_name,
                last_name: response.last_name,
                location: (_ref = response.location) != null ? _ref.name : void 0,
                photo_url: "http://graph.facebook.com/" + response.id + "/picture"
              }
            });
          });
        } else {
          return connectFailure();
        }
      };

      linkedInCallback = function(user_class, user_type) {
        return IN.API.Profile('me').fields('id', 'email-address', 'first-name', 'last-name', 'location', 'summary', 'specialties', 'positions', 'picture-url', 'public-profile-url', 'skills', 'certifications', 'educations', 'date-of-birth', 'three-current-positions').result(function(result) {
          var fields, _ref, _ref1, _ref2, _ref3, _ref4, _ref5, _ref6;
          fields = {
            user_class: user_class,
            user_type: user_type,
            auth_id: result.values[0].emailAddress,
            auth_provider: 'linkedin',
            email: result.values[0].emailAddress,
            additional_fields: {
              first_name: result.values[0].firstName,
              last_name: result.values[0].lastName,
              photo_url: result.values[0].pictureUrl,
              location: (_ref = result.values[0].location) != null ? _ref.name : void 0
            }
          };
          if (user_type === 'freelancer') {
            fields.additional_fields.job_title = (_ref1 = result.values[0].threeCurrentPositions) != null ? (_ref2 = _ref1.values) != null ? (_ref3 = _ref2[0]) != null ? _ref3.title : void 0 : void 0 : void 0;
            fields.additional_fields.professional_history = (_ref4 = result.values[0].threeCurrentPositions) != null ? (_ref5 = _ref4.values) != null ? (_ref6 = _ref5[0]) != null ? _ref6.summary : void 0 : void 0 : void 0;
            fields.additional_fields.other_information = result.values[0].summary;
          }
          IN.API.Raw('/people/~/picture-urls::(original)').result(function(res) {
            return fields.additional_fields.photo_url = res.values[0];
          });
          return authenticate_with_custom_provider(fields);
        });
      };

      CustomProvider.prototype.connect = function(providerName, user_class, user_type) {
        $rootScope.start_ajax();
        return $timeout(function() {
          var _ref;
          switch (providerName) {
            case 'facebook':
              return FB.login((function(response) {
                return facebookCallback(response, user_class, user_type);
              }), {
                scope: 'email, user_about_me, user_location, publish_actions'
              });
            case 'linkedin':
              if ((_ref = IN.User) != null ? _ref.isAuthorized() : void 0) {
                return linkedInCallback(user_class, user_type);
              } else {
                IN.User.authorize();
                return IN.Event.on(IN, 'auth', function() {
                  return linkedInCallback(user_class, user_type);
                });
              }
          }
        }, 100);
      };

      return CustomProvider;

    })();
    return new CustomProvider;
  }
]);
angular.module('account').factory('Session', [
  '$cookieStore', function($cookieStore) {
    var Session;
    Session = (function() {
      function Session() {
        this._init();
      }

      Session.prototype._init = function() {
        var loaded;
        loaded = $cookieStore.get('AuthSession');
        this.user_type = loaded != null ? loaded.user_type : void 0;
        this.auth_id = loaded != null ? loaded.auth_id : void 0;
        this.auth_provider = loaded != null ? loaded.auth_provider : void 0;
        return this.token = loaded != null ? loaded.token : void 0;
      };

      Session.prototype.attributes = function() {
        return {
          user_type: this.user_type,
          auth_id: this.auth_id,
          auth_provider: this.auth_provider,
          token: this.token
        };
      };

      Session.prototype.set = function(user_type, auth_id, auth_provider, token) {
        this.user_type = user_type;
        this.auth_id = auth_id;
        this.auth_provider = auth_provider;
        this.token = token;
        return $cookieStore.put('AuthSession', this.attributes());
      };

      Session.prototype.destroy = function() {
        this.user_type = null;
        this.auth_id = null;
        this.auth_provider = null;
        this.token = null;
        return $cookieStore.remove('AuthSession');
      };

      Session.prototype.as_json = function() {
        return JSON.stringify(this.attributes());
      };

      Session.prototype.isEmpty = function() {
        return this.as_json === '{}';
      };

      return Session;

    })();
    return new Session;
  }
]);
angular.module('admin').config([
  '$routeProvider', 'WardenProvider', function($routeProvider, WardenProvider) {
    return WardenProvider.simplify($routeProvider).set_template_prefix('views/admin').when('admin.login', {
      omitController: true
    }).when('admin.listing').when('admin.events').when('admin.users');
  }
]);
angular.module('admin').controller('AdminEventsCtrl', [
  '$scope', '$rootScope', 'Event', function($scope, $rootScope, Event) {
    return $scope.events = Event.all({
      order: 'updated_at DESC'
    });
  }
]);
angular.module('admin').controller('AdminListingCtrl', [
  '$scope', '$rootScope', 'Provider', function($scope, $rootScope, Provider) {
    $scope.providers = Provider.all({
      order: 'updated_at DESC'
    });
    return $scope.approve = function(provider) {
      provider.status = 'Approved';
      return Provider.approve(provider.id).then(function() {
        return $rootScope.notify_success('approved!');
      }, function() {
        return $rootScope.notify_error('Unable to approve listing');
      });
    };
  }
]);
angular.module('admin').controller('AdminUsersCtrl', [
  '$scope', '$rootScope', 'User', function($scope, $rootScope, User) {
    return $scope.users = User.all({
      order: 'updated_at DESC'
    });
  }
]);
angular.module('admin').directive('adminDashboardSidebar', [
  function() {
    return {
      restrict: 'EA',
      replace: true,
      templateUrl: 'partials/admin/admin_dashboard_sidebar.html'
    };
  }
]);
angular.module('admin').directive('adminLoginForm', [
  function() {
    return {
      restrict: 'EA',
      replace: true,
      scope: {},
      templateUrl: 'forms/admin/login.form.html',
      controller: [
        '$scope', '$rootScope', '$routeParams', 'Auth', function($scope, $rootScope, $routeParams, Auth) {
          var init;
          $scope.hasError = function(input) {
            return !input.$valid && (input.$dirty || $scope.submitted);
          };
          $scope.login = function() {
            $scope.submitted = true;
            if ($scope.form.$valid) {
              $rootScope.clear_notifications();
              return Auth.authenticate('Admin', $scope.user.email, 'local', $scope.user.password);
            }
          };
          init = function() {
            return $scope.submitted = false;
          };
          return init();
        }
      ]
    };
  }
]);
angular.module('account').config([
  '$routeProvider', '$locationProvider', function($routeProvider, $locationProvider) {
    $routeProvider.otherwise({
      redirectTo: '/home'
    });
    return $locationProvider.html5Mode(false);
  }
]);
angular.module('common').config([
  '$httpProvider', function($httpProvider) {
    var interceptor;
    interceptor = [
      "$q", "$injector", "$rootScope", function($q, $injector, $rootScope) {
        var error, success;
        success = function(response) {
          var $http;
          $http = $injector.get("$http");
          if ($http.pendingRequests.length < 1) {
            $rootScope.$broadcast('ajax_loading:stopped');
          }
          return response;
        };
        error = function(response) {
          var $http;
          $http = $injector.get("$http");
          if ($http.pendingRequests.length < 1) {
            $rootScope.$broadcast('ajax_loading:stopped');
          }
          return $q.reject(response);
        };
        return function(promise) {
          $rootScope.$broadcast('ajax_loading:started');
          return promise.then(success, error);
        };
      }
    ];
    return $httpProvider.responseInterceptors.push(interceptor);
  }
]);
angular.module('common').config([
  'RestangularProvider', 'ServiceEndpoint', function(RestangularProvider, ServiceEndpoint) {
    RestangularProvider.setBaseUrl(ServiceEndpoint);
    RestangularProvider.setListTypeIsArray(true);
    RestangularProvider.setFullRequestInterceptor(function(element, operation, route, url, headers, params) {
      var k, _i, _len, _ref;
      if ((element != null ? element._deny_fields : void 0) != null) {
        _ref = element._deny_fields;
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          k = _ref[_i];
          delete element[k];
        }
      }
      return {
        element: element,
        operation: operation,
        route: route,
        url: url,
        headers: headers,
        params: params
      };
    });
    return RestangularProvider.setResponseExtractor(function(response, operation) {
      return response;
    });
  }
]);
angular.module('common').directive('header', [
  function() {
    return {
      restrict: 'EA',
      replace: true,
      templateUrl: 'partials/common/header.html'
    };
  }
]);
angular.module('common').directive('serviceCategories', [
  function() {
    return {
      restrict: 'EA',
      replace: true,
      templateUrl: 'partials/common/service_categories.html'
    };
  }
]);
angular.module('common').directive('sidebar', [
  function() {
    return {
      restrict: 'EA',
      replace: true,
      templateUrl: 'partials/common/sidebar.html',
      controller: [
        '$scope', 'Service', function($scope, Service) {
          return $scope.services = Service.all({
            order: 'created_at ASC'
          });
        }
      ]
    };
  }
]);
angular.module('common').directive('spinner', [
  function() {
    return {
      restrict: 'E',
      replace: true,
      templateUrl: 'partials/common/spinner.html',
      controller: [
        '$scope', function($scope) {
          $scope.$on('ajax_loading:started', function() {
            return $scope.isLoading = true;
          });
          return $scope.$on('ajax_loading:stopped', function() {
            return $scope.isLoading = false;
          });
        }
      ],
      link: function() {
        var opts, target;
        opts = {
          lines: 12,
          length: 7,
          width: 5,
          radius: 10,
          color: "#fff",
          speed: 1,
          trail: 66,
          shadow: true,
          left: '78px',
          top: '78px'
        };
        target = document.getElementById("spin");
        return new Spinner(opts).spin(target);
      }
    };
  }
]);
angular.module('common').directive('tagsinput', [
  function() {
    return {
      restrict: 'A',
      require: '?ngModel',
      link: function(scope, element, attrs, ngModel) {
        var initialized, options, read;
        if (!ngModel) {
          return;
        }
        initialized = false;
        options = {
          onChange: function() {
            return read();
          }
        };
        read = function() {
          return ngModel.$setViewValue(element.val());
        };
        return ngModel.$render = function() {
          if (angular.isString(ngModel.$viewValue)) {
            element.val(ngModel.$viewValue);
            element.attr('value', ngModel.$viewValue);
          }
          if (!initialized) {
            element.tagsInput(options);
            return initialized = true;
          }
        };
      }
    };
  }
]);
angular.module('common').directive('alerter', [
  function() {
    return {
      restrict: 'E',
      replace: true,
      scope: {
        closeCountDown: '@'
      },
      controller: [
        '$scope', '$timeout', function($scope, $timeout) {
          var clearAlertTimeout, stack_topright;
          $scope.alerts = [];
          stack_topright = {
            dir1: "down",
            dir2: "left",
            push: "top",
            spacing1: 25,
            spacing2: 25,
            firstpos1: 125,
            firstpos2: 25
          };
          clearAlertTimeout = null;
          $scope.addAlert = function(type, message) {
            var alert, _alerts, _closeCountDown;
            _alerts = (function() {
              var _i, _len, _ref, _results;
              _ref = $scope.alerts;
              _results = [];
              for (_i = 0, _len = _ref.length; _i < _len; _i++) {
                alert = _ref[_i];
                _results.push(alert.msg);
              }
              return _results;
            })();
            if (_alerts.indexOf(message) >= 0) {
              return;
            }
            $scope.alerts.push({
              type: type,
              msg: message
            });
            $.pnotify({
              text: message,
              type: type,
              stack: stack_topright
            });
            if (clearAlertTimeout != null) {
              $timeout.cancel(clearAlertTimeout);
            }
            _closeCountDown = 3000;
            if (angular.isDefined($scope.closeCountDown)) {
              _closeCountDown = $scope.closeCountDown;
            }
            return clearAlertTimeout = $timeout((function() {
              return $scope.clearAlerts();
            }), _closeCountDown);
          };
          $scope.clearAlerts = function() {
            $scope.alerts = [];
            return $.pnotify_remove_all();
          };
          /* hook to notification event*/

          $scope.$on('notification:info', function(e, msg) {
            return $scope.addAlert('info', msg);
          });
          $scope.$on('notification:success', function(e, msg) {
            return $scope.addAlert('success', msg);
          });
          $scope.$on('notification:error', function(e, msg) {
            return $scope.addAlert('error', msg);
          });
          return $scope.$on('notification:clear', function() {
            return $scope.clearAlerts();
          });
        }
      ]
    };
  }
]);
angular.module('common').directive('fileupload', [
  function() {
    return {
      restrict: 'A',
      scope: {
        uploaderId: '@',
        serverDomain: '@',
        servicePath: '@'
      },
      link: function(scope, element, attrs) {
        var options;
        options = {
          url: "" + attrs.serverDomain + "/" + attrs.servicePath,
          dataType: 'json',
          add: function(e, data) {
            scope.$emit('fileupload:add', {
              id: attrs.uploaderId,
              domain: attrs.serverDomain,
              path: attrs.servicePath,
              data: data
            });
            return data.submit();
          },
          done: function(e, data) {
            return scope.$emit('fileupload:done', {
              id: attrs.uploaderId,
              domain: attrs.serverDomain,
              path: attrs.servicePath,
              data: data
            });
          },
          progress: function(e, data) {
            return scope.$emit('fileupload:progress', {
              id: attrs.uploaderId,
              domain: attrs.serverDomain,
              path: attrs.servicePath,
              data: data
            });
          },
          fail: function(e, data) {
            return scope.$emit('fileupload:fail', {
              id: attrs.uploaderId,
              domain: attrs.serverDomain,
              path: attrs.servicePath,
              data: data
            });
          }
        };
        return element.fileupload(options);
      }
    };
  }
]);
angular.module('common').directive("match", function() {
  return {
    require: "ngModel",
    scope: {
      match: "="
    },
    link: function(scope, element, attrs, ctrl) {
      return scope.$watch((function() {
        var combined;
        combined = void 0;
        if (scope.match || ctrl.$viewValue) {
          combined = scope.match + "_" + ctrl.$viewValue;
        }
        return combined;
      }), function(value) {
        if (value) {
          return ctrl.$parsers.unshift(function(viewValue) {
            var origin;
            origin = scope.match;
            if (origin !== viewValue) {
              ctrl.$setValidity("match", false);
              return undefined;
            } else {
              ctrl.$setValidity("match", true);
              return viewValue;
            }
          });
        }
      });
    }
  };
});
angular.module('common').directive('nailthumb', [
  function() {
    return {
      restrict: 'A',
      scope: {
        method: '@',
        width: '@',
        height: '@',
        replaceAnimation: '@',
        ngSrc: '@'
      },
      link: function(scope, element, attrs) {
        var options;
        options = {
          method: 'crop',
          width: '125',
          height: '125',
          replaceAnimation: 'fade'
        };
        if (attrs.method != null) {
          options.method = attrs.method;
        }
        if (attrs.width != null) {
          options.width = attrs.width;
        }
        if (attrs.height != null) {
          options.height = attrs.height;
        }
        if (attrs.replaceAnimation != null) {
          options.replaceAnimation = attrs.replaceAnimation;
        }
        return attrs.$observe('ngSrc', function() {
          return element.nailthumb(options);
        });
      }
    };
  }
]);
angular.module('common').run([
  '$rootScope', function($rootScope) {
    $rootScope.start_ajax = function() {
      return $rootScope.$broadcast('ajax_loading:started');
    };
    return $rootScope.stop_ajax = function() {
      return $rootScope.$broadcast('ajax_loading:stopped');
    };
  }
]);
angular.module('common').run([
  '$rootScope', '$log', function($rootScope, $log) {
    $rootScope.alert = function(msg) {
      return alert(msg);
    };
    $rootScope.log = function(msg) {
      return $log.log(msg);
    };
    $rootScope.warn = function(msg) {
      return $log.warn(msg);
    };
    return $rootScope.error = function(msg) {
      return $log.error(msg);
    };
  }
]);
angular.module('common').run([
  '$rootScope', function($rootScope) {
    $rootScope.notify_info = function(msg, append) {
      if (append == null) {
        append = false;
      }
      if (!append) {
        $rootScope.$broadcast('notification:clear');
      }
      return $rootScope.$broadcast('notification:info', msg);
    };
    $rootScope.notify_error = function(msg, append) {
      if (append == null) {
        append = true;
      }
      if (!append) {
        $rootScope.$broadcast('notification:clear');
      }
      return $rootScope.$broadcast('notification:error', msg);
    };
    $rootScope.notify_success = function(msg, append) {
      if (append == null) {
        append = false;
      }
      if (!append) {
        $rootScope.$broadcast('notification:clear');
      }
      return $rootScope.$broadcast('notification:success', msg);
    };
    return $rootScope.clear_notifications = function() {
      return $rootScope.$broadcast('notification:clear');
    };
  }
]);
angular.module('common').run([
  '$rootScope', '$location', function($rootScope, $location) {
    return $rootScope.redirect_to = function(path, options) {
      if (options == null) {
        options = {};
      }
      path = path.replace(/^\//, '');
      if (options.success != null) {
        $rootScope.notify_success(options.success);
      }
      if (options.info != null) {
        $rootScope.notify_info(options.info);
      }
      if (options.error != null) {
        $rootScope.notify_error(options.error);
      }
      return $location.path("/" + path);
    };
  }
]);
angular.module('common').run([
  '$rootScope', '$location', function($rootScope, $location) {
    $rootScope.$current_route = '/';
    return $rootScope.$on('$routeChangeSuccess', function() {
      return $rootScope.$current_route = $location.path();
    });
  }
]);
angular.module('common').run([
  '$rootScope', function($rootScope) {
    return $rootScope._ = _;
  }
]);
/*
Converts variable-esque naming conventions to something presentational, capitalized words separated by space.
@param {String} value The value to be parsed and prettified.
@param {String} [inflector] The inflector to use. Default: humanize.
@return {String}
@example {{ 'Here Is my_phoneNumber' | inflector:'humanize' }} => Here Is My Phone Number
{{ 'Here Is my_phoneNumber' | inflector:'underscore' }} => here_is_my_phone_number
{{ 'Here Is my_phoneNumber' | inflector:'variable' }} => hereIsMyPhoneNumber
*/

angular.module('common').filter('inflector', function() {
  var breakup, inflectors, ucwords;
  ucwords = function(text) {
    return text.replace(/^([a-z])|\s+([a-z])/g, function($1) {
      return $1.toUpperCase();
    });
  };
  breakup = function(text, separator) {
    return text.replace(/[A-Z]/g, function(match) {
      return separator + match;
    });
  };
  inflectors = {
    humanize: function(value) {
      return ucwords(breakup(value, " ").split("_").join(" "));
    },
    underscore: function(value) {
      return value.substr(0, 1).toLowerCase() + breakup(value.substr(1), "_").toLowerCase().split(" ").join("_");
    },
    variable: function(value) {
      value = value.substr(0, 1).toLowerCase() + ucwords(value.split("_").join(" ")).substr(1).split(" ").join("");
      return value;
    }
  };
  return function(text, inflector, separator) {
    if (inflector !== false && angular.isString(text)) {
      inflector = inflector || "humanize";
      return inflectors[inflector](text);
    } else {
      return text;
    }
  };
});
var BaseModel;

BaseModel = (function() {
  function BaseModel(Restangular, $rootScope, $filter, singularName, pluralName) {
    this.Restangular = Restangular;
    this.$rootScope = $rootScope;
    this.$filter = $filter;
    this.singularName = singularName;
    this.pluralName = pluralName;
    this.humanizedSingularName = this.$filter('inflector')(this.singularName, 'humanize');
    this.humanizedPluralName = this.$filter('inflector')(this.pluralName, 'humanize');
  }

  BaseModel.prototype.before_operation = function(event) {
    return this.$rootScope.$broadcast('ajax_loading:started');
  };

  BaseModel.prototype.operation_success = function(event) {
    return this.$rootScope.$broadcast('ajax_loading:stopped');
  };

  BaseModel.prototype.operation_failed = function(event) {
    return this.$rootScope.$broadcast('ajax_loading:stopped');
  };

  BaseModel.prototype.create = function(model, options) {
    var opts, promise,
      _this = this;
    if (options == null) {
      options = {};
    }
    this.before_operation({
      model: model,
      options: options
    });
    promise = this.Restangular.all(this.pluralName).post(model);
    if ((options.delegate != null) && options.delegate) {
      return promise;
    } else {
      opts = {
        notify_success: true,
        notify_error: true
      };
      if (options.notify_success != null) {
        opts.notify_success = options.notify_success;
      }
      if (options.notify_error != null) {
        opts.notify_error = options.notify_error;
      }
      return promise.then((function(item) {
        _this.operation_success({
          item: item
        });
        if (opts.notify_success) {
          _this.$rootScope.notify_success("" + _this.humanizedSingularName + " created successfully");
        }
        return item;
      }), function(response) {
        _this.operation_failed({
          response: response,
          model: model,
          options: options
        });
        if (opts.notify_error) {
          _this.$rootScope.notify_error("Failed to create " + _this.humanizedSingularName);
        }
        console.log('@create error: ');
        return console.log(response);
      });
    }
  };

  BaseModel.prototype.count = function(options) {
    var promise, queries,
      _this = this;
    if (options == null) {
      options = {};
    }
    this.before_operation({
      options: options
    });
    queries = {};
    if (options.conditions != null) {
      queries.conditions = JSON.stringify(options.conditions);
    }
    if (options.search != null) {
      queries.search = options.search;
    }
    promise = this.Restangular.all(this.pluralName).customGET('count', queries);
    if ((options.delegate != null) && options.delegate) {
      return promise;
    } else {
      return promise.then((function(count) {
        _this.operation_success({
          count: count
        });
        return count;
      }), function(response) {
        _this.operation_failed({
          response: response,
          options: options
        });
        console.log('@count error:');
        return console.log(response);
      });
    }
  };

  BaseModel.prototype.all = function(options) {
    var promise, queries,
      _this = this;
    if (options == null) {
      options = {};
    }
    this.before_operation({
      options: options
    });
    queries = {
      limit: 1000,
      offset: 0,
      order: 'updated_at DESC',
      page: 1,
      per_page: 100
    };
    if (options.limit != null) {
      queries.limit = options.limit;
    }
    if (options.offset != null) {
      queries.offset = options.offset;
    }
    if (options.order != null) {
      queries.order = options.order;
    }
    if (options.page != null) {
      queries.page = options.page;
    }
    if (options.per_page != null) {
      queries.per_page = options.per_page;
    }
    if (options.includes != null) {
      queries.includes = JSON.stringify(options.includes);
    }
    if (options.conditions != null) {
      queries.conditions = JSON.stringify(options.conditions);
    }
    if (options.search != null) {
      queries.search = options.search;
    }
    promise = this.Restangular.all(this.pluralName).getList(queries);
    if ((options.delegate != null) && options.delegate) {
      return promise;
    } else {
      return promise.then((function(list) {
        _this.operation_success({
          list: list
        });
        return list;
      }), function(response) {
        _this.operation_failed({
          response: response,
          options: options
        });
        console.log('@all error:');
        return console.log(response);
      });
    }
  };

  BaseModel.prototype.find = function(id, options) {
    var promise, queries,
      _this = this;
    if (options == null) {
      options = {};
    }
    this.before_operation({
      id: id,
      options: options
    });
    queries = {};
    if (options.includes != null) {
      queries.includes = JSON.stringify(options.includes);
    }
    promise = this.Restangular.one(this.pluralName, id).get(queries);
    if ((options.delegate != null) && options.delegate) {
      return promise;
    } else {
      return promise.then((function(item) {
        _this.operation_success({
          item: item
        });
        return item;
      }), function(response) {
        _this.operation_failed({
          response: response
        });
        _this.$rootScope.notify_error("Unable to find " + _this.humanizedSingularName);
        console.log('@find error');
        return console.log(response);
      });
    }
  };

  BaseModel.prototype.destroy = function(id, options) {
    var promise,
      _this = this;
    if (options == null) {
      options = {};
    }
    this.before_operation({
      id: id,
      options: options
    });
    console.log(id);
    console.log(this.Restangular.one(this.pluralName, id).remove);
    promise = this.Restangular.one(this.pluralName, id).remove();
    if ((options.delegate != null) && options.delegate) {
      return promise;
    } else {
      return promise.then((function(item) {
        return _this.operation_success({
          item: item
        });
      }), function(response) {
        _this.operation_failed({
          response: response
        });
        _this.$rootScope.notify_error("Unable to delete " + _this.humanizedSingularName);
        console.log('@destroy error');
        return console.log(response);
      });
    }
  };

  return BaseModel;

})();
angular.module('common').provider('Warden', function() {
  var Warden;
  Warden = (function() {
    function Warden() {}

    Warden.prototype.$get = function() {};

    Warden.prototype.simplify = function(routeProvider) {
      this.routeProvider = routeProvider;
      this.requireUser = false;
      this.omitView = false;
      this.omitController = false;
      return this;
    };

    Warden.prototype.set_template_prefix = function(prefix) {
      this.templatePrefix = prefix;
      if (prefix.slice(-1) !== '/') {
        this.templatePrefix += '/';
      }
      return this;
    };

    Warden.prototype.require_user = function() {
      this.requireUser = true;
      return this;
    };

    Warden.prototype.omit_view = function() {
      this.omitView = true;
      return this;
    };

    Warden.prototype.omit_controller = function() {
      this.omitController = true;
      return this;
    };

    Warden.prototype.when = function(route, options) {
      var cleanRoute, controller, controllerTokens, resolve, resolves, routeStr, templateUrl, token, _i, _len, _ref;
      if (options == null) {
        options = {};
      }
      if (route.slice(0, 1) === '/') {
        route = route.slice(1);
      }
      cleanRoute = route.split('/')[0];
      controllerTokens = (function() {
        var _i, _len, _ref, _results;
        _ref = cleanRoute.split(/\.|_/);
        _results = [];
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          token = _ref[_i];
          _results.push(token.capitalize());
        }
        return _results;
      })();
      routeStr = options.route || ("/" + route);
      controller = "" + (controllerTokens.join('')) + "Ctrl";
      templateUrl = "" + this.templatePrefix + cleanRoute + ".html";
      resolves = {};
      if (options.user == null) {
        options.user = this.requireUser;
      }
      if (options.omitView == null) {
        options.omitView = this.omitView;
      }
      if (options.omitController == null) {
        options.omitController = this.omitController;
      }
      if (options.user) {
        resolves.current_user = resolvables['current_user'];
      }
      if (options.resolves != null) {
        _ref = options.resolves;
        for (_i = 0, _len = _ref.length; _i < _len; _i++) {
          resolve = _ref[_i];
          resolves[resolve] = resolvables[resolve];
        }
      }
      if (options.omitView) {
        templateUrl = 'views/pages/empty.html';
      }
      if (options.templateUrl != null) {
        templateUrl = options.templateUrl;
      }
      if (options.omitController) {
        this.routeProvider.when(routeStr, {
          templateUrl: templateUrl,
          resolve: resolves
        });
      } else {
        this.routeProvider.when(routeStr, {
          templateUrl: templateUrl,
          controller: controller,
          resolve: resolves
        });
      }
      return this;
    };

    return Warden;

  })();
  return new Warden;
});
angular.module('common').service('ErrorProcessor', [
  '$rootScope', '$log', function($rootScope, $log) {
    this.process_save = function(response, defaultHandler) {
      var error, error_list, field, _ref, _results;
      switch (response.status) {
        case 422:
          _ref = response.data;
          _results = [];
          for (field in _ref) {
            error_list = _ref[field];
            _results.push((function() {
              var _i, _len, _results1;
              _results1 = [];
              for (_i = 0, _len = error_list.length; _i < _len; _i++) {
                error = error_list[_i];
                $log.error(error);
                _results1.push($rootScope.notify_error("" + field + " " + error));
              }
              return _results1;
            })());
          }
          return _results;
          break;
        default:
          if (defaultHandler != null) {
            return defaultHandler();
          } else {
            return $rootScope.notify_error('Unable to complete your request. Please contact the administrator.');
          }
      }
    };
    this.process_login = function(response, defaultHandler) {
      switch (response.status) {
        case 401:
          if ("message" in response.data) {
            return $rootScope.notify_error(response.data.message);
          }
          break;
        default:
          if (defaultHandler != null) {
            return defaultHandler();
          } else {
            return $rootScope.notify_error('Sorry, we are unable to log you in. Please contact the administrator.');
          }
      }
    };
    this.process_registration = function(response, defaultHandler) {
      switch (response.status) {
        case 401:
          if ("message" in response.data) {
            return $rootScope.notify_error(response.data.message);
          }
          break;
        default:
          if (defaultHandler != null) {
            return defaultHandler();
          } else {
            return $rootScope.notify_error('Sorry, we are unable to proceed with registration. Please contact the administrator.');
          }
      }
    };
    this.process_forgot_password = function(response, defaultHandler) {
      switch (response.status) {
        case 401:
          if ("message" in response.data) {
            return $rootScope.notify_error(response.data.message);
          }
          break;
        default:
          if (defaultHandler != null) {
            return defaultHandler();
          } else {
            return $rootScope.notify_error('Sorry, we are unable to reset your password. Please contact the administrator');
          }
      }
    };
    return this;
  }
]);
angular.module('common').service('FormHandler', [
  '$rootScope', function($rootScope) {
    this.formify = function(scope) {
      scope.submitted = false;
      scope.form_object = {};
      scope.hasError = function(input) {
        return !input.$valid && (input.$dirty || scope.submitted);
      };
      return scope.removeAssoc = function(assoc, index) {
        if (assoc[index].id != null) {
          return assoc[index]._destroy = true;
        } else {
          return assoc.splice(index, 1);
        }
      };
    };
    this.validate = function(form_errors) {
      window.scrollTo(0);
      return angular.forEach(form_errors, function(val, key) {
        return angular.forEach(val, function(inner_val) {
          var _ref;
          switch (key) {
            case 'required':
              if (inner_val.$error.required === true) {
                if (inner_val.$name != null) {
                  return $rootScope.notify_error("" + ((_ref = inner_val.$name) != null ? _ref.humanize() : void 0) + " is missing.");
                }
              } else if (angular.isArray(inner_val.$error.required)) {
                if (inner_val.$error.required[0].$name != null) {
                  return $rootScope.notify_error("" + (inner_val.$error.required[0].$name.humanize()) + " is missing");
                }
              }
              break;
            case 'email':
              if (inner_val.$error.email === true) {
                if (inner_val.$viewValue != null) {
                  return $rootScope.notify_error("" + inner_val.$viewValue + " is not a valid email.");
                }
              } else if (angular.isArray(inner_val.$error.email)) {
                if (inner_val.$error.email[0].$viewValue != null) {
                  return $rootScope.notify_error("" + inner_val.$error.email[0].$viewValue + " is not a valid email.");
                }
              }
              break;
            case 'url':
              if (inner_val.$error.url === true) {
                if (inner_val.$viewValue != null) {
                  return $rootScope.notify_error("" + inner_val.$viewValue + " is not a valid url.");
                }
              } else if (angular.isArray(inner_val.$error.url)) {
                if (inner_val.$error.url[0].$viewValue != null) {
                  return $rootScope.notify_error("" + inner_val.$error.url[0].$viewValue + " is not a valid url.");
                }
              }
          }
        });
      });
    };
    this.handleImage = function(scope, uploader_id, receiver, uploading_msg, upload_failed_msg) {
      if (uploading_msg == null) {
        uploading_msg = "Uploading..";
      }
      if (upload_failed_msg == null) {
        upload_failed_msg = "Failed to upload picture.";
      }
      scope.$on('fileupload:add', function(e, data) {
        return scope.$apply(function() {
          switch (data.id) {
            case uploader_id:
              return scope["" + uploader_id + "_state"] = uploading_msg;
          }
        });
      });
      scope.$on('fileupload:done', function(e, data) {
        return scope.$apply(function() {
          var avatar_url, thumb_url, url, _ref, _ref1, _ref2, _ref3, _ref4, _ref5, _ref6, _ref7, _ref8;
          url = (_ref = data.data.result) != null ? (_ref1 = _ref.data) != null ? (_ref2 = _ref1.content) != null ? _ref2.url : void 0 : void 0 : void 0;
          avatar_url = (_ref3 = data.data.result) != null ? (_ref4 = _ref3.data) != null ? (_ref5 = _ref4.avatar) != null ? _ref5.url : void 0 : void 0 : void 0;
          thumb_url = (_ref6 = data.data.result) != null ? (_ref7 = _ref6.data) != null ? (_ref8 = _ref7.thumb) != null ? _ref8.url : void 0 : void 0 : void 0;
          if (url != null) {
            switch (data.id) {
              case uploader_id:
                scope["" + uploader_id + "_state"] = '';
                return receiver.push({
                  url: data.domain + url,
                  avatar_url: data.domain + avatar_url,
                  thumb_url: data.domain + thumb_url
                });
            }
          }
        });
      });
      return scope.$on('fileupload:failed', function() {
        return $rootScope.notify_error(upload_failed_msg, false);
      });
    };
    return this;
  }
]);
/*
  Memory store serves to persist data across ng-view switches, it does not persist data in cookie or localStorage
  Usage for this can be reset password, passing data from one controller to another.
*/

angular.module('common').service('MemoryStore', [
  function() {
    var data;
    data = {};
    this.set = function(key, value) {
      return data[key] = value;
    };
    this.get = function(key) {
      return data[key];
    };
    this.del = function(key) {
      return delete data[key];
    };
    this.inspect = function() {
      return data;
    };
    this.clear = function() {
      return data = {};
    };
    return this;
  }
]);
angular.module('config').constant('SiteName', 'DrawingBoard');

angular.module('config').constant('ServiceEndpoint', 'http://162.243.15.77\:3000');
angular.module('dashboard').controller('DashboardMemberCartCtrl', [
  '$scope', 'Cart', function($scope, Cart) {
    $scope.cart = Cart.get();
    $scope.remove = function(service_name, provider_id) {
      return Cart.remove(service_name, provider_id);
    };
    return $scope.lengthOfHash = function(hash) {
      return Object.keys(hash).length - 1;
    };
  }
]);
angular.module('dashboard').controller('DashboardMemberCheckoutCtrl', [
  '$scope', 'Cart', '$routeParams', 'FormHandler', 'Event', function($scope, Cart, $routeParams, FormHandler, Event) {
    var init;
    $scope.remove = function(service_name, provider_id) {
      return Cart.remove(service_name, provider_id);
    };
    $scope.lengthOfHash = function(hash) {
      return Object.keys(hash).length - 1;
    };
    $scope.saveForm = function() {
      var promise, success_msg;
      $scope.submitted = true;
      if ($scope.terms_and_conditions) {
        if ($scope.form.$valid) {
          $scope.clear_notifications();
          promise = Event.save_form($scope.form_object);
          success_msg = 'Your event details are updated successfully';
          return promise.then((function(object) {
            return $scope.redirect_to("dashboard.member.events", {
              success: success_msg
            });
          }), function() {
            return $scope.notify_error('Form has missing or invalid values');
          });
        } else {
          return FormHandler.validate($scope.form.$error);
        }
      } else {
        return $scope.notify_info('Please check that you have read the terms and conditions');
      }
    };
    $scope.submitForm = function() {
      var promise, success_msg;
      $scope.submitted = true;
      if ($scope.terms_and_conditions) {
        if ($scope.form.$valid) {
          $scope.clear_notifications();
          promise = Event.submit_form($scope.form_object);
          success_msg = 'Your request has been submitted.';
          return promise.then((function(object) {
            return $scope.redirect_to("dashboard.member.events", {
              success: success_msg
            });
          }), function() {
            return $scope.notify_error('Form has missing or invalid values');
          });
        } else {
          return FormHandler.validate($scope.form.$error);
        }
      } else {
        return $scope.notify_info('Please check that you have read the terms and conditions');
      }
    };
    init = function() {
      FormHandler.formify($scope);
      return Event.find($routeParams.event_id).then(function(obj) {
        $scope.form_object = obj;
        $scope.form_object.cart = Cart.get();
        $scope.form_object.contact_email = $scope.current_user.email;
        if (angular.isUndefined($scope.form_object.questions)) {
          return $scope.form_object.questions = {};
        }
      });
    };
    return init();
  }
]);
angular.module('dashboard').controller('DashboardMemberProfileCtrl', [
  '$scope', '$rootScope', 'FormHandler', function($scope, $rootScope, FormHandler) {
    var init;
    $scope.hasError = function(input) {
      return !input.$valid && (input.$dirty || $scope.submitted);
    };
    $scope.submitForm = function() {
      $scope.submitted = true;
      if ($scope.form.$valid) {
        $scope.clear_notifications();
        return $rootScope.current_user.put().then((function(current_user) {
          $rootScope.current_user = current_user;
          return $scope.notify_success('Your profile is updated successfully');
        }), function() {
          window.scrollTo(0);
          return $scope.notify_error('Form has missing or invalid values');
        });
      } else {
        return FormHandler.validate($scope.form.$error);
      }
    };
    init = function() {
      return $scope.submitted = false;
    };
    return init();
  }
]);
angular.module('dashboard').controller('DashboardVendorProfileCtrl', [
  '$scope', '$rootScope', 'FormHandler', function($scope, $rootScope, FormHandler) {
    var init;
    $scope.hasError = function(input) {
      return !input.$valid && (input.$dirty || $scope.submitted);
    };
    $scope.submitForm = function() {
      $scope.submitted = true;
      if ($scope.form.$valid) {
        $scope.clear_notifications();
        return $rootScope.current_user.put().then((function(current_user) {
          $rootScope.current_user = current_user;
          return $scope.notify_success('Your profile is updated successfully');
        }), function() {
          window.scrollTo(0);
          return $scope.notify_error('Form has missing or invalid values');
        });
      } else {
        return FormHandler.validate($scope.form.$error);
      }
    };
    init = function() {
      return $scope.submitted = false;
    };
    return init();
  }
]);
angular.module('dashboard').config([
  '$routeProvider', 'WardenProvider', function($routeProvider, WardenProvider) {
    return WardenProvider.simplify($routeProvider).set_template_prefix('views/dashboard').require_user().when('dashboard.vendor.listing', {
      omitController: true
    }).when('dashboard.vendor.profile').when('dashboard.member.events', {
      omitController: true
    }).when('dashboard.member.cart').when('dashboard.member.checkout/:event_id').when('dashboard.member.profile').when('listing.new', {
      omitController: true
    }).when('listing.edit/:id', {
      omitController: true
    }).when('event.new', {
      omitController: true
    }).when('event.edit/:id', {
      omitController: true
    });
  }
]);
angular.module('dashboard').directive('eventForm', [
  function() {
    return {
      restrict: 'EA',
      replace: true,
      scope: {
        type: '@',
        user: '='
      },
      templateUrl: 'forms/dashboard/event.form.html',
      controller: [
        '$scope', '$rootScope', '$routeParams', 'FormHandler', 'Event', function($scope, $rootScope, $routeParams, FormHandler, Entity) {
          var init;
          $scope.submitForm = function() {
            var promise, success_msg;
            $scope.submitted = true;
            if ($scope.form.$valid) {
              $rootScope.clear_notifications();
              switch ($scope.type) {
                case 'new':
                  promise = Entity.create($scope.form_object, {
                    notify_success: false
                  });
                  success_msg = 'Event has been submitted';
                  break;
                case 'edit':
                  promise = $scope.form_object.put();
                  success_msg = 'Your event is updated successfully';
              }
              return promise.then((function(object) {
                return $rootScope.redirect_to("dashboard.member.events", {
                  success: success_msg
                });
              }), function() {
                return $rootScope.notify_error('Form has missing or invalid values');
              });
            } else {
              return FormHandler.validate($scope.form.$error);
            }
          };
          init = function() {
            FormHandler.formify($scope);
            switch ($scope.type) {
              case 'new':
                return $scope.form_object = {
                  member_id: $scope.user.id
                };
              case 'edit':
                return Entity.find($routeParams.id).then(function(obj) {
                  return $scope.form_object = obj;
                });
            }
          };
          return init();
        }
      ]
    };
  }
]);
angular.module('dashboard').directive('listingForm', [
  function() {
    return {
      restrict: 'EA',
      replace: true,
      scope: {
        type: '@',
        user: '='
      },
      templateUrl: 'forms/dashboard/listing.form.html',
      controller: [
        '$scope', '$rootScope', '$routeParams', 'FormHandler', 'Provider', 'Service', function($scope, $rootScope, $routeParams, FormHandler, Entity, Service) {
          var init;
          $scope.submitForm = function() {
            var promise, success_msg;
            $scope.submitted = true;
            if ($scope.terms_and_conditions) {
              if ($scope.form.$valid) {
                $rootScope.clear_notifications();
                $scope.form_object.service_ids = [];
                angular.forEach($scope.form_object.checked_services, function(checked, id) {
                  if (checked) {
                    return $scope.form_object.service_ids.push(id);
                  }
                });
                delete $scope.form_object.services;
                switch ($scope.type) {
                  case 'new':
                    promise = Entity.create($scope.form_object, {
                      notify_success: false
                    });
                    success_msg = 'Listing has been submitted';
                    break;
                  case 'edit':
                    promise = $scope.form_object.put();
                    success_msg = 'Your listing is updated successfully';
                }
                return promise.then((function(object) {
                  return $rootScope.redirect_to("dashboard.vendor.listing", {
                    success: success_msg
                  });
                }), function() {
                  return $rootScope.notify_error('Form has missing or invalid values');
                });
              } else {
                return FormHandler.validate($scope.form.$error);
              }
            } else {
              return $rootScope.notify_info('Please check that you have read the terms and conditions');
            }
          };
          init = function() {
            FormHandler.formify($scope);
            $scope.services = Service.all();
            switch ($scope.type) {
              case 'new':
                $scope.form_object = {
                  vendor_id: $scope.user.id,
                  provider_pictures: [],
                  checked_services: {}
                };
                return FormHandler.handleImage($scope, 'provider_picture', $scope.form_object.provider_pictures);
              case 'edit':
                return Entity.find($routeParams.id).then(function(obj) {
                  $scope.form_object = obj;
                  $scope.form_object.checked_services = {};
                  angular.forEach(obj.services, function(input) {
                    return $scope.form_object.checked_services[input.id] = true;
                  });
                  return FormHandler.handleImage($scope, 'provider_picture', $scope.form_object.provider_pictures);
                });
            }
          };
          return init();
        }
      ]
    };
  }
]);
angular.module('pages').controller('ContactCtrl', [
  '$scope', 'Mailer', function($scope, Mailer) {
    return $scope.submitForm = function() {
      console.log($scope.contact);
      return Mailer.contact_us($scope.contact).then(function() {
        return $scope.notify_success("Thank you for contacting us. We will get back to you shortly");
      });
    };
  }
]);
angular.module('pages').controller('HomeCtrl', [
  '$scope', function($scope) {
    return console.log('noop');
  }
]);
angular.module('pages').config([
  '$routeProvider', 'WardenProvider', function($routeProvider, WardenProvider) {
    return WardenProvider.simplify($routeProvider).set_template_prefix('views/pages').when('home').when('about', {
      omitController: true
    }).when('contact');
  }
]);
angular.module('pages').factory('Mailer', [
  'Restangular', '$rootScope', function(Restangular) {
    var Mailer;
    Mailer = (function() {
      function Mailer() {}

      Mailer.prototype.contact_us = function(form_values) {
        return Restangular.all('mailer').customPOST('contact_us', {
          form_values: form_values
        });
      };

      return Mailer;

    })();
    return new Mailer;
  }
]);
angular.module('platform').controller('ProviderCtrl', [
  '$scope', 'provider', 'service', '$modal', 'Cart', 'Review', function($scope, provider, service, $modal, Cart, Review) {
    var first, i, second;
    $scope.provider = provider;
    $scope.service = service;
    $scope.reviewFormOpened = false;
    $scope.provider_pictures_pairs = [];
    i = 0;
    while (i < $scope.provider.provider_pictures.length) {
      first = $scope.provider.provider_pictures[i];
      second = $scope.provider.provider_pictures[i + 1];
      $scope.provider_pictures_pairs.push([first, second]);
      i += 2;
    }
    $scope.all_reviews_count = Review.count();
    $scope.reviews = Review.all({
      conditions: {
        provider_id: provider.id
      }
    });
    $scope.populateReviews = function() {
      $scope.reviews = Review.all({
        conditions: {
          provider_id: provider.id
        }
      });
      return $scope.all_reviews_count = Review.count();
    };
    $scope.$on('repull_reviews', function() {
      return $scope.populateReviews();
    });
    $scope.openPictureDialog = function(url) {
      return $modal.open({
        templateUrl: 'dialogs/provider_picture.dialog.html',
        windowClass: 'modal-img modal',
        controller: [
          '$scope', '$modalInstance', function($scope, $modalInstance) {
            $scope.picture_url = url;
            return $scope.close = function() {
              return $modalInstance.close();
            };
          }
        ]
      });
    };
    return $scope.openQuoteDialog = function() {
      if ($scope.user_type === 'member') {
        return $modal.open({
          templateUrl: 'dialogs/choose_services.dialog.html',
          windowClass: 'modal',
          controller: [
            '$scope', '$modalInstance', function($scope, $modalInstance) {
              $scope.services = provider.services;
              $scope.selected_services = {};
              $scope.cancel = function() {
                return $modalInstance.close();
              };
              return $scope.confirm = function() {
                angular.forEach($scope.selected_services, function(checked, service) {
                  if (checked) {
                    return Cart.add(service, provider);
                  }
                });
                return $modalInstance.close();
              };
            }
          ]
        });
      } else {
        return $scope.notify_info('You need to login as member to request for quotes.');
      }
    };
  }
]);
angular.module('platform').controller('ServicesCtrl', [
  '$scope', 'service', '$modal', 'Cart', '$location', function($scope, service, $modal, Cart, $location) {
    $scope.service = service;
    $scope.openQuoteDialog = function(provider) {
      if ($scope.user_type === 'member') {
        return $modal.open({
          templateUrl: 'dialogs/choose_services.dialog.html',
          windowClass: 'modal',
          controller: [
            '$scope', '$modalInstance', function($scope, $modalInstance) {
              $scope.services = provider.services;
              console.log(provider);
              $scope.selected_services = {};
              $scope.cancel = function() {
                return $modalInstance.close();
              };
              return $scope.confirm = function() {
                angular.forEach($scope.selected_services, function(checked, service) {
                  if (checked) {
                    return Cart.add(service, provider);
                  }
                });
                console.log(Cart.get());
                return $modalInstance.close();
              };
            }
          ]
        });
      } else {
        return $scope.notify_info('You need to login as member to request for quotes.');
      }
    };
    return $scope.goToDetailsPage = function(provider_id) {
      if ($scope.user_type === 'member') {
        return $location.path("provider/" + provider_id + "/" + service.name);
      } else {
        return $scope.notify_info('You need to login as member first to view details and request for quotes');
      }
    };
  }
]);
angular.module("fork").constant("customRatingConfig", {
  max: 5,
  stateOn: null,
  stateOff: null
});

angular.module("fork").controller("CustomRatingController", [
  "$scope", "$attrs", "$parse", "customRatingConfig", function($scope, $attrs, $parse, ratingConfig) {
    this.maxRange = (angular.isDefined($attrs.max) ? $scope.$parent.$eval($attrs.max) : ratingConfig.max);
    this.stateOn = (angular.isDefined($attrs.stateOn) ? $scope.$parent.$eval($attrs.stateOn) : ratingConfig.stateOn);
    this.stateOff = (angular.isDefined($attrs.stateOff) ? $scope.$parent.$eval($attrs.stateOff) : ratingConfig.stateOff);
    this.createRateObjects = function(states) {
      var defaultOptions, i, n;
      defaultOptions = {
        stateOn: this.stateOn,
        stateOff: this.stateOff
      };
      i = 0;
      n = states.length;
      while (i < n) {
        states[i] = angular.extend({
          index: i
        }, defaultOptions, states[i]);
        i++;
      }
      return states;
    };
    $scope.range = (angular.isDefined($attrs.ratingStates) ? this.createRateObjects(angular.copy($scope.$parent.$eval($attrs.ratingStates))) : this.createRateObjects(new Array(this.maxRange)));
    $scope.rate = function(value) {
      if ($scope.readonly || $scope.value === value) {
        return;
      }
      return $scope.value = value;
    };
    $scope.enter = function(value) {
      if (!$scope.readonly) {
        $scope.val = value;
      }
      return $scope.onHover({
        value: value
      });
    };
    $scope.reset = function() {
      $scope.val = angular.copy($scope.value);
      return $scope.onLeave();
    };
    $scope.$watch("value", function(value) {
      return $scope.val = value;
    });
    $scope.readonly = false;
    if ($attrs.readonly) {
      return $scope.$parent.$watch($parse($attrs.readonly), function(value) {
        return $scope.readonly = !!value;
      });
    }
  }
]);

angular.module("fork").directive("customRating", function() {
  return {
    restrict: "EA",
    scope: {
      value: "=",
      onHover: "&",
      onLeave: "&"
    },
    controller: "CustomRatingController",
    templateUrl: "template/custom_rating/custom_rating.html",
    replace: true
  };
});
angular.module('platform').directive('searchMenu', [
  function() {
    return {
      restrict: 'E',
      templateUrl: 'partials/platform/search.menu.html',
      scope: {
        name: '@',
        options: '@'
      },
      controller: [
        '$scope', '$parse', '$attrs', function($scope, $parse, $attrs) {
          var OPTIONS_REGEXP, list_item, match, name, options, valueName, valuesFn;
          name = $attrs.name;
          options = $attrs.options;
          OPTIONS_REGEXP = /^\s*(.*?)(?:\s+as\s+(.*?))?(?:\s+group\s+by\s+(.*))?\s+for\s+(?:([\$\w][\$\w\d]*)|(?:\(\s*([\$\w][\$\w\d]*)\s*,\s*([\$\w][\$\w\d]*)\s*\)))\s+in\s+(.*)$/;
          if (!(match = options.match(OPTIONS_REGEXP))) {
            throw Error("Expected options in form of '_select_ (as _label_)? for (_key_,)?_value_ in _collection_'" + " but got '" + options + "'.");
          }
          $scope.displayFn = $parse(match[2] || match[1]);
          valueName = match[4] || match[6];
          $scope.valueFn = $parse((match[2] ? match[1] : valueName));
          valuesFn = $parse(match[7]);
          $scope.list = (function() {
            var _i, _len, _ref, _results;
            _ref = valuesFn($scope.$parent);
            _results = [];
            for (_i = 0, _len = _ref.length; _i < _len; _i++) {
              list_item = _ref[_i];
              _results.push({
                item: list_item
              });
            }
            return _results;
          })();
          console.log(name);
          return $scope.select = function(selected) {
            return $scope.$emit('search:menu', {
              name: name,
              selected: selected
            });
          };
        }
      ]
    };
  }
]);
angular.module('platform').directive('searchInput', [
  '$timeout', function($timeout) {
    return {
      restrict: 'A',
      controller: [
        '$scope', '$element', function($scope, $element) {
          $scope.$on('search:trigger', function() {
            return $scope.search();
          });
          return $scope.search = function() {
            return $scope.$emit('search:input', $element.val());
          };
        }
      ],
      link: function(scope, element) {
        var timer;
        timer = null;
        return element.keyup(function() {
          $timeout.cancel(timer);
          return timer = $timeout((function() {
            return scope.search();
          }), 500);
        });
      }
    };
  }
]);

angular.module('platform').directive('searchButton', [
  function() {
    return {
      restrict: 'A',
      link: function(scope, element) {
        return element.click(function() {
          return scope.$emit('search:trigger');
        });
      }
    };
  }
]);
angular.module('dashboard').directive('reviewForm', [
  function() {
    return {
      restrict: 'EA',
      replace: true,
      scope: {
        type: '@',
        reviewer: '=',
        provider: '=',
        reviewFormOpened: '='
      },
      templateUrl: 'forms/platform/review.form.html',
      controller: [
        '$scope', '$rootScope', '$routeParams', 'FormHandler', 'Review', function($scope, $rootScope, $routeParams, FormHandler, Entity) {
          var init;
          $scope.submitReview = function() {
            var promise, success_msg;
            $scope.submitted = true;
            if ($scope.form.$valid) {
              $rootScope.clear_notifications();
              switch ($scope.type) {
                case 'new':
                  promise = Entity.create($scope.form_object, {
                    notify_success: false
                  });
                  success_msg = 'Review has been submitted';
                  break;
                case 'edit':
                  promise = $scope.form_object.put();
                  success_msg = 'Your event is updated successfully';
              }
              return promise.then((function(object) {
                $rootScope.notify_success(success_msg);
                $scope.closeForm();
                return $scope.$emit('repull_reviews');
              }), function() {
                return $rootScope.notify_error('Form has missing or invalid values');
              });
            } else {
              return FormHandler.validate($scope.form.$error);
            }
          };
          $scope.closeForm = function() {
            $scope.reviewFormOpened = false;
            return $scope.form_object = {
              reviewer_id: $scope.reviewer.id,
              provider_id: $scope.provider.id,
              rating: 0,
              content: '',
              title: ''
            };
          };
          init = function() {
            FormHandler.formify($scope);
            switch ($scope.type) {
              case 'new':
                return $scope.form_object = {
                  reviewer_id: $scope.reviewer.id,
                  provider_id: $scope.provider.id,
                  rating: 0,
                  content: '',
                  title: ''
                };
              case 'edit':
                return Entity.find($routeParams.id).then(function(obj) {
                  return $scope.form_object = obj;
                });
            }
          };
          return init();
        }
      ]
    };
  }
]);
var __hasProp = {}.hasOwnProperty,
  __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

angular.module('platform').factory('Event', [
  'Restangular', '$rootScope', '$filter', function(Restangular, $rootScope, $filter) {
    var Model, _ref;
    Model = (function(_super) {
      __extends(Model, _super);

      function Model() {
        _ref = Model.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      Model.prototype.save_form = function(form_object) {
        this.before_operation(form_object);
        return Restangular.all('events').customPOST('save_form', {}, {}, form_object);
      };

      Model.prototype.submit_form = function(form_object) {
        this.before_operation(form_object);
        return Restangular.all('events').customPOST('submit_form', {}, {}, form_object);
      };

      return Model;

    })(BaseModel);
    return new Model(Restangular, $rootScope, $filter, 'event', 'events');
  }
]);
var __hasProp = {}.hasOwnProperty,
  __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

angular.module('platform').factory('Provider', [
  'Restangular', '$rootScope', '$filter', function(Restangular, $rootScope, $filter) {
    var Model, _ref;
    Model = (function(_super) {
      __extends(Model, _super);

      function Model() {
        _ref = Model.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      Model.prototype.approve = function(id) {
        return Restangular.one('providers', id).customPUT('approve', {}, {});
      };

      return Model;

    })(BaseModel);
    return new Model(Restangular, $rootScope, $filter, 'provider', 'providers');
  }
]);
var __hasProp = {}.hasOwnProperty,
  __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

angular.module('platform').factory('Review', [
  'Restangular', '$rootScope', '$filter', function(Restangular, $rootScope, $filter) {
    var Model, _ref;
    Model = (function(_super) {
      __extends(Model, _super);

      function Model() {
        _ref = Model.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      return Model;

    })(BaseModel);
    return new Model(Restangular, $rootScope, $filter, 'review', 'reviews');
  }
]);
var __hasProp = {}.hasOwnProperty,
  __extends = function(child, parent) { for (var key in parent) { if (__hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; };

angular.module('platform').factory('Service', [
  'Restangular', '$rootScope', '$filter', function(Restangular, $rootScope, $filter) {
    var Model, _ref;
    Model = (function(_super) {
      __extends(Model, _super);

      function Model() {
        _ref = Model.__super__.constructor.apply(this, arguments);
        return _ref;
      }

      Model.prototype.get_from_name = function(name) {
        return Restangular.all('services').customGET('get_from_name', {
          name: name
        });
      };

      return Model;

    })(BaseModel);
    return new Model(Restangular, $rootScope, $filter, 'service', 'services');
  }
]);
angular.module('platform').config([
  '$routeProvider', 'WardenProvider', function($routeProvider, WardenProvider) {
    return WardenProvider.simplify($routeProvider).set_template_prefix('views/platform').when('service_categories', {
      omitController: true
    }).when('services/:service_name', {
      resolves: ['service']
    }).when('provider/:id', {
      resolves: ['provider', 'service']
    }).when('provider/:id/:service_name', {
      resolves: ['provider', 'service']
    });
  }
]);
resolvables['provider'] = [
  'Provider', '$route', function(Provider, $route) {
    var id;
    id = $route.current.params['id'];
    return Provider.find(id);
  }
];
resolvables['service'] = [
  'Service', '$route', function(Service, $route) {
    var name;
    name = $route.current.params['service_name'];
    if (name) {
      return Service.get_from_name(name);
    } else {
      return null;
    }
  }
];
resolvables['services'] = [
  'Service', function(Service) {
    return Service.all();
  }
];
angular.module('platform').factory('Cart', [
  '$cookieStore', function($cookieStore) {
    var Cart;
    Cart = (function() {
      function Cart() {
        this._init();
      }

      Cart.prototype._init = function() {
        this.cart = $cookieStore.get('CartSession');
        if (angular.isUndefined(this.cart)) {
          return this.cart = {};
        }
      };

      Cart.prototype.get = function() {
        return this.cart;
      };

      Cart.prototype.add = function(service_name, provider) {
        if (angular.isUndefined(this.cart[service_name])) {
          this.cart[service_name] = {};
        }
        this.cart[service_name][provider.id] = provider.name;
        return $cookieStore.put('CartSession', this.get());
      };

      Cart.prototype.remove = function(service_name, provider_id) {
        delete this.cart[service_name][provider_id];
        if (Object.keys(this.cart[service_name]).length === 1) {
          delete this.cart[service_name];
        } else {

        }
        return $cookieStore.put('CartSession', this.get());
      };

      Cart.prototype.destroy = function() {
        this.cart = {};
        return $cookieStore.remove('CartSession');
      };

      Cart.prototype.as_json = function() {
        return JSON.stringify(this.get());
      };

      Cart.prototype.isEmpty = function() {
        return this.as_json === '{}';
      };

      return Cart;

    })();
    return new Cart;
  }
]);
