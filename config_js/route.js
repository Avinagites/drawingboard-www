angular.module('pages').config(['$routeProvider', 'WardenProvider', function($routeProvider, WardenProvider) {
        return WardenProvider.simplify($routeProvider)
            .set_template_prefix('views/pages')
            .omit_controller()
            .when('home', {omitController: false})
            .when('about')
            .when('contact', {omitController: false})
            .when('check_email')
            .when('faq')
            .when('terms')
            .when('privacy')
            .when('blog')
            .when('why_list_our_business')
            .when('advertise')
            .when('page_not_found')
            .when('newsletter');
    }
]);

