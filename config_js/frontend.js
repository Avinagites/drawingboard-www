/******** View port ******/

if (/iphone|ipod|android|blackberry|opera mini|opera mobi|skyfire|maemo|windows phone|palm|iemobile|symbian|symbianos|fennec/i.test(navigator.userAgent.toLowerCase())) {
    $("meta[name='viewport']").attr("content", "width=480");
}

/******** GA ******/

(function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
    (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
    m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
})(window,document,'script','//www.google-analytics.com/analytics.js','ga');

ga('create', 'UA-46992471-1', 'drawingboardevents.com.sg');
ga('send', 'pageview');

/******** Animation ******/

frontendFns = {}
frontendFns.sidebarAnimation = function() {
    $("#pull").click(function() {
        $('#sidebar-nav').slideToggle();
    });
};
frontendFns.exampleFn1 = function() {
    // yugene add your code here
}

initiateFrontendFunctions = function(){
    frontendFns.sidebarAnimation();
    frontendFns.exampleFn1();
}