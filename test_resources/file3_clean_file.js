!function(){var
e={76141:function(e){e.exports={source_map:"hidden-source-map",api_base:"htt
ps://api-iam.mysite.com",public_path:"https://js.mysitecdn.com/",sheets_prox
y_path:"https://mysite-sheets.com/sheets_proxy",sentry_proxy_path:"https://w
ww.mysite-reporting.com/sentry/index.html",install_mode_base:"https://app.my
site.com",sentry_dsn:"https://f305de69cac64a84a494556d5303dc2d@app.getsentry
.com/24287",intersection_js:"https://js.mysitecdn.com/intersection/assets/ap
p.js",intersection_styles:"https://js.mysitecdn.com/intersection/assets/styl
es.js",article_search_messenger_app_id:27,mode:"production"}}},t={};function
n(r){var o=t[r];if(void 0!==o)return o.exports;var
i=t[r]={exports:{}};return e[r](i,i.exports,n),i.exports}!function(){"use
strict";var e=/iphone|ipad|ipod|android|blackberry|opera
mini|iemobile/i,t=[".mysite-lightweight-app-launcher",".mysite-launcher-fram
e","#mysite-container",".mysite-messenger",".mysite-notifications"];function
r(e){try{if(!(e in window))return!1;var t=window[e];return
null!==t&&(t.setItem("mysite-test","0"),t.removeItem("mysite-test"),!0)}catc
h(e){return!1}}function o(){var e=i().vendor||"",t=i().userAgent||"";return
0===e.indexOf("Apple")&&/\sSafari\//.test(t)}function i(){return
navigator||{}}function a(e){return void
0===e&&(e=i().userAgent),/iPad|iPhone|iPod/.test(e)&&!window.MSStream}functi
on s(){var e;return(null==(e=function(){if(a()){var
e=i().appVersion.match(/OS
(\d+)_(\d+)_?(\d+)?/);return{major:parseInt(e[1],10),minor:parseInt(e[2],10)
,patch:parseInt(e[3]||0,10)}}return null}())?void 0:e.major)>=15}var
c={hasXhr2Support:function(){return"XMLHttpRequest"in
window&&"withCredentials"in new
XMLHttpRequest},hasLocalStorageSupport:function(){return
r("localStorage")},hasSessionStorageSupport:function(){return
r("sessionStorage")},hasFileSupport:function(){return!!(window.FileReader&&w
indow.File&&window.FileList&&window.FormData)},hasAudioSupport:function(){va
r
e=document.createElement("audio");return!!e.canPlayType&&!!e.canPlayType("au
dio/mpeg;").replace(/^no$/,"")},hasVisibilitySupport:function(){return void
0!==document.hidden||void 0!==document.mozHidden||void
0!==document.msHidden||void
0!==document.webkitHidden},messengerIsVisible:function(){return
t.some((function(e){var t=window.parent.document.querySelector(e);if(t){var
n=t.getBoundingClientRect();return
n&&n.width>0&&n.height>0}}))},messengerHasDisplayNoneSet:function(){return
t.some((function(e){var t=window.parent.document.querySelector(e);if(t){var
n=window.getComputedStyle(t);return
null===n||"none"===n.display}}))},isMobileBrowser:function(){var
t=i().userAgent;return!!t&&(null!==t.match(e)&&void
0!==window.parent)},isIOSFirefox:function(){return!!i().userAgent.match("Fxi
OS")},isFirefox:function(){return!!i().userAgent.match("Firefox")},isSafari:
o,isElectron:function(){var
e=i().userAgent||"",t=window.parent||{},n=t.process&&t.versions&&t.versions.
electron;return/\sElectron\//.test(e)||n},isIE:function(){var
e=i().userAgent||"";return
e.indexOf("MSIE")>0||e.indexOf("Trident")>0},isEdge:function(){return(i().us
erAgent||"").indexOf("Edge")>0},isNativeMobile:function(){return
i().isNativeMobile},isChrome:function(){var
e=window.chrome,t=i().vendor,n=i().userAgent.indexOf("OPR")>-1,r=i().userAge
nt.indexOf("Edge")>-1;return!!i().userAgent.match("CriOS")||null!=e&&"Google
Inc."===t&&!1===n&&!1===r},isIOS:a,isIOS15Safari:function(){var
e=i().userAgent,t=a(e),n=!!e.match(/WebKit/i);return
t&&n&&!e.match(/CriOS/i)&&s()},isAndroid:function(e){return void
0===e&&(e=i().userAgent),e&&e.toLowerCase().indexOf("android")>-1},isMacOS:f
unction(){return
window.navigator.appVersion.indexOf("Mac")>=0}},d=["turbo:visit","turbolinks
:visit","page:before-change"],u=["turbo:before-cache","turbolinks:before-cac
he"],m=["turbo:load","turbolinks:load","page:change"];var p=function(e){var
t=document.createElement("script");return
t.type="text/javascript",t.charset="utf-8",t.src=e,t},l=n(76141).public_path
,f=l+"frame.7a3ddac5.js",w=l+"vendor.e163e343.js",h=l+"frame-modern.78abb9d0
.js",v=l+"vendor-modern.dde03d24.js",g="MySite",b=/bot|googlebot|crawler|spi
der|robot|crawling|facebookexternalhit/i,y=function(){return
window[g]&&window[g].booted},S=function(){var
e,t=!!(e=navigator.userAgent.match(/Chrom(?:e|ium)\/([0-9\.]+)/))&&e[1];retu
rn!!t&&t.split(".").map((function(e){return parseInt(e)}))},A=function(){var
e=document.querySelector('meta[name="referrer"]'),t=e?'<meta name="referrer"
content="'+e.content+'">':"",n=document.createElement("iframe");n.id="mysite
-frame",n.setAttribute("style","position: absolute !important; opacity: 0
!important; width: 1px !important; height: 1px !important; top: 0
!important; left: 0 !important; border: none !important; display: block
!important; z-index: -1 !important; pointer-events:
none;"),o()&&n.setAttribute("style",n.getAttribute("style")+"visibility:
hidden;"),n.setAttribute("aria-hidden","true"),n.setAttribute("tabIndex","-1
"),n.setAttribute("title","MySite"),document.body.appendChild(n),function(e,
t,n){if(void 0===n&&(n="en"),c.isFirefox()){var
r=e.contentDocument.open();r.write("<!DOCTYPE
html>"),r.close()}!function(e,t,n){void
0===n&&(n="en"),e.documentElement.innerHTML=t,e.documentElement.setAttribute
("lang",n)}(e.contentDocument,t,n)}(n,'<!DOCTYPE html>\n <html
lang="en">\n <head>\n '+t+"\n </head>\n <body>\n
</body>\n </html>");var
r,i=!!(r=S())&&r[0]>=120,a=p(i?h:f),s=p(i?v:w);return
n.contentDocument.head.appendChild(a),n.contentDocument.head.appendChild(s),
window.__mysiteAssignLocation=function(e){window.location.assign(e)},window.
__mysiteReloadLocation=function(){window.location.reload()},n},x=function(){
var
e=document.getElementById("mysite-frame");e&&e.parentNode&&e.parentNode.remo
veChild(e),delete window.__mysiteAssignLocation,delete
window.__mysiteReloadLocation},_=function(){if(!window[g]){var e=function
e(){for(var t=arguments.length,n=new
Array(t),r=0;r<t;r++)n[r]=arguments[r];e.q.push(n)};e.q=[],window[g]=e}},E=f
unction(){y()||(_(),A(),window[g].booted=!0)};"attachEvent"in
window&&!window.addEventListener||navigator&&navigator.userAgent&&/MSIE
9\.0/.test(navigator.userAgent)&&window.addEventListener&&!window.atob||"onp
ropertychange"in document&&window.matchMedia&&/MSIE
10\.0/.test(navigator.userAgent)||navigator&&navigator.userAgent&&b.test(nav
igator.userAgent)||window.isMySiteMessengerSheet||y()||(E(),function(e,t,n){
m.forEach((function(t){document.addEventListener(t,e)})),u.forEach((function
(e){document.addEventListener(e,t)})),d.forEach((function(e){document.addEve
ntListener(e,n)}))}(E,x,(function(){window[g]("shutdown",!1),delete
window[g],x(),_()})))}()}();
