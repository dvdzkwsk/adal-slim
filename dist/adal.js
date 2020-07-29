function e(){return(e=Object.assign||function(e){for(var n=1;n<arguments.length;n++){var t=arguments[n];for(var r in t)Object.prototype.hasOwnProperty.call(t,r)&&(e[r]=t[r])}return e}).apply(this,arguments)}function n(e,n){(null==n||n>e.length)&&(n=e.length);for(var t=0,r=new Array(n);t<n;t++)r[t]=e[t];return r}function t(e,t){var r;if("undefined"==typeof Symbol||null==e[Symbol.iterator]){if(Array.isArray(e)||(r=function(e,t){if(e){if("string"==typeof e)return n(e,void 0);var r=Object.prototype.toString.call(e).slice(8,-1);return"Object"===r&&e.constructor&&(r=e.constructor.name),"Map"===r||"Set"===r?Array.from(e):"Arguments"===r||/^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(r)?n(e,void 0):void 0}}(e))||t&&e&&"number"==typeof e.length){r&&(e=r);var o=0;return function(){return o>=e.length?{done:!0}:{done:!1,value:e[o++]}}}throw new TypeError("Invalid attempt to iterate non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}return(r=e[Symbol.iterator]()).next.bind(r)}var r;!function(e){e.TOKEN_KEYS="adal.token.keys",e.ACCESS_TOKEN_KEY="adal.access.token.key",e.EXPIRATION_KEY="adal.expiration.key",e.STATE_LOGIN="adal.state.login",e.STATE_RENEW="adal.state.renew",e.NONCE_IDTOKEN="adal.nonce.idtoken",e.SESSION_STATE="adal.session.state",e.USERNAME="adal.username",e.IDTOKEN="adal.idtoken",e.ERROR="adal.error",e.ERROR_DESCRIPTION="adal.error.description",e.LOGIN_REQUEST="adal.login.request",e.LOGIN_ERROR="adal.login.error",e.RENEW_STATUS="adal.token.renew.status"}(r||(r={}));var o,a,i,s,c,l=function(){function e(e){var n=window[e];return!!n&&(n.setItem("__test__","__test__"),"__test__"===n.getItem("__test__")&&(n.removeItem("__test__"),!n.getItem("__test__")))}return e("localStorage")?localStorage:e("sessionStorage")?sessionStorage:{getItem:function(){},setItem:function(){}}}();!function(e){e[e.Error=0]="Error",e[e.Warn=1]="Warn",e[e.Info=2]="Info",e[e.Verbose=3]="Verbose"}(a||(a={})),(o={})[a.Error]="ERROR",o[a.Warn]="WARNING",o[a.Info]="INFO",o[a.Verbose]="VERBOSE",function(e){e.LOGIN="LOGIN",e.RENEW_TOKEN="RENEW_TOKEN",e.UNKNOWN="UNKNOWN"}(i||(i={})),function(e){e.ID_TOKEN="id_token token",e.TOKEN="token"}(s||(s={})),function(e){e.Canceled="Canceled",e.Completed="Completed",e.InProgress="In Progress"}(c||(c={}));var u=function(e){return encodeURIComponent(e)},d=function(e,n){return new RegExp("[\\?&]"+e+"=").test(n)},p=function(e,n){return e.replace(new RegExp("(\\&"+n+"=)[^&]+"),"").replace(new RegExp("("+n+"=)[^&]+&"),"").replace(new RegExp("("+n+"=)[^&]+"),"")},E=function(e,n,t){if(void 0===t&&(t=!1),t){var r=I(e)||"";l.setItem(e,r+n+"||")}else l.setItem(e,n)},f=function(e){var n=I(r.TOKEN_KEYS);return!N(n)&&n.indexOf(e+"|")>-1},_=function(e){return e.indexOf("#/")>-1?e.substring(e.indexOf("#/")+2):e.indexOf("#")>-1?e.substring(1):e},R=function(e){for(var n=/\+/g,t=/([^&=]+)=([^&]*)/g,r=function(e){return decodeURIComponent(e.replace(n," "))},o={},a=t.exec(e);a;)o[r(a[1])]=r(a[2]),a=t.exec(e);return o},O=function(){var e=new Uint8Array(16);return crypto.getRandomValues(e),e[6]|=64,e[6]&=79,e[8]|=128,e[8]&=191,(e=e.map(function(e){for(var n=e.toString(16);n.length<2;)n="0"+n;return n}))[0]+e[1]+e[2]+e[3]+"-"+e[4]+e[5]+"-"+e[6]+e[7]+"-"+e[8]+e[9]+"-"+e[10]+e[11]+e[12]+e[13]+e[14]+e[15]},I=function(e){return l.getItem(e)},N=function(e){return!e||!e.length},T=function(e,n){return Object.hasOwnProperty.call(e,n)},v=function(){return Math.round(Date.now()/1e3)};exports.AuthenticationContext=function(n){if(window._adalInstance)return window._adalInstance;var o,a;n=function(n){return e({popUp:!1,instance:"https://login.microsoftonline.com/",loginResource:n.clientId,laodFrameTimeout:6e3,expireOffsetSeconds:300,navigateToLoginRequestUrl:!0,tenant:"common",redirectUri:window.location.href.split("?")[0].split("#")[0],callback:function(){}},n)}(n);var l={},m=!1,S=!1,g=[],w=[],h={},K={},k=i.LOGIN;function y(e,n,t,o,a){E(r.ERROR,t),E(r.ERROR_DESCRIPTION,o),E(r.LOGIN_ERROR,a),n&&l[n]&&(l[n]=null),m=!1,S=!1,e&&e(o,null,t)}function C(e,t,r){var o=function(e,n,t,r){try{var o=window.innerWidth/2-241.5+window.screenX,a=window.innerHeight/2-300+window.screenY,i=window.open(e,"login","width=483, height=600, top="+a+", left="+o);return i.focus&&i.focus(),i}catch(e){m=!1,S=!1}}(e),a=r||n.callback;if(o){w.push(o);var i=n.redirectUri.split("#")[0],s=setInterval(function(){if(!o||o.closed||void 0===o.closed){var e="Popup Window closed by UI action/ Popup Window handle destroyed due to cross zone navigation in IE/Edge";return y(a,t,"Popup Window closed",e,e),void clearInterval(s)}try{var n=o.location;if(-1!=encodeURI(n.href).indexOf(encodeURI(i)))return D(n.hash),clearInterval(s),m=!1,S=!1,w=[],void o.close()}catch(e){}},1)}else{var c="Popup Window is null. This can happen if you are using IE";y(a,t,"Error opening popup",c,c)}}function A(e,n,t){l[n]=e,K[e]||(K[e]=[]),K[e].push(t),h[e]||(h[e]=function(t,r,o,a){l[n]=null;for(var i=0;i<K[e].length;++i)try{K[e][i](t,r,o,a)}catch(o){}K[e]=null,h[e]=null})}function b(e,t,o){void 0===o&&(o="token");var i=Y("adalRenewFrame"+e),c=O()+"|"+e;n.state=c,g.push(c);var l=p(G(o,e),"prompt");o===s.ID_TOKEN&&(a=O(),E(r.NONCE_IDTOKEN,a,!0),l+="&nonce="+u(a)),l=W(l+="&prompt=none"),A(c,e,t),i.src="about:blank",U(l,"adalRenewFrame"+e,e)}function P(e,t){var o=Y("adalIdTokenFrame"),i=O()+"|"+n.clientId;a=O(),E(r.NONCE_IDTOKEN,a,!0),n.state=i,g.push(i);var s=t||n.clientId,c=p(G(t=t||"id_token",s),"prompt");c=W(c+"&prompt=none"),c+="&nonce="+u(a),A(i,n.clientId,e),o.src="about:blank",U(c,"adalIdTokenFrame",n.clientId)}function U(e,t,o){E(r.RENEW_STATUS+o,c.InProgress),function e(n,t){setTimeout(function(){var r=Y(t);r.src&&"about:blank"!==r.src||(r.src=n,e(n,t))},500)}(e,t),setTimeout(function(){if(I(r.RENEW_STATUS+o)===c.InProgress){var e=l[o];e&&h[e]&&h[e]("Token renewal operation failed due to timeout",null,"Token Renewal Failed"),E(r.RENEW_STATUS+o,c.Canceled)}},n.loadFrameTimeout)}function x(e){e&&window.location.replace(e)}function W(e){if(!o||!o.profile)return e;if(o.profile.sid&&-1!==e.indexOf("&prompt=none"))d("sid",e)||(e+="&sid="+u(o.profile.sid));else if(o.profile.upn&&(d("login_hint",e)||(e+="&login_hint="+u(o.profile.upn)),!d("domain_hint",e)&&o.profile.upn.indexOf("@")>-1)){var n=o.profile.upn.split("@");e+="&domain_hint="+u(n[n.length-1])}return e}function L(e){var t=function(e){var n,t=function(e){if(!N(e)){var n=/^([^\.\s]*)\.([^\.\s]+)\.([^\.\s]*)$/.exec(e);if(n&&!(n.length<4))return{header:n[1],JWSPayload:n[2],JWSSig:n[3]}}}(e);if(t)try{var r=(n=(n=t.JWSPayload).replace(/-/g,"+").replace(/_/g,"/"),decodeURIComponent(escape(window.atob(n))));return r?JSON.parse(r):void 0}catch(e){}}(e);if(T(t,"aud"))return t.aud.toLowerCase()===n.clientId.toLowerCase()?{userName:t.upn||t.email,profile:t}:void 0}function D(e){if(void 0===e&&(e=window.location.hash),function(e){var n=R(_(e));return T(n,"error_description")||T(n,"access_token")||T(n,"id_token")}(e)){var n,t,o=w[w.length-1];o&&o.opener&&o.opener._AuthenticationContextInstance?(n=o.opener._adalInstance,t=!0):window.parent&&window.parent._adalInstance&&(n=window.parent._adalInstance);var a,s,c,l=n.getRequestInfo(e);a=t||window.parent!==window?n._callBackMappedToRenewStates[l.stateResponse]:n.config.callback,n.saveTokenFromHash(l),l.requestType===i.RENEW_TOKEN&&window.parent?(s=l.parameters.access_token||l.parameters.id_token,c="access_token"):l.requestType===i.LOGIN&&(s=l.parameters.id_token,c="id_token");try{a&&a(l.parameters.error_description,s,l.parameters.error,c)}catch(e){}window.parent!==window||t||(n.config.navigateToLoginRequestUrl?window.location.href=I(r.LOGIN_REQUEST):window.location.hash="")}}var G=function(e,t){return n.instance+n.tenant+"/oauth2/authorize"+function(e,n,t){if(!n)return"";var r=["?response_type="+e,"client_id="+u(n.clientId)];t&&r.push("resource="+u(t)),r.push("redirect_uri="+u(n.redirectUri)),r.push("state="+u(n.state)),T(n,"slice")&&r.push("slice="+u(n.slice)),T(n,"extraQueryParameter")&&r.push(n.extraQueryParameter);var o=n.correlationId||O();return r.push("client-request-id="+u(o)),r.join("&")}(e,n,t)};function Y(e){return document.getElementById(e)||(document.body.insertAdjacentHTML("beforeEnd",'<iframe name="'+e+'" id="'+e+'" style="display:none"></iframe>'),window.frames&&window.frames[e])}return window._adalInstance={config:n,login:function(){if(!m){m=!0;var e=O(),t=window.location.href;n.state=e,a=O(),E(r.LOGIN_REQUEST,t),E(r.LOGIN_ERROR,""),E(r.STATE_LOGIN,e,!0),E(r.NONCE_IDTOKEN,a,!0),E(r.ERROR,""),E(r.ERROR_DESCRIPTION,"");var o=G("id_token")+"&nonce="+u(a);n.displayCall?n.displayCall(o):n.popUp?(E(r.STATE_LOGIN,""),g.push(e),A(e,n.clientId,n.callback),C(o)):x(o)}},logout:function(){var e;if(function(){E(r.LOGIN_REQUEST,""),E(r.SESSION_STATE,""),E(r.STATE_LOGIN,""),E(r.STATE_RENEW,""),g=[],E(r.NONCE_IDTOKEN,""),E(r.IDTOKEN,""),E(r.ERROR,""),E(r.ERROR_DESCRIPTION,""),E(r.LOGIN_ERROR,""),E(r.LOGIN_ERROR,"");var e=I(r.TOKEN_KEYS);if(!N(e)){e=e.split("|");for(var n=0;n<e.length&&""!==e[n];n++)E(r.ACCESS_TOKEN_KEY+e[n],""),E(r.EXPIRATION_KEY+e[n],0)}E(r.TOKEN_KEYS,"")}(),o=null,n.logOutUri)e=n.logOutUri;else{var t="";n.postLogoutRedirectUri&&(t="post_logout_redirect_uri="+u(n.postLogoutRedirectUri)),e=n.instance+n.tenant+"/oauth2/logout?"+t}x(e)},getUser:function(){if(!o){var e=I(r.IDTOKEN);e&&(o=L(e))}return o},registerCallback:A,acquireToken:function(e,t){if(e){var a=function(e){if(f(e)){var t=I(r.ACCESS_TOKEN_KEY+e),o=I(r.EXPIRATION_KEY+e);if(o&&o>v()+n.expireOffsetSeconds)return t;E(r.ACCESS_TOKEN_KEY+e,""),E(r.EXPIRATION_KEY+e,0)}}(e);if(a)t(null,a,null);else if(o||n.extraQueryParameter&&-1!==n.extraQueryParameter.indexOf("login_hint"))l[e]?A(l[e],e,t):(k=i.RENEW_TOKEN,e===n.clientId?o?P(t):P(t,s.ID_TOKEN):o?b(e,t):b(e,t,s.ID_TOKEN));else{var c="User login is required";t(c,null,c)}}else{var u="resource is required";t(u,null,u)}},acquireTokenPopup:function(e,t,r,a){if(function(e){var t;return e?o?S&&(t="Acquire token interactive is already in progress"):t="User login is required":t="Resource is required",t&&n.callback(t,null,t),!t}(e)){var s=O()+"|"+e;n.state=s,g.push(s),k=i.RENEW_TOKEN;var c=p(G("token",e),"prompt");if(c+="&prompt=select_account",t&&(c+=t),r){if(-1!==c.indexOf("&claims"))throw new Error("Claims cannot be passed as an extraQueryParameter");c+="&claims="+u(r)}c=W(c),S=!0,A(s,e,a),C(c,e,a)}},getRequestInfo:function(e){var n={valid:!1,parameters:{},stateMatch:!1,stateResponse:"",requestType:i.UNKNOWN},o=R(_(e));if(!o)return n;if(n.parameters=o,T(o,"error_description")||T(o,"access_token")||T(o,"id_token")){if(n.valid=!0,!T(o,"state"))return n;if(n.stateResponse=o.state,function(e){var n=I(r.STATE_LOGIN);if(n)for(var o,a=t(n.split("||"));!(o=a()).done;)if(o.value===e.stateResponse)return e.requestType=i.LOGIN,e.stateMatch=!0,!0;var s=I(r.STATE_RENEW);if(s)for(var c,l=t(s.split("||"));!(c=l()).done;)if(c.value===e.stateResponse)return e.requestType=i.RENEW_TOKEN,e.stateMatch=!0,!0;return!1}(n))return n;if(!n.stateMatch&&window.parent){n.requestType=k;for(var a,s=t(g);!(a=s()).done;)if(a.value===n.stateResponse){n.stateMatch=!0;break}}}return n},saveTokenFromHash:function(e){E(r.ERROR,""),E(r.ERROR_DESCRIPTION,"");var a,s=function(e){if(e){var n=e.indexOf("|");if(n>-1&&n+1<e.length)return e.substring(n+1)}return""}(e.stateResponse);if(T(e.parameters,"error_description"))E(r.ERROR,e.parameters.error),E(r.ERROR_DESCRIPTION,e.parameters.error_description),e.requestType===i.LOGIN&&(m=!1,E(r.LOGIN_ERROR,e.parameters.error_description));else if(e.stateMatch){var l;if(T(e.parameters,"session_state")&&E(r.SESSION_STATE,e.parameters.session_state),T(e.parameters,"access_token")&&(f(s)||(l=I(r.TOKEN_KEYS)||"",E(r.TOKEN_KEYS,l+s+"|")),E(r.ACCESS_TOKEN_KEY+s,e.parameters.access_token),E(r.EXPIRATION_KEY+s,((a=e.parameters.expires_in)||(a=3599),v()+parseInt(a,10)))),T(e.parameters,"id_token"))if(m=!1,(o=L(e.parameters.id_token))&&o.profile)!function(e){var n=I(r.NONCE_IDTOKEN);if(n)for(var o,a=t(n.split("||"));!(o=a()).done;)if(o.value===e.profile.nonce)return!0;return!1}(o)?(E(r.LOGIN_ERROR,"Nonce received: "+o.profile.nonce+" is not same as requested: "+I(r.NONCE_IDTOKEN)),o=null):(E(r.IDTOKEN,e.parameters.id_token),f(s=n.loginResource?n.loginResource:n.clientId)||(l=I(r.TOKEN_KEYS)||"",E(r.TOKEN_KEYS,l+s+"|")),E(r.ACCESS_TOKEN_KEY+s,e.parameters.id_token),E(r.EXPIRATION_KEY+s,o.profile.exp));else{var u="invalid id_token",d="Invalid id_token. id_token: "+e.parameters.id_token;e.parameters.error=u,e.parameters.error_description=d,E(r.ERROR,u),E(r.ERROR_DESCRIPTION,d)}}else{var p="Invalid_state. state: "+e.stateResponse;e.parameters.error="Invalid_state",e.parameters.error_description=p,E(r.ERROR,"Invalid_state"),E(r.ERROR_DESCRIPTION,p)}E(r.RENEW_STATUS+s,c.Completed)},loginInProgress:function(){return m},handleWindowCallback:D,_callBackMappedToRenewStates:h,_callBacksMappedToRenewStates:K}},exports.clearCacheForResource=function(e){E(r.STATE_RENEW,""),E(r.ERROR,""),E(r.ERROR_DESCRIPTION,""),f(e)&&(E(r.ACCESS_TOKEN_KEY+e,""),E(r.EXPIRATION_KEY+e,0))};
//# sourceMappingURL=adal.js.map