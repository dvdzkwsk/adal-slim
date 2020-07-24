var e;!function(e){e.TOKEN_KEYS="adal.token.keys",e.ACCESS_TOKEN_KEY="adal.access.token.key",e.EXPIRATION_KEY="adal.expiration.key",e.STATE_LOGIN="adal.state.login",e.STATE_RENEW="adal.state.renew",e.NONCE_IDTOKEN="adal.nonce.idtoken",e.SESSION_STATE="adal.session.state",e.USERNAME="adal.username",e.IDTOKEN="adal.idtoken",e.ERROR="adal.error",e.ERROR_DESCRIPTION="adal.error.description",e.LOGIN_REQUEST="adal.login.request",e.LOGIN_ERROR="adal.login.error",e.RENEW_STATUS="adal.token.renew.status"}(e||(e={}));const t=(()=>{function e(e){const t=window[e];return!!t&&(t.setItem("__test__","__test__"),"__test__"===t.getItem("__test__")&&(t.removeItem("__test__"),!t.getItem("__test__")))}return e("localStorage")?localStorage:e("sessionStorage")?sessionStorage:{getItem(){},setItem(){}}})();var n,r,s,i;!function(e){e[e.Error=0]="Error",e[e.Warn=1]="Warn",e[e.Info=2]="Info",e[e.Verbose=3]="Verbose"}(n||(n={})),function(e){e.LOGIN="LOGIN",e.RENEW_TOKEN="RENEW_TOKEN",e.UNKNOWN="UNKNOWN"}(r||(r={})),function(e){e.ID_TOKEN="id_token token",e.TOKEN="token"}(s||(s={})),function(e){e.Canceled="Canceled",e.Completed="Completed",e.InProgress="In Progress"}(i||(i={}));class o{constructor(e){if(this._activeRenewals={},this._loginInProgress=!1,this._acquireTokenInProgress=!1,this._renewStates=[],this._openedWindows=[],this._callBackMappedToRenewStates={},this._callBacksMappedToRenewStates={},this._requestType=r.LOGIN,window._adalInstance)return window._adalInstance;this.config={popUp:!1,instance:"https://login.microsoftonline.com/",loginResource:e.clientId,laodFrameTimeout:6e3,expireOffsetSeconds:300,anonymousEndpoints:[],navigateToLoginRequestUrl:!0,tenant:"common",redirectUri:window.location.href.split("?")[0].split("#")[0],callback:()=>{},...e},window._adalInstance=this}login(){if(this._loginInProgress)return;this._loginInProgress=!0;const t=u(),n=window.location.href;this.config.state=t,this._idTokenNonce=u(),a(e.LOGIN_REQUEST,n),a(e.LOGIN_ERROR,""),a(e.STATE_LOGIN,t,!0),a(e.NONCE_IDTOKEN,this._idTokenNonce,!0),a(e.ERROR,""),a(e.ERROR_DESCRIPTION,"");var r=this._getNavigateUrl("id_token")+"&nonce="+encodeURIComponent(this._idTokenNonce);this.config.displayCall?this.config.displayCall(r):this.config.popUp?(a(e.STATE_LOGIN,""),this._renewStates.push(t),this.registerCallback(t,this.config.clientId,this.config.callback),this._loginPopup(r)):this.promptUser(r)}_openPopup(e,t,n,r){try{const s=window.innerWidth/2-n/2+window.screenX,i=window.innerHeight/2-r/2+window.screenY,o=window.open(e,t,"width="+n+", height="+r+", top="+i+", left="+s);return o.focus&&o.focus(),o}catch(e){return this._loginInProgress=!1,this._acquireTokenInProgress=!1,null}}_handlePopupError(t,n,r,s,i){a(e.ERROR,r),a(e.ERROR_DESCRIPTION,s),a(e.LOGIN_ERROR,i),n&&this._activeRenewals[n]&&(this._activeRenewals[n]=null),this._loginInProgress=!1,this._acquireTokenInProgress=!1,t&&t(s,null,r)}_loginPopup(e,t,n){var r=this._openPopup(e,"login",483,600),s=n||this.config.callback;if(!r){var i="Popup Window is null. This can happen if you are using IE";return void this._handlePopupError(s,t,"Error opening popup",i,i)}this._openedWindows.push(r);const o=this.config.redirectUri.split("#")[0];var a=setInterval(()=>{if(!r||r.closed||void 0===r.closed){var e="Popup Window closed by UI action/ Popup Window handle destroyed due to cross zone navigation in IE/Edge";return this._handlePopupError(s,t,"Popup Window closed",e,e),void clearInterval(a)}try{var n=r.location;if(-1!=encodeURI(n.href).indexOf(encodeURI(o)))return this.handleWindowCallback(n.hash),clearInterval(a),this._loginInProgress=!1,this._acquireTokenInProgress=!1,this._openedWindows=[],void r.close()}catch(e){}},1)}loginInProgress(){return this._loginInProgress}_hasResource(t){var n=c(e.TOKEN_KEYS);return!d(n)&&n.indexOf(t+"|")>-1}getCachedToken(t){if(!this._hasResource(t))return;const n=c(e.ACCESS_TOKEN_KEY+t),r=c(e.EXPIRATION_KEY+t);if(r&&r>p()+this.config.expireOffsetSeconds)return n;a(e.ACCESS_TOKEN_KEY+t,""),a(e.EXPIRATION_KEY+t,0)}getCachedUser(){return this.getUser()}registerCallback(e,t,n){this._activeRenewals[t]=e,this._callBacksMappedToRenewStates[e]||(this._callBacksMappedToRenewStates[e]=[]),this._callBacksMappedToRenewStates[e].push(n),this._callBackMappedToRenewStates[e]||(this._callBackMappedToRenewStates[e]=(n,r,s,i)=>{this._activeRenewals[t]=null;for(var o=0;o<this._callBacksMappedToRenewStates[e].length;++o)try{this._callBacksMappedToRenewStates[e][o](n,r,s,i)}catch(s){}this._callBacksMappedToRenewStates[e]=null,this._callBackMappedToRenewStates[e]=null})}_renewToken(t,n,r="token"){var i=this._addAdalFrame("adalRenewFrame"+t),o=u()+"|"+t;this.config.state=o,this._renewStates.push(o);var c=this._urlRemoveQueryStringParameter(this._getNavigateUrl(r,t),"prompt");r===s.ID_TOKEN&&(this._idTokenNonce=u(),a(e.NONCE_IDTOKEN,this._idTokenNonce,!0),c+="&nonce="+encodeURIComponent(this._idTokenNonce)),c=this._addHintParameters(c+="&prompt=none"),this.registerCallback(o,t,n),i.src="about:blank",this._loadFrameTimeout(c,"adalRenewFrame"+t,t)}_renewIdToken(t,n){let r=this._addAdalFrame("adalIdTokenFrame"),s=u()+"|"+this.config.clientId;this._idTokenNonce=u(),a(e.NONCE_IDTOKEN,this._idTokenNonce,!0),this.config.state=s,this._renewStates.push(s);let i=n||this.config.clientId,o=this._urlRemoveQueryStringParameter(this._getNavigateUrl(n=n||"id_token",i),"prompt");o+="&prompt=none",o=this._addHintParameters(o),o+="&nonce="+encodeURIComponent(this._idTokenNonce),this.registerCallback(s,this.config.clientId,t),r.src="about:blank",this._loadFrameTimeout(o,"adalIdTokenFrame",this.config.clientId)}_urlContainsQueryStringParameter(e,t){return new RegExp("[\\?&]"+e+"=").test(t)}_urlRemoveQueryStringParameter(e,t){var n=new RegExp("(\\&"+t+"=)[^&]+");return e=e.replace(n,""),n=new RegExp("("+t+"=)[^&]+&"),e=e.replace(n,""),n=new RegExp("("+t+"=)[^&]+"),e.replace(n,"")}_loadFrameTimeout(t,n,r){a(e.RENEW_STATUS+r,i.InProgress),this._loadFrame(t,n),setTimeout(()=>{if(c(e.RENEW_STATUS+r)===i.InProgress){var t=this._activeRenewals[r];t&&this._callBackMappedToRenewStates[t]&&this._callBackMappedToRenewStates[t]("Token renewal operation failed due to timeout",null,"Token Renewal Failed"),a(e.RENEW_STATUS+r,i.Canceled)}},this.config.loadFrameTimeout)}_loadFrame(e,t){setTimeout(()=>{const n=this._addAdalFrame(t);n.src&&"about:blank"!==n.src||(n.src=e,this._loadFrame(e,t))},500)}acquireToken(e,t){if(e){var n=this.getCachedToken(e);if(n)t(null,n,null);else if(this._user||this.config.extraQueryParameter&&-1!==this.config.extraQueryParameter.indexOf("login_hint"))this._activeRenewals[e]?this.registerCallback(this._activeRenewals[e],e,t):(this._requestType=r.RENEW_TOKEN,e===this.config.clientId?this._user?this._renewIdToken(t):this._renewIdToken(t,s.ID_TOKEN):this._user?this._renewToken(e,t):this._renewToken(e,t,s.ID_TOKEN));else{const e="User login is required";t(e,null,e)}}else{const e="resource is required";t(e,null,e)}}acquireTokenPopup(e,t,n,s){if(this._canAcquireToken(e)){var i=u()+"|"+e;this.config.state=i,this._renewStates.push(i),this._requestType=r.RENEW_TOKEN;var o=this._urlRemoveQueryStringParameter(this._getNavigateUrl("token",e),"prompt");if(o+="&prompt=select_account",t&&(o+=t),n&&-1===o.indexOf("&claims"))o+="&claims="+encodeURIComponent(n);else if(n&&-1!==o.indexOf("&claims"))throw new Error("Claims cannot be passed as an extraQueryParameter");o=this._addHintParameters(o),this._acquireTokenInProgress=!0,this.registerCallback(i,e,s),this._loginPopup(o,e,s)}}acquireTokenRedirect(t,n,r){if(!this._canAcquireToken(t))return;const s=u()+"|"+t;this.config.state=s;var i=this._urlRemoveQueryStringParameter(this._getNavigateUrl("token",t),"prompt");if(i+="&prompt=select_account",n&&(i+=n),r&&-1===i.indexOf("&claims"))i+="&claims="+encodeURIComponent(r);else if(r&&-1!==i.indexOf("&claims"))throw new Error("Claims cannot be passed as an extraQueryParameter");i=this._addHintParameters(i),this._acquireTokenInProgress=!0,a(e.LOGIN_REQUEST,window.location.href),a(e.STATE_RENEW,s,!0),this.promptUser(i)}_canAcquireToken(e){let t;return e?this._user?this._acquireTokenInProgress&&(t="Acquire token interactive is already in progress"):t="User login is required":t="Resource is required",!t||(this.config.callback(t,null,t),!1)}promptUser(e){e&&window.location.replace(e)}clearCache(){a(e.LOGIN_REQUEST,""),a(e.SESSION_STATE,""),a(e.STATE_LOGIN,""),a(e.STATE_RENEW,""),this._renewStates=[],a(e.NONCE_IDTOKEN,""),a(e.IDTOKEN,""),a(e.ERROR,""),a(e.ERROR_DESCRIPTION,""),a(e.LOGIN_ERROR,""),a(e.LOGIN_ERROR,"");var t=c(e.TOKEN_KEYS);if(!d(t)){t=t.split("|");for(var n=0;n<t.length&&""!==t[n];n++)a(e.ACCESS_TOKEN_KEY+t[n],""),a(e.EXPIRATION_KEY+t[n],0)}a(e.TOKEN_KEYS,"")}clearCacheForResource(t){a(e.STATE_RENEW,""),a(e.ERROR,""),a(e.ERROR_DESCRIPTION,""),this._hasResource(t)&&(a(e.ACCESS_TOKEN_KEY+t,""),a(e.EXPIRATION_KEY+t,0))}logOut(){let e;if(this.clearCache(),this._user=null,this.config.logOutUri)e=this.config.logOutUri;else{let t="";this.config.postLogoutRedirectUri&&(t="post_logout_redirect_uri="+encodeURIComponent(this.config.postLogoutRedirectUri)),e=this.config.instance+this.config.tenant+"/oauth2/logout?"+t}this.promptUser(e)}getUser(){if(!this._user){const t=c(e.IDTOKEN);t&&(this._user=this._createUser(t))}return this._user}_addHintParameters(e){if(this._user&&this._user.profile)if(this._user.profile.sid&&-1!==e.indexOf("&prompt=none"))this._urlContainsQueryStringParameter("sid",e)||(e+="&sid="+encodeURIComponent(this._user.profile.sid));else if(this._user.profile.upn&&(this._urlContainsQueryStringParameter("login_hint",e)||(e+="&login_hint="+encodeURIComponent(this._user.profile.upn)),!this._urlContainsQueryStringParameter("domain_hint",e)&&this._user.profile.upn.indexOf("@")>-1)){var t=this._user.profile.upn.split("@");e+="&domain_hint="+encodeURIComponent(t[t.length-1])}return e}_createUser(e){const t=this._extractIdToken(e);if(h(t,"aud"))return t.aud.toLowerCase()===this.config.clientId.toLowerCase()?{userName:t.upn||t.email,profile:t}:void 0}getLoginError(){return c(e.LOGIN_ERROR)}getRequestInfo(e){const t={valid:!1,parameters:{},stateMatch:!1,stateResponse:"",requestType:r.UNKNOWN},n=_(l(e));if(!n)return t;if(t.parameters=n,h(n,"error_description")||h(n,"access_token")||h(n,"id_token")){if(t.valid=!0,!n.hasOwnProperty("state"))return t;if(t.stateResponse=n.state,this._matchState(t))return t;if(!t.stateMatch&&window.parent){t.requestType=this._requestType;for(const e of this._renewStates)if(e===t.stateResponse){t.stateMatch=!0;break}}}return t}_matchState(t){const n=c(e.STATE_LOGIN);if(n)for(const e of n.split("||"))if(e===t.stateResponse)return t.requestType=r.LOGIN,t.stateMatch=!0,!0;const s=c(e.STATE_RENEW);if(s)for(const e of s.split("||"))if(e===t.stateResponse)return t.requestType=r.RENEW_TOKEN,t.stateMatch=!0,!0;return!1}saveTokenFromHash(t){a(e.ERROR,""),a(e.ERROR_DESCRIPTION,"");var n,s,o=function(e){if(e){var t=e.indexOf("|");if(t>-1&&t+1<e.length)return e.substring(t+1)}return""}(t.stateResponse);t.parameters.hasOwnProperty("error_description")?(a(e.ERROR,t.parameters.error),a(e.ERROR_DESCRIPTION,t.parameters.error_description),t.requestType===r.LOGIN&&(this._loginInProgress=!1,a(e.LOGIN_ERROR,t.parameters.error_description))):t.stateMatch?(t.parameters.hasOwnProperty("session_state")&&a(e.SESSION_STATE,t.parameters.session_state),t.parameters.hasOwnProperty("access_token")&&(this._hasResource(o)||(n=c(e.TOKEN_KEYS)||"",a(e.TOKEN_KEYS,n+o+"|")),a(e.ACCESS_TOKEN_KEY+o,t.parameters.access_token),a(e.EXPIRATION_KEY+o,((s=t.parameters.expires_in)||(s=3599),p()+parseInt(s,10)))),t.parameters.hasOwnProperty("id_token")&&(this._loginInProgress=!1,this._user=this._createUser(t.parameters.id_token),this._user&&this._user.profile?function(t){const n=c(e.NONCE_IDTOKEN);if(n)for(const e of n.split("||"))if(e===t.profile.nonce)return!0;return!1}(this._user)?(a(e.IDTOKEN,t.parameters.id_token),this._hasResource(o=this.config.loginResource?this.config.loginResource:this.config.clientId)||(n=c(e.TOKEN_KEYS)||"",a(e.TOKEN_KEYS,n+o+"|")),a(e.ACCESS_TOKEN_KEY+o,t.parameters.id_token),a(e.EXPIRATION_KEY+o,this._user.profile.exp)):(a(e.LOGIN_ERROR,"Nonce received: "+this._user.profile.nonce+" is not same as requested: "+c(e.NONCE_IDTOKEN)),this._user=null):(t.parameters.error="invalid id_token",t.parameters.error_description="Invalid id_token. id_token: "+t.parameters.id_token,a(e.ERROR,"invalid id_token"),a(e.ERROR_DESCRIPTION,"Invalid id_token. id_token: "+t.parameters.id_token)))):(t.parameters.error="Invalid_state",t.parameters.error_description="Invalid_state. state: "+t.stateResponse,a(e.ERROR,"Invalid_state"),a(e.ERROR_DESCRIPTION,"Invalid_state. state: "+t.stateResponse)),a(e.RENEW_STATUS+o,i.Completed)}getResourceForEndpoint(e){if(this.config.anonymousEndpoints)for(let t=0;t<this.config.anonymousEndpoints.length;t++)if(e.indexOf(this.config.anonymousEndpoints[t])>-1)return;if(this.config.endpoints)for(const t in this.config.endpoints)if(e.indexOf(t)>-1)return this.config.endpoints[t];return e.indexOf("http://")>-1||e.indexOf("https://")>-1?(t=this.config.redirectUri,new URL(e).host===new URL(t).host?this.config.loginResource:void 0):this.config.loginResource;var t}handleWindowCallback(t=window.location.hash){if(function(e){const t=_(l(e));return h(t,"error_description")||h(t,"access_token")||h(t,"id_token")}(t)){let i,o;const a=this._openedWindows[this._openedWindows.length-1];a&&a.opener&&a.opener._adalInstance?(i=a.opener._adalInstance,o=!0):window.parent&&window.parent._adalInstance&&(i=window.parent._adalInstance);let l,_,d,h=i.getRequestInfo(t);l=o||window.parent!==window?i._callBackMappedToRenewStates[h.stateResponse]:i.config.callback,i.saveTokenFromHash(h),h.requestType===r.RENEW_TOKEN&&window.parent?(_=h.parameters.access_token||h.parameters.id_token,d="access_token"):h.requestType===r.LOGIN&&(_=h.parameters.id_token,d="id_token");var n=h.parameters.error_description,s=h.parameters.error;try{l&&l(n,_,s,d)}catch(e){}window.parent!==window||o||(i.config.navigateToLoginRequestUrl?window.location.href=c(e.LOGIN_REQUEST):window.location.hash="")}}_getNavigateUrl(e,t){return this.config.instance+this.config.tenant+"/oauth2/authorize"+function(e,t,n){if(!t)return"";const r=["?response_type="+e,"client_id="+encodeURIComponent(t.clientId)];n&&r.push("resource="+encodeURIComponent(n)),r.push("redirect_uri="+encodeURIComponent(t.redirectUri)),r.push("state="+encodeURIComponent(t.state)),h(t,"slice")&&r.push("slice="+encodeURIComponent(t.slice)),h(t,"extraQueryParameter")&&r.push(t.extraQueryParameter);const s=t.correlationId||u();return r.push("client-request-id="+encodeURIComponent(s)),r.join("&")}(e,this.config,t)}_extractIdToken(e){var t=this._decodeJwt(e);if(t)try{var n=this._base64DecodeStringUrlSafe(t.JWSPayload);return n?JSON.parse(n):void 0}catch(e){}}_base64DecodeStringUrlSafe(e){return e=e.replace(/-/g,"+").replace(/_/g,"/"),decodeURIComponent(escape(window.atob(e)))}_decodeJwt(e){if(!d(e)){var t=/^([^\.\s]*)\.([^\.\s]+)\.([^\.\s]*)$/.exec(e);if(t&&!(t.length<4))return{header:t[1],JWSPayload:t[2],JWSSig:t[3]}}}_addAdalFrame(e){return document.getElementById(e)||(document.body.insertAdjacentHTML("beforeEnd",`<iframe name="${e}" id="${e}" style="display:none"></iframe>`),window.frames&&window.frames[e])}}function a(e,n,r=!1){if(r){const r=c(e)||"";t.setItem(e,r+n+"||")}else t.setItem(e,n)}function c(e){return t.getItem(e)}function l(e){return e.indexOf("#/")>-1?e=e.substring(e.indexOf("#/")+2):e.indexOf("#")>-1&&(e=e.substring(1)),e}function _(e){var t,n=/\+/g,r=/([^&=]+)=([^&]*)/g,s=e=>decodeURIComponent(e.replace(n," ")),i={};for(t=r.exec(e);t;)i[s(t[1])]=s(t[2]),t=r.exec(e);return i}function d(e){return void 0===e||!e||0===e.length}function h(e,t){return Object.hasOwnProperty.call(e,t)}function p(){return Math.round(Date.now()/1e3)}function u(){let e=new Uint8Array(16);return crypto.getRandomValues(e),e[6]|=64,e[6]&=79,e[8]|=128,e[8]&=191,e=e.map(e=>{let t=e.toString(16);for(;t.length<2;)t="0"+t;return t}),e[0]+e[1]+e[2]+e[3]+"-"+e[4]+e[5]+"-"+e[6]+e[7]+"-"+e[8]+e[9]+"-"+e[10]+e[11]+e[12]+e[13]+e[14]+e[15]}export{o as Adal};
//# sourceMappingURL=adal.modern.js.map
