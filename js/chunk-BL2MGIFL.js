import{E as C,I as b,J as y,R as x,a as M,c,g as T,i as u,k as d,m as L,q as g}from"./chunk-6NZN5PKE.js";import{a as w}from"./chunk-O6XLKH6S.js";import{a as s}from"./chunk-O5BPB6HH.js";s();var O=(e,t,r,o)=>{let a,n="none";switch(t){case 0:a={opacity:[1,0]};break;case 1:a={opacity:[0,1]},n="block";break;case"bounceUpIn":a={begin(i){u(e,"block")},translateY:[{value:-60,duration:200},{value:10,duration:200},{value:-5,duration:200},{value:0,duration:200}],opacity:[0,1]},n="block";break;case"shrinkIn":a={begin(i){u(e,"block")},scale:[{value:1.1,duration:300},{value:1,duration:200}],opacity:1},n="block";break;case"slideRightIn":a={begin(i){u(e,"block")},translateX:["100%","0%"],opacity:[0,1]},n="block";break;case"slideRightOut":a={translateX:["0%","100%"],opacity:[1,0]};break;default:a=t,n=t.display;break}w(Object.assign({targets:e,duration:200,easing:"linear",begin(){o&&o()},complete(){u(e,n),r&&r()}},a)).play()},m=(e,t,r)=>{w({targets:typeof t=="number"&&typeof e!="number"?e.parentNode:document.scrollingElement,duration:500,easing:"easeInOutQuad",scrollTop:t||(typeof e=="number"?e:e?T(e)+document.documentElement.scrollTop-C:0),complete(){r&&r()}}).play()};s();s();var h={set(e,t){localStorage.setItem(e,t)},get(e){return localStorage.getItem(e)},del(e){localStorage.removeItem(e)}};var k=e=>{if(!e)return;let t=c(g,"div",{innerHTML:e,className:"tip"});setTimeout(()=>{t.addClass("hide"),setTimeout(()=>{g.removeChild(t)},300)},3e3)},U=()=>{d.auto_scroll&&h.set(y,String(L.y))},W=e=>{let t=window.location.hash,r=null;if(b){h.del(y);return}t?r=document.querySelector(decodeURI(t)):r=d.auto_scroll?parseInt(h.get(y)):0,r&&(m(r),x(1)),e&&t&&!b&&(m(r),x(1))},X=(e,t)=>{navigator.clipboard&&window.isSecureContext?navigator.clipboard.writeText(e).then(()=>{t&&t(!0)},()=>{t&&t(!1)}):(console.error("Too old browser, clipborad API not supported."),t&&t(!1))};s();s();var S=()=>{let e;M.each("div.tab",t=>{if(t.getAttribute("data-ready"))return;let r=t.getAttribute("data-id"),o=t.getAttribute("data-title"),a=document.getElementById(r);a?e=!1:(a=document.createElement("div"),a.className="tabs",a.id=r,a.innerHTML='<div class="show-btn"></div>',a.querySelector(".show-btn").addEventListener("click",()=>{m(a)}),t.parentNode.insertBefore(a,t),e=!0);let n=a.querySelector(".nav ul");n||(n=c(a,"div",{className:"nav",innerHTML:"<ul></ul>"}).querySelector("ul"));let i=c(n,"li",{innerHTML:o});e&&(i.addClass("active"),t.addClass("active")),i.addEventListener("click",f=>{let v=f.currentTarget;a.find(".active").forEach(l=>{l.removeClass("active")}),t.addClass("active"),v.addClass("active")}),a.appendChild(t),t.setAttribute("data-ready",String(!0))})};var le=/mobile/i.test(window.navigator.userAgent);s();function ue(){let e=!0;window.addEventListener("DOMContentLoaded",function(){e=!1}),document.readyState==="loading"&&window.addEventListener("load",function(){e&&(window.dispatchEvent(new Event("DOMContentLoaded")),console.log("%c \u2601\uFE0Fcloudflare patch %c running","color: white; background: #ff8c00; padding: 5px 3px;","padding: 4px;border:1px solid #ff8c00"))})}var E=(e,t,r,o)=>{if(o)r();else{let a=document.createElement("script");a.onload=function(n,i){(i||!a.readyState)&&(console.log("abort!"),a.onload=null,a=void 0,!i&&r&&setTimeout(r,0))},a.src=e,a.integrity=t,a.crossOrigin="anonymous",document.head.appendChild(a)}},pe=e=>{let{text:t,parentNode:r,id:o,className:a,type:n,src:i,dataset:f}=e,v=t||e.textContent||e.innerHTML||"";r.removeChild(e);let l=document.createElement("script");o&&(l.id=o),a&&(l.className=a),n&&(l.type=n),i&&(l.src=i,l.async=!1),f.pjax!==void 0&&(l.dataset.pjax=""),v!==""&&l.appendChild(document.createTextNode(v)),r.appendChild(l)};s();var N=(e,t)=>{let r=d[e][t].url;return r.startsWith("https")?r:r.startsWith("http")?(console.warn(`Upgrade vendor ${e}/${t} to HTTPS, Please use HTTPS url instead of HTTP url.`),r.replace("http","https")):`/${r}`},ge=(e,t,r)=>{LOCAL[e]&&E(N("js",e),d.js[e].sri,t||function(){window[e]=!0},r||window[e])},be=(e,t)=>{if(!window["css"+e]&&LOCAL[e]){let r={rel:"stylesheet",href:N("css",e)},o=d.css[e];o.local||(r.integrity=o.sri,r.crossOrigin="anonymous"),c(document.head,"link",r),window["css"+e]=!0}};export{O as a,m as b,h as c,k as d,U as e,W as f,X as g,S as h,ue as i,pe as j,ge as k,be as l};
/*! For license information please see chunk-BL2MGIFL.js.LEGAL.txt */
