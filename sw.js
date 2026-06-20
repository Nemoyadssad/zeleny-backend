const CACHE='zeleny-v1';
const ASSETS=['index.html','oferta.html','refund.html','delivery.html','contacts.html','manifest.json','questions.json','signs.json','markup.json','penalties.json'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)).catch(()=>{}));self.skipWaiting();});
self.addEventListener('activate',e=>{self.clients.claim();});
self.addEventListener('fetch',e=>{
  if(e.request.method!=='GET')return;
  e.respondWith(caches.match(e.request).then(r=>r||fetch(e.request)).catch(()=>caches.match('index.html')));
});