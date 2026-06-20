const CACHE='zeleny-v2';
const ASSETS=['index.html','oferta.html','refund.html','delivery.html','contacts.html','manifest.json','questions.json','signs.json','markup.json','penalties.json'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)).catch(()=>{}));self.skipWaiting();});
self.addEventListener('activate',e=>{
  e.waitUntil(
    caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim())
  );
});
self.addEventListener('fetch',e=>{
  if(e.request.method!=='GET')return;
  const url=new URL(e.request.url);
  // HTML и JSON всегда тянем из сети (свежий контент), при офлайне — из кэша
  if(e.request.mode==='navigate' || url.pathname.endsWith('.html') || url.pathname.endsWith('.json')){
    e.respondWith(
      fetch(e.request).then(r=>{const cp=r.clone();caches.open(CACHE).then(c=>c.put(e.request,cp));return r;})
                      .catch(()=>caches.match(e.request).then(r=>r||caches.match('index.html')))
    );
    return;
  }
  // остальное — сперва кэш, потом сеть
  e.respondWith(caches.match(e.request).then(r=>r||fetch(e.request)).catch(()=>caches.match('index.html')));
});
