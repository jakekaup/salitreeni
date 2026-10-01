Salitreeni v3.2.1
Safari/PWA käynnistyskorjaus:
- DOM-elementit sidotaan eksplisiittisesti eikä luoteta ID-globaaleihin.
- Käynnistysvirhe näytetään ruudulla mustan näkymän sijaan.
- Supabase/CDN-pyynnöt ohitetaan service worker -cachesta.
- Uusi cache-versio pakottaa käyttöliittymän päivittymään.
