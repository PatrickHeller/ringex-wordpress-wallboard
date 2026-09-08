# RingEX WordPress Wallboard

Call-Queue-Wallboard für RingEX (Warteschlangen-Übersicht) als WordPress-Theme-Erweiterung
(`www.p-h-c.de`, Theme `twentyseventeen`). Öffentlicher TV-Wallboard-Zugang (kein Login nötig).
Wurde später zusätzlich als [ringex-suitecrm-wallboard](https://github.com/PatrickHeller/ringex-suitecrm-wallboard)
in SuiteCRM 8 portiert.

Stand: 2026-09-02 (Anrufstatistik umgebaut, seitdem stabil).

## Aufbau

- `wp-content/themes/twentyseventeen/ringex-app/dashboard_ex.php` — Logik + HTML + AJAX-Polling
  alle 300s.
- `wp-content/themes/twentyseventeen/template-ringex.php` — WordPress-Template-Einbindung.
- Config: `ringex-app/config_ex.ini` (nicht Teil dieses Repos, Vorlage siehe
  `config_ex.ini.example`, liegt im Theme-Ordner unterhalb der Webroot — geringer sicher als die
  SuiteCRM-Variante, aber bewusst so belassen).

## Datenzugriff

JWT-Bearer-OAuth-Flow gegen `platform.ringcentral.com` (Service-Account, kein interaktiver Login).
Queues via `GET /restapi/v1.0/account/~/extension?extensionType=Department`
(zusätzlich hart auf `type === 'Department'` gefiltert, da RC den Filter nicht strikt einhält).

**Anrufstatistik läuft über das klassische Call-Log**, nicht über die Analytics-API:
`GET /restapi/v1.0/account/~/extension/{queueId}/call-log?direction=Inbound&type=Voice&view=Simple&...`
— liefert `result` und `duration` (Sekunden) direkt und korrekt. Die Analytics-API
(`/analytics/calls/v1/.../records/fetch`) wurde bewusst verworfen: bei extern weitergeleiteten
Anrufen fehlt dort der erfolgreiche Ziel-Hop komplett, wodurch tatsächlich angenommene Anrufe fälschlich
als `NotAnswered` erscheinen — keine Hop-Heuristik kann das reparieren. Pagination des
Call-Log-Endpoints nutzt `navigation.nextPage`, kein `paging.totalPages`.

## Bekannter, gefixter Bug (2026-08-19)

`get_call_queues()` warf sporadisch `TokenInvalid`/`OAU-213 Token not found` durch parallele
Token-Refreshs (mehrere offene Tabs / überlappendes AJAX-Polling). Fix: `flock()`-Lock um den
Refresh-Pfad (Double-Checked Locking) + 401-Retry, analog zu `get_analytics_records()`.

## Deploy

Nach `wp-content/` der WordPress-Installation kopieren. Datei gehört `www-data:www-data`.
